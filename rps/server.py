"""IP Reputation Server

A basic IP reputation server, capable of receiving and processing IP
reputation events, as provided by the client.

This server does nothing with the reported data - the expectation is
that it will be sub-classed and the subclass will store the data in a
database or some other suitable action. The server subclass must also
provide an appropriate authentication back-end.
"""

import hmac
import time
import struct
import random
import logging
import hashlib
import SocketServer

import spoon

from .events import *
from .reports import *


class RequestHandler(spoon.server.Gulp):
    """Handle a single request.

    It is expected that the handle_events() method will be overloaded by
    a subclass, to do something more useful with the data."""

    def handle_events(self, username, events, software_name,
                      software_version, end_user):
        """Subclasses should override, and do something useful with the
        report."""
        pass

    def get_password(self, username):
        """Subclasses should override, providing the password for the
        specified user."""
        pass

    def handle(self):
        """Verify that a report is acceptable, and convert it to useful
        data, then call handle_events() with this data."""
        log = logging.getLogger("ip-reputation")
        log.debug("Handling report from %s", self.client_address[0])
        report = self.rfile.read(320000)
        # All log calls must include the reporting address
        # (self.client_address) and the username.
        report, footer = report[:-10], report[-10:]
        signature_text = report
        try:
            (version, username_length,
             report) = report[0], report[1], report[2:]
        except IndexError:
            log.info("Invalid report (%r) from %s.", report,
                     self.client_address[0])
            return
        username_length = ord(username_length)
        username, report = (report[:username_length], report[username_length:])
        username = struct.unpack("!%ss" % username_length,
                                 username)[0].decode("utf8")
        # An aggregator must ignore a report with a version number other
        # than 2.
        if version != "\x02":
            log.error("Unknown version: %s", version)
            return
        # The aggregator must look up the secret based on the user name
        # in the report. An aggregator must reject a report that fails
        # to validate. It should log information about invalid reports.
        password = self.get_password(username)
        if not password:
            log.debug("No password found.")
            return
        correct_digest = hmac.new(password, signature_text, hashlib.sha1)
        if correct_digest.digest()[:10] != footer:
            log.warn("Failed password check: %s [%s] (%r != %r).",
                     username, self.client_address[0],
                     correct_digest.digest()[:10], footer)
            return
        random8, timestamp, subreports = (report[:8], report[8:12],
                                          report[12:])
        if not subreports:
            log.info("Empty report from %s.", self.client_address[0])
            return
        # An aggregator should not accept a report whose timestamp is
        # more than two minutes away from the current time.
        timestamp = struct.unpack("!I", timestamp)[0]
        if time.time() - timestamp > 120:
            log.info("Report too old: %s vs. %s", time.time(), timestamp)
            return
        # An aggregator should use the time stamp and random-number
        # fields to detect duplicate reports and fend off replay
        # attacks.
        if (timestamp, random8) in self.server.recent_reports:
            log.info("Replayed report: %s/%s", timestamp, random8)
            return
        # Clear out out reports.
        if random.random() > 0.99:
            log.info("Clearing out old reports (current size: %s)",
                     len(self.server.recent_reports))
            for (old_timestamp,
                 old_random8) in tuple(self.server.recent_reports):
                if time.time() - old_timestamp > 120:
                    log.debug("Removing report %s/%s.", old_timestamp,
                              old_random8)
                    try:
                        self.server.recent_reports.remove((old_timestamp,
                                                           old_random8))
                    except KeyError:
                        pass
            log.info("Clearing out complete (current size: %s)",
                     len(self.server.recent_reports))
        self.server.recent_reports.add((timestamp, random8))
        events = []
        try:
            (software_name, software_version,
             end_user) = self.process_subreports(subreports, events)
        except AssertionError as e:
            # The entire report needs to be ignored.
            log.warn("Could not process report: %s", e,
                     extra={"data": {"reporter": self.client_address[0],
                                     "subreports": subreports,
                                     "events": events}},
                     exc_info=True)
            return
        self.handle_events(username, events, software_name, software_version,
                           end_user)
        self.server.report_count += 1
        if self.server.report_count % 1000 == 0:
            log.info("Processed %d reports since start.",
                     self.server.report_count)

    def process_subreports(self, subreports, events, software_name=None,
                           software_version=None, end_user=None):
        """Convert the subreport data into usable objects."""
        log = logging.getLogger("ip-reputation")
        log.debug("Raw data: %r", subreports)
        try:
            (fmt, length) = struct.unpack("!BH", subreports[:3])
            subreports = subreports[3:]
        except struct.error as e:
            log.info("Unable to unpack %r: %s", subreports, e)
            # Give up on this report, because we don't know how to
            # continue.
            return software_name, software_version, end_user
        # An aggregator must skip over subreports with format values it
        # does not understand. (It can do this by skipping ahead length
        # bytes.)
        try:
            report_class = FORMATS[fmt]
        except KeyError:
            log.warn("Unknown format: %s", fmt, exc_info=True,
                     extra={"data": {"reporter": self.client_address[0]}})
            if not subreports[length:]:
                return software_name, software_version, end_user
            return self.process_subreports(subreports[length:], events,
                                           software_name, software_version,
                                           end_user)
        # An aggregator must ignore the entire report if any subreports
        # have invalid lengths.
        if report_class in (IPv4Events, RepeatedIPv4Events, IPv6Events,
                            RepeatedIPv6Events):
            assert length % report_class.length == 0
        else:
            assert length == report_class.length
        bytestr, subreports = subreports[:length], subreports[length:]
        subreport = report_class.from_bytes(bytestr)
        if isinstance(subreport, SoftwareName):
            software_name = subreport.value
        elif isinstance(subreport, SoftwareVersion):
            software_version = subreport.value
        elif isinstance(subreport, EndUser):
            end_user = subreport.value
        else:
            events.extend(subreport.events)
        if subreports and subreports != "\x00":
            (software_name, software_version,
             end_user) = self.process_subreports(subreports, events,
                                                 software_name,
                                                 software_version, end_user)
        return software_name, software_version, end_user


class ReportServer(spoon.server.TCPSpoon):
    """A simple server that handles reports."""
    server_logger = "ip-reputation"
    handler_klass = RequestHandler

    def __init__(self, address):
        logging.getLogger("ip-reputation").debug("Listening on %s", address)
        self.recent_reports = set()
        self.report_count = 0
        SocketServer.UDPServer.__init__(self, address, self.handler_class)


class ReportServerForked(ReportServer, spoon.server.TCPSpork):
    """A pre-fork version of the report server."""
    prefork = 6


# A dynamic list of all the format types that we handle.
FORMATS = dict((obj.format, obj) for obj in locals().values()
               if isinstance(obj, type) and issubclass(obj, SubReport) and
               obj.format is not None)
