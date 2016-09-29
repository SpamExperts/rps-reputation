#! /usr/bin/env python

"""An implementation of the Roaring Penguin IP reputation reporting system.

See http://www.roaringpenguin.com/draft-dskoll-reputation-reporting-02.html.

There is currently no support for vendor-specific subreports or hierarchical
aggregation.

In some places where the specification uses "SHOULD", this implementation
treats the recommendation as "MUST".  For example, in the specification the
software version SHOULD be an ASCII string, but in this implementation it
MUST be an ASCII string.
"""

import time
import hmac
import struct
import random
import socket
import hashlib
import logging
try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    import ipaddress
except ImportError:
    ipaddress = None
    import ipaddr

try:
    import spoon
    import spoon.server
except ImportError:
    _server_parent = socketserver.UDPServer
    _handler_parent = socketserver.DatagramRequestHandler
else:
    _server_parent = spoon.server.UDPSpoon
    _handler_parent = spoon.server.UDPGulp

PORT = 6568
VERSION = 2

EVENTS = [
    # Event type 0 is reserved. A sensor MUST NOT report events of type 0.
    "RESERVED",
    # An SMTP client at the specified IP address was greylisted.
    "GREYLISTED",
    # An SMTP client at the specified IP address was previously greylisted,
    # but has now passed the greylisting test.
    "UNGREYLISTED",
    # An SMTP client at the specified IP address sent a message that was
    # considered to be spam by automatic filtering software.
    "AUTO-SPAM",
    # An SMTP client at the specified IP address sent a message that was
    # considered to be spam by a human being.
    "HAND-SPAM",
    # An SMTP client at the specified IP address sent a message that was
    # considered to be non-spam by automatic filtering software.
    "AUTO-HAM",
    # An SMTP client at the specified IP address sent a message that was
    # considered to be non-spam by a human being.
    "HAND-HAM",
    # An SMTP client at the specified IP address issued an SMTP RCPT command
    # that specified a valid recipient address.
    "VALID-RECIPIENT",
    # An SMTP client at the specified IP address issued an SMTP RCPT command
    # that specified an invalid recipient address.
    "INVALID-RECIPIENT",
    # An SMTP client at the specified IP address transmitted a message
    # considered to be a virus by virus-scanning software.
    "VIRUS",

    # These are non-standard event types, in the "reserved for future use"
    # space.  They may need to change in the future, if the specification
    # adds new event types.

    # An SMTP client at the specified IP address transmitted a message
    # considered to be a phishing attempt by anti-phishing software.
    "PHISH",
    # An SMTP client at the specific IP address used SMTP AUTH with
    # invalid credentials.
    "AUTH-FAILED",
]


class ReportClient(object):
    """Methods to generate and submit IP reputation reports.

    Create an instance of the class with appropriate parameters.  Add events
    to the events member, and call send_report() whenever you want to try
    to send a report.  If there is not enough data to send, then the report
    will not be sent.  If there is pending data when the instance is
    garbage-collected, then a report will be sent at that time.
    """

    def __init__(self, timeout, server, username, password, port=PORT,
                 software_name=None, software_version=None, end_user=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.software_name = software_name
        self.software_version = software_version
        self.end_user = end_user
        self.events = []

    @staticmethod
    def generate_report(subreports, username, password):
        """A report consists of the following items:

            * A one-byte protocol version number.
            * A one-byte number indicating the length of a user name.
            * A sequence of bytes indicating a user name.
            * Eight randomly-generated bytes.
            * A four-byte timestamp in network byte order. This is
              constructed by computing the current time in seconds since
              midnight, January 1 1970 UTC as an unsigned integer, and
              taking the low-order 32 bits of the result.
            * One or more subreports.
            * Finally, ten bytes consisting of the ten most-significant
              bytes (in network byte order) of the SHA1 HMAC digest of all
              data from the version number up to and including the EOR byte.
              The password used to calculate the HMAC is a shared secret
              known by the sensor.

        """
        # A sensor must not send an empty report.
        assert subreports, "A report must contain at least one subreport."
        # There must not be more than one software name subreport.
        name_reports = [subreport for subreport in subreports
                        if isinstance(subreport, SoftwareName)]
        assert len(name_reports) <= 1
        # There must not be more than one software version subreport.
        version_reports = [subreport for subreport in subreports
                           if isinstance(subreport, SoftwareVersion)]
        assert len(version_reports) <= 1
        # If a software version subreport is included, there must also be a
        # software name subreport.
        if version_reports:
            assert name_reports
        username = username.encode("utf8")
        # A username must range from 0 to 63 bytes in length.
        assert len(username) < 64
        random_bytes = [random.randint(0, 255) for dummy in range(8)]
        header = struct.pack("!B%dp8BI" % (len(username) + 1), VERSION,
                             username, random_bytes[0], random_bytes[1],
                             random_bytes[2], random_bytes[3],
                             random_bytes[4], random_bytes[5],
                             random_bytes[6], random_bytes[7],
                             int(time.time()))
        subreports = "".join(str(subreport) for subreport in subreports)
        footer = hmac.new(password, header + subreports,
                          hashlib.sha1).digest()[:10]
        return header + subreports + footer

    def send_report(self, force=False):
        """Send a generated report to the specified server."""
        subreports = list(self.events)
        if self.software_name:
            subreports.append(SoftwareName(self.software_name))
        if self.software_version:
            subreports.append(SoftwareVersion(self.software_version))
        if self.end_user:
            subreports.append(EndUser(self.end_user))
        subreports.append(EndOfReport())
        report = self.generate_report(subreports, self.username,
                                      self.password)
        # A sensor should include as many events in its report as necessary
        # to make the report size at least 400 bytes. A sensor may send out
        # a shorter report, but must not do so unless failing to do so would
        # result in loss of data or unless it has not sent a report within
        # the last hour.
        if not force and len(report) < 400:
            return
        try:
            sent = self.socket.sendto(report, 0, (self.server, self.port))
        except socket.error as e:
            log = logging.getLogger("ip-reputation")
            log.info("Unable to submit report: %s", e)
        else:
            if sent == len(report):
                self.events = []

    def __del__(self):
        if self.events:
            self.send_report(force=True)


def reportable_ip(address):
    """A sensor must not report events for an IPv4 address that is not a
    globally-routable unicast address. In particular, no IPv4 address
    in the Private Address Space of [RFC1918] should appear in a
    report, nor should any address in 127/8 nor 224/4.
    """
    assert not address.is_private
    assert not address.is_loopback  # 127/8
    assert not address.is_multicast  # 22/4
    # A sensor must not report events for an IPv6 address that is not an
    # Aggregatable Global Unicast Address as defined in [RFC4291].
    assert not address.is_unspecified
    try:
        assert not address.is_site_local
    except AttributeError:
        # IPv4 Addresses do not have a "site local" attribute.
        pass
    assert not address.is_link_local
    assert not address.is_reserved


class RequestHandler(_handler_parent):
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
            log.info("Invalid report (%r) from %s.",
                     report, self.client_address[0])
            return
        username_length = ord(username_length)
        username, report = (report[:username_length],
                            report[username_length:])
        username = struct.unpack("!%ss" % username_length,
                                 username)[0].decode("utf8")
        # An aggregator must ignore a report with a version number other
        # than 2.
        if version != "\x02":
            log.error("Unknown version: %s", version)
            return
        # The aggregator must look up the secret based on the user name in
        # the report. An aggregator must reject a report that fails to
        # validate. It should log information about invalid reports.
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
        # An aggregator should not accept a report whose timestamp is more
        # than two minutes away from the current time.
        timestamp = struct.unpack("!I", timestamp)[0]
        if time.time() - timestamp > 120:
            log.info("Report too old: %s vs. %s", time.time(), timestamp)
            return
        # An aggregator should use the time stamp and random-number fields
        # to detect duplicate reports and fend off replay attacks.
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
        self.handle_events(username, events, software_name,
                           software_version, end_user)
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
            # Give up on this report, because we don't know how to continue.
            return software_name, software_version, end_user
        # An aggregator must skip over subreports with format values it does
        # not understand. (It can do this by skipping ahead length bytes.)
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
        # An aggregator must ignore the entire report if any subreports have
        # invalid lengths.
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


class ReportServer(_server_parent):
    """A simple server that handles reports."""
    # handler_class is used for SocketServer, and handler_klass is used
    # for spoon.server. For compatibility, it's easiest to just have
    # them both defined.
    handler_class = RequestHandler
    handler_klass = RequestHandler

    def __init__(self, address):
        logging.getLogger("ip-reputation").debug("Listening on %s", address)
        self.recent_reports = set()
        self.report_count = 0
        super(ReportServer, self).__init__(address)


class SubReport(object):
    """An abstract base class for the various subreport types.

    A subreport consists of either the single byte 0, indicating the end of
    the subreports, or a three-byte preamble followed by the subreport
    contents. The three-byte preamble consists of:

        * One format byte.
        * A two-byte length field. This is a 16-bit unsigned integer in
          network byte order indicating the length of the subreport
          contents, not including the three-byte preamble.
    """
    # Subclasses must override these.
    format = None
    length = None

    def __str__(self):
        return struct.pack("!BH", self.format, self.length)

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        raise NotImplementedError()


class EndOfReport(SubReport):
    """This signifies the end of the subreports in the report. It must not
    be followed by a length field."""
    format = 0

    def __str__(self):
        return struct.pack("B", 0)

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        assert not bytestr
        return cls()


class IPEvent(object):
    """To be included in an IPEvents subreport."""

    def __init__(self, address, event):
        if ipaddress:
            self.address = ipaddress.ip_address(address)
        else:
            self.address = ipaddr.IPAddress(address)
        self.event = event
        # Ensure that this IP is valid.
        reportable_ip(self.address)

    def __str__(self):
        return "%s%s" % (self.address.packed,
                         struct.pack("B", EVENTS.index(self.event)))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        event = EVENTS[struct.unpack("B", bytestr[-1])[0]]
        bytestr = bytestr[:-1]
        fmt = "!" + ("B" * len(bytestr))
        parts = enumerate(struct.unpack(fmt, bytestr)[::-1])
        address = sum((part * (2 ** (8 * byte))) for byte, part in parts)
        if ipaddress:
            address = ipaddress.ip_address(address)
        else:
            address = ipaddr.IPAddress(address)
        return cls(address, event)


class IPEvents(SubReport):
    """A subreport regarding an IP address.

    This is an abstract base class.
    """

    def __init__(self, events):
        SubReport.__init__(self)
        self.events = events

    def __str__(self):
        return "%s%s" % (struct.pack("!BH", self.format,
                                     self.length * len(self.events)),
                         "".join(str(event) for event in self.events))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        result = cls([])
        while bytestr:
            event_bytes, bytestr = bytestr[:cls.length], bytestr[cls.length:]
            result.events.append(IPEvent.from_bytes(event_bytes))
        return result


class IPv4Events(IPEvents):
    """A subreport regarding an IPv4 address.

    Each IPv4 subreport contains one or more events. The length of each
    event is 5. The events themselves consist of:

        * The 4-byte IPv4 address network byte order.
        * A one-byte event type.
    """
    format = 1
    length = 5


class IPv6Events(IPEvents):
    """A subreport regarding an IPv6 address.

    Each IPv6 subreport contains one or more events. The length of each
    event is 17. The events themselves consist of:

        * The 16-byte IPv4 address network byte order.
        * A one-byte event type.
    """
    format = 2
    length = 17


class RepeatedIPEvent(IPEvent):
    """To be included in an RepeatedIPEvents subreport."""

    def __init__(self, address, event, repeat):
        IPEvent.__init__(self, address, event)
        # The repeat must be greater than or equal to two.
        assert repeat >= 2
        self.repeat = repeat

    def __str__(self):
        if ipaddress:
            address = ipaddress.ip_address(self.address)
        else:
            address = ipaddr.IPAddress(self.address)
        return "%s%s" % (address.packed,
                         struct.pack("BB", EVENTS.index(self.event),
                                     self.repeat))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        event = EVENTS[struct.unpack("B", bytestr[-1])[0]]
        repeat = EVENTS[struct.unpack("B", bytestr[-2])[0]]
        bytestr = bytestr[:-2]
        fmt = "!" + ("B" * len(bytestr))

        parts = enumerate(struct.unpack(fmt, bytestr)[::-1])
        address = sum((part * (2 ** (8 * byte))) for byte, part in parts)
        if ipaddress:
            address = ipaddress.ip_address(address)
        else:
            address = ipaddr.IPAddress(address)
        return cls(address, event, repeat)


class RepeatedEvents(SubReport):
    """A subreport regarding multiple occurrences of events regarding an
    IP address."""

    def __init__(self, events):
        SubReport.__init__(self)
        self.events = events

    def __str__(self):
        return "%s%s" % (struct.pack("!BH", self.format,
                                     self.length * len(self.events)),
                         "".join(str(event) for event in self.events))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        result = cls([])
        while bytestr:
            event_bytes, bytestr = bytestr[:cls.length], bytestr[cls.length:]
            result.events.append(RepeatedIPEvent.from_bytes(event_bytes))
        return result


class RepeatedIPv4Events(RepeatedEvents):
    """A subreport regarding multiple occurrences of events regarding an
    IPv4 address.

    Each repeated IPv4 subreport contains one or more events. The length of
    each event is 6. The events themselves consist of:

        * The 4-byte IPv4 address in network byte order.
        * A one-byte event type.
        * A one-byte repeat. This byte is interpreted as an unsigned number.
    """
    format = 3
    length = 6


class RepeatedIPv6Events(RepeatedEvents):
    """A subreport regarding multiple occurrences of events regarding an
    IPv6 address.

    Each repeated IPv6 subreport contains one or more events. The length of
    each event is 18. The events themselves consist of:

        * The 16-byte IPv6 address in network byte order.
        * A one-byte event type.
        * A one-byte repeat. This byte is interpreted as an unsigned number.
          It must be greater than or equal to two.
    """
    format = 4
    repeat = 18


class StringReport(SubReport):
    """SubReports that are just a string."""
    # Subclasses must override this.
    maximum_length = None
    encoding = None

    def __init__(self, value):
        SubReport.__init__(self)
        if self.encoding:
            value = value.encode(self.encoding)
        assert len(value) < self.maximum_length
        self.value = value

    def __str__(self):
        return struct.pack("!Bp", self.format, self.value)

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        return cls(struct.unpack("%ss" % len(bytestr), bytes)[0])


class SoftwareName(StringReport):
    """The name of the software doing the report.

    The length can range from 1 to 63. The contents must be a valid UTF-8
    string specifying the name of the software running on the aggregator.
    """
    format = 6
    maximum_length = 64
    encoding = "utf8"


class SoftwareVersion(StringReport):
    """A string version number of the software doing the report.

    The length can range from 1 to 31. The contents must be a valid US-ASCII
    string specifying the version of the software running on the aggregator.
    """
    format = 7
    maximum_length = 32
    encoding = "utf8"


class EndUser(StringReport):
    """A method of identifying the user reporting the events.

    This report, if present, provides additional information about the
    specific user who generated subsequent subreports. For example, if an
    ISP is reporting events, the end user subreport may contain enough
    information for the ISP to determine which of its subscribers reported
    the events. The contents of the end user subreport are a sequence of
    bytes ranging in length from 1 to 31 bytes. The contents are opaque and
    have meaning only to the organization running the sensor.
    """
    format = 8
    maximum_length = 32
    encoding = None


# A dynamic list of all the format types that we handle.
FORMATS = dict((obj.format, obj) for obj in locals().values()
               if isinstance(obj, type) and issubclass(obj, SubReport) and
               obj.format is not None)

# XXX We could add a simple script that can report event CLI.
# XXX This will also allow for functional tests.
