"""Reputation Report Types

This module contains the core sub-report types that may be used with the
reputation server.

SubReport: an ABC for sub-report types.
EndOfReport: a meta sub-report type that indicates the end of the
report.
StringReport: a generic string sub-report type.
SoftwareName: a sub-report indicating the name of the software doing the
reporting.
SoftwareVersion: a sub-report indicating the version of the software
doing the reporting.
EndUser: a sub-report indicating the end-user doing the reporting.
"""

import struct


class SubReport(object):
    """An abstract base class for the various subreport types.

    A subreport consists of either the single byte 0, indicating the end
    of the subreports, or a three-byte preamble followed by the
    subreport contents. The three-byte preamble consists of:

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
    """This signifies the end of the subreports in the report. It must
    not be followed by a length field."""
    format = 0

    def __str__(self):
        return struct.pack("B", 0)

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        assert not bytestr
        return cls()


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

    The length can range from 1 to 63. The contents must be a valid
    UTF-8 string specifying the name of the software running on the
    aggregator.
    """
    format = 6
    maximum_length = 64
    encoding = "utf8"


class SoftwareVersion(StringReport):
    """A string version number of the software doing the report.

    The length can range from 1 to 31. The contents must be a valid
    US-ASCII string specifying the version of the software running on
    the aggregator.
    """
    format = 7
    maximum_length = 32
    encoding = "utf8"


class EndUser(StringReport):
    """A method of identifying the user reporting the events.

    This report, if present, provides additional information about the
    specific user who generated subsequent subreports. For example, if
    an ISP is reporting events, the end user subreport may contain
    enough information for the ISP to determine which of its subscribers
    reported the events. The contents of the end user subreport are a
    sequence of bytes ranging in length from 1 to 31 bytes. The contents
    are opaque and have meaning only to the organization running the
    sensor.
    """
    format = 8
    maximum_length = 32
    encoding = None
