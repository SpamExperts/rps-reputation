"""IP Reputation Events

This module defines a series of sub-reports that deal with IP reputation
events.

IPEvent: an object of this class must be included in the various event
sub-reports.
IPEvents: an ABC sub-report for reporting IP events.
IPv4Events: used to report one or more events regarding an IPv4 address.
IPv6Events: used to report one or more events regarding an IPv6 address.
RepeatedIPEvent: an object of this class must be included in the various
repeated event sub-reports (used to inform the server about multiple
events regarding the same IP and event).
RepeatedIPv4Events: used to report multiple events regarding an IPv4
address.
RepeatedIPv6Events: used to report multiple events regarding an IPv6
address.
"""

import struct

import ipaddr

from . import core
from . import reports


class IPEvent(object):
    """To be included in an IPEvents subreport."""

    def __init__(self, address, event):
        self.address = ipaddr.IPAddress(address)
        self.event = event
        # Ensure that this IP is valid.
        core.reportable_ip(self.address)

    def __str__(self):
        return "%s%s" % (self.address.packed,
                         struct.pack("B", core.EVENTS.index(self.event)))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        event = core.EVENTS[struct.unpack("B", bytestr[-1])[0]]
        bytestr = bytestr[:-1]
        fmt = "!" + ("B" * len(bytestr))
        parts = enumerate(struct.unpack(fmt, bytestr)[::-1])
        address = ipaddr.IPAddress(sum((part * (2 ** (8 * byte)))
                                       for byte, part in parts))
        return cls(address, event)


class IPEvents(reports.SubReport):
    """A subreport regarding an IP address.

    This is an abstract base class.
    """

    def __init__(self, events):
        reports.SubReport.__init__(self)
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
        return "%s%s" % (ipaddr.IPAddress(self.address).packed,
                         struct.pack("BB", core.EVENTS.index(self.event),
                                     self.repeat))

    @classmethod
    def from_bytes(cls, bytestr):
        """Return an instance of this class with the data from the given
        byte string."""
        event = core.EVENTS[struct.unpack("B", bytestr[-1])[0]]
        repeat = core.EVENTS[struct.unpack("B", bytestr[-2])[0]]
        bytestr = bytestr[:-2]
        fmt = "!" + ("B" * len(bytestr))

        parts = enumerate(struct.unpack(fmt, bytestr)[::-1])
        address = ipaddr.IPAddress(sum((part * (2 ** (8 * byte)))
                                       for byte, part in parts))
        return cls(address, event, repeat)


class RepeatedEvents(reports.SubReport):
    """A subreport regarding multiple occurrences of events regarding an
    IP address."""

    def __init__(self, events):
        reports.SubReport.__init__(self)
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

    Each repeated IPv4 subreport contains one or more events. The length
    of each event is 6. The events themselves consist of:

        * The 4-byte IPv4 address in network byte order.
        * A one-byte event type.
        * A one-byte repeat. This byte is interpreted as an unsigned number.
    """
    format = 3
    length = 6


class RepeatedIPv6Events(RepeatedEvents):
    """A subreport regarding multiple occurrences of events regarding an
    IPv6 address.

    Each repeated IPv6 subreport contains one or more events. The length
    of each event is 18. The events themselves consist of:

        * The 16-byte IPv6 address in network byte order.
        * A one-byte event type.
        * A one-byte repeat. This byte is interpreted as an unsigned
          number. It must be greater than or equal to two.
    """
    format = 4
    repeat = 18


