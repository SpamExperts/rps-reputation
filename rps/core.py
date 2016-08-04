VERSION = 2

EVENTS = [
    # Event type 0 is reserved. A sensor MUST NOT report events of type
    # 0.
    "RESERVED",
    # An SMTP client at the specified IP address was greylisted.
    "GREYLISTED",
    # An SMTP client at the specified IP address was previously
    # greylisted, but has now passed the greylisting test.
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
    # An SMTP client at the specified IP address issued an SMTP RCPT
    # command that specified a valid recipient address.
    "VALID-RECIPIENT",
    # An SMTP client at the specified IP address issued an SMTP RCPT
    # command that specified an invalid recipient address.
    "INVALID-RECIPIENT",
    # An SMTP client at the specified IP address transmitted a message
    # considered to be a virus by virus-scanning software.
    "VIRUS",

    # These are non-standard event types, in the "reserved for future
    # use" space.  They may need to change in the future, if the
    # specification adds new event types.

    # An SMTP client at the specified IP address transmitted a message
    # considered to be a phishing attempt by anti-phishing software.
    "PHISH",
    # An SMTP client at the specific IP address used SMTP AUTH with
    # invalid credentials.
    "AUTH-FAILED",
]


def reportable_ip(address):
    """Assert that the provided IP is one suitable for reporting.

    A sensor must not report events for an IPv4 address that is not a
    globally-routable unicast address. In particular, no IPv4 address
    in the Private Address Space of [RFC1918] should appear in a
    report, nor should any address in 127/8 nor 224/4.

    The address argument must be an ipaddr.IPAddress object.
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
