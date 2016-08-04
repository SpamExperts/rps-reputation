"""An implementation of the Roaring Penguin IP reputation reporting
system.

See http://www.roaringpenguin.com/draft-dskoll-reputation-reporting-02.html.

There is currently no support for vendor-specific subreports or
hierarchical aggregation.

In some places where the specification uses "SHOULD", this
implementation treats the recommendation as "MUST". For example, in the
specification the software version SHOULD be an ASCII string, but in
this implementation it MUST be an ASCII string.
"""

__version__ = "1.0.2"
