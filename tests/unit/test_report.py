"""Test rps.report"""

import hmac
import hashlib
import unittest

from rps.report import IPEvent
from rps.report import IPv4Events
from rps.report import IPv6Events
from rps.report import ReportClient
from rps.report import RepeatedIPEvent
from rps.report import RepeatedIPv4Events

# XXX These should be reformatted to proper unittests
class TestReport(unittest.TestCase):
    def test_report(self):
        """Check that the example in the specification generates the correct
        report data."""
        # The report is from the user "dfs" with password "foo".
        subreports = [
            IPv4Events([IPEvent("192.0.2.2", "AUTO-SPAM"),
                        IPEvent("192.0.2.3", "GREYLISTED")]),
            RepeatedIPv4Events([
                RepeatedIPEvent("192.0.2.4", "INVALID-RECIPIENT", 3)]),
            IPv6Events([
                IPEvent("2001:db8:1d:e4:2e0:18ff:feab:147f",
                        "VALID-RECIPIENT")]),
        ]
        report = ReportClient.generate_report(subreports, "dfs", "foo")
        correct = ("02036466732a9a82d6512964f74bd9daeb01000ac000020203c00002030"
                   "1030006c0000204080302001120010db8001d00e402e018fffeab147f07"
                   "9c7dcb30a60592faa3a8")
        # Check that our HMAC matches.
        correct_hmac = correct[-20:]
        report_hmac = hmac.new("foo", correct[:-20], hashlib.sha1).hexdigest()
        print report_hmac
        print correct_hmac
        self.assertEqual(report_hmac, correct_hmac)
        hex_report = "".join("%.2x" % ord(c) for c in report)
        # Make the random bytes and timestamp the same.
        correct = correct[:10] + hex_report[10:34] + correct[34:]
        print hex_report[:-20]
        print correct[:-20]
        self.assertEqual(hex_report[:-20], correct[:-20])
