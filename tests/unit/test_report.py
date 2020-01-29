"""Test rps.report"""

from __future__ import print_function

import unittest

import mock

from rps.report import IPEvent
from rps.report import IPv4Events
from rps.report import IPv6Events
from rps.report import ReportClient
from rps.report import RepeatedIPEvent
from rps.report import RepeatedIPv4Events


# XXX These should be reformatted to proper unittests
@unittest.skip
class TestReport(unittest.TestCase):
    def setUp(self):
        """Prepare for a single test."""
        mock.patch("random.randint", return_value=1).start()
        mock.patch("time.time", return_value=1156727880.0).start()

    def tearDown(self):
        """Clean up after a single test."""
        mock.patch.stopall()

    def test_report(self):
        """Check that the example in the specification generates the
        correct report data."""
        # The report is from the user "dfs" with password "foo".
        subreports = [
            IPv4Events([IPEvent("5.79.73.204", "AUTO-SPAM"),
                        IPEvent("95.211.160.147", "GREYLISTED")]),
            RepeatedIPv4Events([
                RepeatedIPEvent("93.184.216.34", "INVALID-RECIPIENT", 3)]),
            IPv6Events([
                IPEvent("2606:2800:220:1:248:1893:25c8:1946",
                        "VALID-RECIPIENT")]),
        ]
        report = ReportClient.generate_report(subreports, "dfs", "foo")
        correct = ("0203646673010101010101010144f2444801000a054f49cc030"
                   "54f4147010300065db8d8220803020011260628000220000102"
                   "48189325c81946070c90ebfd8d9da4a67577")
        try:
            hex_report = "".join("%.2x" % ord(c) for c in report)
        except TypeError:
            # Python 3.
            hex_report = "".join("%.2x" % c for c in report)
        # XXX Why are we printing things in a unit test?
        print(hex_report[:-20])
        print(correct[:-20])
        self.assertEqual(hex_report, correct)


class MockTest(unittest.TestCase):
    def test_1(self):
        self.assertEqual(1, 1)
