import unittest
import sys

from eset_ndf_parser import EsetNdfParser
from eset_virlog_parser import EsetVirlogParser

if sys.hexversion >= 0x03000000:
    from io import StringIO
else:
    from StringIO import StringIO
from contextlib import contextmanager


@contextmanager
def capture():
    out, sys.stdout = sys.stdout, StringIO()
    err, sys.stderr = sys.stderr, StringIO()
    try:
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout = out
        sys.stderr = err


class HelperMethodsTest(unittest.TestCase):
    def test_timestamp_conversion(self):
        time_bytes = int.to_bytes(131349483990000000, length=8, byteorder="little")
        from utils import RawTimeConverter

        tc = RawTimeConverter("windows")

        self.assertEqual(tc.decode(time_bytes).timestamp(), 1490474799)

    def test_timestamp_conversion_fail(self):
        from utils import RawTimeConverter

        self.assertRaises(ValueError, RawTimeConverter, ("debian",))

    def test_error_print(self):
        from EsetLogParser import eprint

        hello = "HelloError"
        with capture() as (out, err):
            eprint(hello)
        self.assertEqual(err.getvalue().strip(), hello)

    def test_info_message(self):
        from EsetLogParser import _infoNotFound

        field = "FIELD"
        with capture() as (out, err):
            _infoNotFound(field)
        msg = err.getvalue().strip()
        self.assertTrue(msg.find("Info") > -1)
        self.assertTrue(msg.find(field) > -1)

    def test_warning_message(self):
        from EsetLogParser import _warningUnexpected

        field = "FIELD"
        with capture() as (out, err):
            _warningUnexpected(field)
        msg = err.getvalue().strip()
        self.assertTrue(msg.find("Warning") > -1)
        self.assertTrue(msg.find(field) > -1)


class ArgumentTest(unittest.TestCase):
    def test_virlog_argument(self):
        from EsetLogParser import _parse_args

        virlog = "virlog.dat"
        args = _parse_args([virlog])
        self.assertEqual(args.path, virlog)

    def test_main_argument_nonexistent(self):
        import EsetLogParser

        with capture() as (out, err):
            self.assertRaises(
                Exception,
                EsetLogParser.main,
                (["test.dat"],),
                msg="virlog file does not exist",
            )


class EsetLogParserTest(unittest.TestCase):
    def setUp(self):
        virlog = "testlog.dat"
        self.data = EsetVirlogParser.from_file(virlog)

    def test_get_raw_records(self):
        from EsetLogParser import getRawVirlogRecords

        records = getRawVirlogRecords(self.data)
        self.assertEqual(len(records), 2)

    def test_parse_record(self):
        from EsetLogParser import getRawVirlogRecords, parseVirlogRecord

        records = getRawVirlogRecords(self.data)
        with capture() as (out, err):
            parsed = parseVirlogRecord(records[0][0], records[0][1])
        self.assertEqual(int(parsed[0]), 0)
        self.assertTrue("@Teststring.Eicar" in parsed)
        self.assertTrue("3395856ce81f2b7382dee72602f798b642f14140" in parsed)

    def test_main(self):
        import EsetLogParser

        with capture() as (out, err):
            parsed = EsetLogParser.main(["testlog.dat"])
        msg = out.getvalue()
        self.assertEqual(msg.count("\n"), 3)
        self.assertTrue(msg.find("@Teststring.Eicar") > -1)
        self.assertTrue(msg.find("3395856ce81f2b7382dee72602f798b642f14140") > -1)


class EsetNDFParserTest(unittest.TestCase):
    def setUp(self):
        ndf = "testndf.ndf"
        self.data = EsetNdfParser.from_file(ndf)

    def test_get_raw_records(self):
        from EsetLogParser import getRawNDFRecords

        header, records = getRawNDFRecords(self.data)
        self.assertEqual(len(records), 2)
        self.assertEqual(type(header), dict)
        self.assertEqual(len(header), 4)

    def test_parse_record(self):
        from EsetLogParser import getRawNDFRecords, parseNdfRecord

        header, records = getRawNDFRecords(self.data)
        with capture() as (out, err):
            parsed = parseNdfRecord(records[0][0], records[0][1])
            parsed_header = list(header.values())
        self.assertEqual(int(parsed[0]), 0)
        self.assertIn("@NAME=Eicar@TYPE=Teststring@SUSP=inf", parsed)
        self.assertIn("3395856ce81f2b7382dee72602f798b642f14140", parsed_header)
        self.assertIn(68, parsed_header)

    def test_main(self):
        import EsetLogParser

        with capture() as (out, err):
            parsed = EsetLogParser.main(["testndf.ndf", "--type", "ndf"])
        msg = out.getvalue()
        self.assertEqual(msg.count("\n"), 5)
        self.assertTrue(msg.find("@NAME=Eicar@TYPE=Teststring@SUSP=inf") > -1)
        self.assertTrue(msg.find("3395856ce81f2b7382dee72602f798b642f14140") > -1)
        self.assertTrue(msg.find("68") > -1)


if __name__ == "__main__":
    unittest.main()
