import unittest
import sys
from datetime import datetime

from EsetLogParser import Hash, UnixTimestamp, WinTimestamp, UInt, CString, WideString, UTC_TIMEZONE

if sys.hexversion >= 0x03000000:
    from io import StringIO
else:
    from StringIO import StringIO
    bytes = bytearray
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

class DataStructuresTest(unittest.TestCase):
    def test_wide_string(self):
        data = bytes([
            0x76, 0x00, 0x00, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x5c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x6e, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x61, 0x00,
            0x64, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x75, 0x00, 0x74, 0x00, 0x77, 0x00, 0x65, 0x00, 0x62, 0x00,
            0x5f, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x73, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x6c, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x77, 0x00, 0x6a, 0x00, 0x51, 0x00, 0x67, 0x00, 0x73, 0x00,
            0x31, 0x00, 0x5f, 0x00, 0x4e, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x2e, 0x00,
            0x70, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x00, 0x00
        ])
        self.assertEqual(WideString().convert(data), "C:\\Users\\admin\\Downloads\\utweb_installer.wjQgs1_N.exe.part")

    def test_wide_string_fail_not_enough_integer(self):
        data = bytes([
            0x76, 0x00
        ])
        self.assertRaises(ValueError, WideString().convert, data)

    def test_wide_string_fail_not_enough_data(self):
        data = bytes([
            0x76, 0x00, 0x00, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00,
        ])
        self.assertRaises(ValueError, WideString().convert, data)

    def test_wide_null_bytes_missing(self):
        data = bytes([
            0x76, 0x00, 0x00, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x5c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x6e, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x61, 0x00,
            0x64, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x75, 0x00, 0x74, 0x00, 0x77, 0x00, 0x65, 0x00, 0x62, 0x00,
            0x5f, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x73, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x6c, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x77, 0x00, 0x6a, 0x00, 0x51, 0x00, 0x67, 0x00, 0x73, 0x00,
            0x31, 0x00, 0x5f, 0x00, 0x4e, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x2e, 0x00,
            0x70, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x00, 0x01
        ])
        self.assertRaises(ValueError, WideString().convert, data)

    def test_cstr_string(self):
        data = bytes([
            0x1b, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
            0x73, 0x6f, 0x66, 0x74, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x00
        ])
        self.assertEqual(CString().convert(data), "https://www.softpedia.com/")

    def test_cstr_string_fail_not_enough_integer(self):
        data = bytes([
            0x1b, 0x00
        ])
        self.assertRaises(ValueError, CString().convert, data)

    def test_cstr_string_fail_not_enough_data(self):
        data = bytes([
            0x1b, 0x00, 0x00, 0x00, 0x68,
        ])
        self.assertRaises(ValueError, CString().convert, data)

    def test_cstr_null_bytes_missing(self):
        data = bytes([
            0x1b, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
            0x73, 0x6f, 0x66, 0x74, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x01
        ])
        self.assertRaises(ValueError, CString().convert, data)

    def test_uint(self):
        data = bytes([
            0x10, 0x05
        ])
        self.assertEqual(UInt(1).convert(data), 0x10)
        self.assertEqual(UInt(1).convert(data[1:]), 0x05)

        data = bytes([
            0x10, 0x05
        ])
        self.assertEqual(UInt(2).convert(data), 0x0510)

        data = bytes([
            0x10, 0x05, 0x87, 0x78
        ])
        self.assertEqual(UInt(4).convert(data), 0x078870510)

        data = bytes([
            0x10, 0x05, 0x87, 0x78, 0x11, 0x12, 0x33, 0x06, 0x75
        ])
        self.assertEqual(UInt(8).convert(data), 0x0633121178870510)

    def test_uint_fail_ne_data(self):
        data = bytes([
            0x1b
        ])
        self.assertRaises(ValueError, UInt(2).convert, data)

    def test_win_timestamp(self):
        data = bytes([
            0x51, 0xdf, 0xb5, 0x88, 0x60, 0x74, 0xdd, 0x01
        ])
        self.assertEqual(WinTimestamp().convert(data),
                         datetime(year=2026, month=11, day=14, hour=17, minute=49, second=45,
                                  tzinfo=UTC_TIMEZONE))

    def test_win_timestamp_fail(self):
        data = bytes([
            0x51
        ])
        self.assertRaises(ValueError, WinTimestamp().convert, data)

    def test_unix_timestamp(self):
        data = bytes([
            0xac, 0x9a, 0xf8, 0x6a
        ])
        self.assertEqual(UnixTimestamp(4).convert(data),
                         datetime(year=2026, month=11, day=14, hour=17, minute=30, second=20,
                                  tzinfo=UTC_TIMEZONE))

    def test_unix_timestamp_fail(self):
        data = bytes([
            0xac, 0x9a, 0xf8
        ])
        self.assertRaises(ValueError, UnixTimestamp(4).convert, data)

    def test_hash(self):
        data = bytes([
            0x02, 0x00, 0x00, 0x00, 0x15, 0x29
        ])
        self.assertEqual(Hash().convert(data), bytes([0x15, 0x29]))

    def test_hash_fail_not_enough_integer(self):
        data = bytes([
            0x02, 0x00
        ])
        self.assertRaises(ValueError, Hash().convert, data)

    def test_hash_fail_not_enough_data(self):
        data = bytes([
            0x02, 0x00, 0x00, 0x00, 0x15
        ])
        self.assertRaises(ValueError, Hash().convert, data)

class HelperMethodsTest(unittest.TestCase):
    def test_timestamp_conversion(self):
        from EsetLogParser import _winToUnixTimestamp
        self.assertEqual(_winToUnixTimestamp(131349483990000000), 1490474799)
    def test_error_print(self):
        from EsetLogParser import eprint
        hello = 'HelloError'
        with capture() as (out, err):
            eprint(hello)
        self.assertEqual(err.getvalue().strip(), hello)

    def test_info_message(self):
        from EsetLogParser import _infoNotFound
        field = 'FIELD'
        with capture() as (out, err):
            _infoNotFound(field)
        msg = err.getvalue().strip()
        self.assertTrue(msg.find('Info') > -1)
        self.assertTrue(msg.find(field) > -1)

    def test_warning_message(self):
        from EsetLogParser import _warningUnexpected
        field = 'FIELD'
        with capture() as (out, err):
            _warningUnexpected(field)
        msg = err.getvalue().strip()
        self.assertTrue(msg.find('Warning') > -1)
        self.assertTrue(msg.find(field) > -1)

class ArgumentTest(unittest.TestCase):
    def test_virlog_argument(self):
        from EsetLogParser import _parse_args
        virlog = 'virlog.dat'
        args = _parse_args([virlog])
        self.assertEqual(args.virlog, virlog)

class EsetLogParserTest(unittest.TestCase):
    def setUp(self):
        virlog = 'testlog.dat'
        with open(virlog, 'rb') as f:
            self.data = f.read()

    def test_get_raw_records(self):
        from EsetLogParser import getRawRecords
        records = getRawRecords(self.data)
        self.assertEqual(len(records), 2)

    def test_parse_record(self):
        from EsetLogParser import getRawRecords, parseRecord
        records = getRawRecords(self.data)
        with capture() as (out, err):
            parsed = parseRecord(records[0][0], records[0][1])
        self.assertEqual(int(parsed[0]), 0)
        self.assertTrue('@Teststring.Eicar' in parsed)
        self.assertTrue('3395856ce81f2b7382dee72602f798b642f14140' in parsed)
    def test_main(self):
        import EsetLogParser
        with capture() as (out, err):
            parsed = EsetLogParser.main(['testlog.dat'])
        msg = out.getvalue()
        self.assertEqual(msg.count('\n'),3)
        self.assertTrue(msg.find('@Teststring.Eicar') > -1)
        self.assertTrue(msg.find('3395856ce81f2b7382dee72602f798b642f14140') > -1)

if __name__ == '__main__':
    unittest.main()
