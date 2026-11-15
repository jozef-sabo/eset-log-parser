import os
import sys
import unittest
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO

import EsetLogParser
from eset_virlog_parser import (
    CString,
    EsetVirlogParser,
    Hash,
    UInt,
    UnixTimestamp,
    WideString,
    WinTimestamp,
    _info_not_found,
    _parse_args,
    _warning_unexpected,
    eprint,
    main,
)

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_LOG = os.path.join(PROJECT_DIR, 'testlog.dat')


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
        self.assertRaises(ValueError, WideString().convert, bytes([0x76, 0x00]))

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
        self.assertRaises(ValueError, CString().convert, bytes([0x1b, 0x00]))

    def test_cstr_string_fail_not_enough_data(self):
        self.assertRaises(ValueError, CString().convert, bytes([0x1b, 0x00, 0x00, 0x00, 0x68]))

    def test_cstr_null_bytes_missing(self):
        data = bytes([
            0x1b, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
            0x73, 0x6f, 0x66, 0x74, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x01
        ])
        self.assertRaises(ValueError, CString().convert, data)

    def test_uint(self):
        self.assertEqual(UInt(1).convert(bytes([0x10, 0x05])), 0x10)
        self.assertEqual(UInt(1).convert(bytes([0x05])), 0x05)
        self.assertEqual(UInt(2).convert(bytes([0x10, 0x05])), 0x0510)
        self.assertEqual(UInt(4).convert(bytes([0x10, 0x05, 0x87, 0x78])), 0x078870510)
        self.assertEqual(
            UInt(8).convert(bytes([0x10, 0x05, 0x87, 0x78, 0x11, 0x12, 0x33, 0x06, 0x75])),
            0x0633121178870510,
        )

    def test_uint_fail_not_enough_data(self):
        self.assertRaises(ValueError, UInt(2).convert, bytes([0x1b]))

    def test_win_timestamp(self):
        data = bytes([0x51, 0xdf, 0xb5, 0x88, 0x60, 0x74, 0xdd, 0x01])
        self.assertEqual(
            WinTimestamp().convert(data),
            datetime(year=2026, month=11, day=14, hour=17, minute=49, second=45, tzinfo=timezone.utc),
        )

    def test_win_timestamp_fail(self):
        self.assertRaises(ValueError, WinTimestamp().convert, bytes([0x51]))

    def test_unix_timestamp(self):
        data = bytes([0xac, 0x9a, 0xf8, 0x6a])
        self.assertEqual(
            UnixTimestamp(4).convert(data),
            datetime(year=2026, month=11, day=14, hour=17, minute=30, second=20, tzinfo=timezone.utc),
        )

    def test_unix_timestamp_fail(self):
        self.assertRaises(ValueError, UnixTimestamp(4).convert, bytes([0xac, 0x9a, 0xf8]))

    def test_hash(self):
        data = bytes([0x02, 0x00, 0x00, 0x00, 0x15, 0x29])
        self.assertEqual(Hash().convert(data), bytes([0x15, 0x29]))

    def test_hash_fail_not_enough_integer(self):
        self.assertRaises(ValueError, Hash().convert, bytes([0x02, 0x00]))

    def test_hash_fail_not_enough_data(self):
        self.assertRaises(ValueError, Hash().convert, bytes([0x02, 0x00, 0x00, 0x00, 0x15]))


class HelperMethodsTest(unittest.TestCase):
    def test_error_print(self):
        with capture() as (out, err):
            eprint('HelloError')
        self.assertEqual(err.getvalue().strip(), 'HelloError')

    def test_info_message(self):
        with capture() as (out, err):
            _info_not_found('FIELD')
        msg = err.getvalue().strip()
        self.assertIn('Info', msg)
        self.assertIn('FIELD', msg)

    def test_warning_message(self):
        with capture() as (out, err):
            _warning_unexpected('FIELD')
        msg = err.getvalue().strip()
        self.assertIn('Warning', msg)
        self.assertIn('FIELD', msg)


class ArgumentTest(unittest.TestCase):
    def test_virlog_argument(self):
        self.assertEqual(_parse_args(['virlog.dat']).virlog, 'virlog.dat')


class EsetLogParserTest(unittest.TestCase):
    def setUp(self):
        with open(TEST_LOG, 'rb') as f:
            self.data = f.read()

    def test_get_raw_records(self):
        self.assertEqual(len(EsetVirlogParser.get_raw_records(self.data)), 2)

    def test_parse_records(self):
        parser = EsetVirlogParser()
        with capture():
            parsed = parser.parse_records(self.data)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ['ID'] + list(parser.OUTPUT_FIELDS))
        self.assertEqual(len(parsed[1]), len(parser.OUTPUT_FIELDS) + 1)

    def test_parse_record(self):
        records = EsetVirlogParser.get_raw_records(self.data)
        parsed = EsetVirlogParser.parse_record(
            records[0][0], EsetVirlogParser.extract_data_from_record(records[0][1])
        )
        self.assertEqual(int(parsed[0]), 0)
        self.assertEqual(len(parsed), len(EsetVirlogParser.OUTPUT_FIELDS) + 1)
        self.assertIn('@Teststring.Eicar', parsed)
        self.assertIn('3395856ce81f2b7382dee72602f798b642f14140', parsed)

    def test_output_fields(self):
        expected_first_fields = [
            'timestamp', 'virus_db', 'object_name', 'object_hash', 'infiltration_name',
            'user_name', 'program_name', 'program_hash', 'firstseen',
        ]
        self.assertEqual(list(EsetVirlogParser.OUTPUT_FIELDS[:9]), expected_first_fields)
        self.assertEqual(len(EsetVirlogParser.OUTPUT_FIELDS), len(EsetVirlogParser.INTERESTING_DATA_HEADERS) + 1)
        self.assertTrue(set(EsetVirlogParser.INTERESTING_DATA_HEADERS).issubset(EsetVirlogParser.OUTPUT_FIELDS))
        self.assertEqual(list(EsetVirlogParser.OUTPUT_FIELDS[9:]), [
            field for field in EsetVirlogParser.INTERESTING_DATA_HEADERS if field not in expected_first_fields
        ])

    def test_main(self):
        with capture() as (out, err):
            main([TEST_LOG])
        msg = out.getvalue()
        rows = [row.split(';') for row in msg.splitlines()]
        self.assertEqual(msg.count('\n'), 3)
        self.assertEqual(rows[0], ['ID'] + list(EsetVirlogParser.OUTPUT_FIELDS))
        self.assertTrue(all(len(row) == len(rows[0]) for row in rows))
        self.assertIn('@Teststring.Eicar', msg)
        self.assertIn('3395856ce81f2b7382dee72602f798b642f14140', msg)
        self.assertIn('cea0890d4b99bae3f635a16dae71f69d137027b9', msg)


class DeprecatedCompatibilityTest(unittest.TestCase):
    def setUp(self):
        with open(TEST_LOG, 'rb') as f:
            self.data = f.read()

    def assert_deprecated(self, function, *args):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            result = function(*args)
        self.assertTrue(any(item.category is DeprecationWarning for item in caught))
        return result

    def test_get_raw_records(self):
        self.assertEqual(len(self.assert_deprecated(EsetLogParser.getRawRecords, self.data)), 2)

    def test_parse_record(self):
        records = EsetVirlogParser.get_raw_records(self.data)
        with capture():
            parsed = self.assert_deprecated(EsetLogParser.parseRecord, records[0][0], records[0][1])
        self.assertIn('@Teststring.Eicar', parsed)

    def test_timestamp_conversion(self):
        self.assertEqual(self.assert_deprecated(EsetLogParser._winToUnixTimestamp, 131349483990000000), 1490474799)

    def test_info_and_warning_messages(self):
        with capture() as (out, err):
            self.assert_deprecated(EsetLogParser._infoNotFound, 'FIELD')
            self.assert_deprecated(EsetLogParser._warningUnexpected, 'FIELD')
        self.assertIn('Info: field not found: FIELD', err.getvalue())
        self.assertIn('Warning: unexpected bytes in field FIELD', err.getvalue())

    def test_record_type_mapper(self):
        self.assertEqual(EsetLogParser.RECORD_TYPE_MAPPER['Object'], 'object_name')
        self.assertEqual(EsetLogParser.RECORD_TYPE_MAPPER['ProgHash'], 'program_hash')


if __name__ == '__main__':
    unittest.main()
