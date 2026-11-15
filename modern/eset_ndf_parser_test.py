import os
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO

from eset_ndf_parser import (
    EsetNdfParser,
    Hash,
    NdfWideString,
    UInt,
    UnixTimestamp,
    WinTimestamp,
    main,
)

TEST_NDF = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'testndf.ndf',
)


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


class NdfDataStructuresTest(unittest.TestCase):
    def test_ndf_wide_string(self):
        text = 'Eicar testovací súbor'
        data = len(text).to_bytes(4, 'little') + text.encode('utf-16-le')
        self.assertEqual(NdfWideString().convert(data), text)

    def test_ndf_wide_string_does_not_require_terminator(self):
        data = (5).to_bytes(4, 'little') + 'Eicar'.encode('utf-16-le')
        self.assertEqual(NdfWideString().convert(data), 'Eicar')

    def test_ndf_wide_string_fail_not_enough_data(self):
        self.assertRaises(ValueError, NdfWideString().convert, bytes([2, 0, 0, 0, 0x41, 0]))


class ParseDataStructuresTest(unittest.TestCase):
    def test_uint_parse(self):
        self.assertEqual(UInt(4).parse(b'\xff\x01\x00\x00\x00', 1), (1, 5))

    def test_win_timestamp_parse(self):
        data = (116444736000000000).to_bytes(8, 'little')
        self.assertEqual(
            WinTimestamp().parse(data),
            (datetime(1970, 1, 1, tzinfo=timezone.utc), 8),
        )

    def test_unix_timestamp_parse(self):
        self.assertEqual(
            UnixTimestamp(4).parse(bytes(4)),
            (datetime(1970, 1, 1, tzinfo=timezone.utc), 4),
        )

    def test_hash_parse(self):
        data = (2).to_bytes(4, 'little') + b'\x15\x29'
        self.assertEqual(Hash().parse(data), (b'\x15\x29', len(data)))

    def test_ndf_wide_string_parse(self):
        data = (1).to_bytes(4, 'little') + 'a'.encode('utf-16-le')
        self.assertEqual(NdfWideString().parse(data), ('a', len(data)))

    def test_parse_error_contains_recovery_offset(self):
        with self.assertRaises(ValueError) as context:
            UInt(4).parse(b'\x01')
        self.assertEqual(context.exception.next_offset, 4)


class EsetNdfParserTest(unittest.TestCase):
    def setUp(self):
        with open(TEST_NDF, 'rb') as file:
            self.data = file.read()

    def test_get_raw_records(self):
        header, records = EsetNdfParser.get_raw_records(self.data)
        self.assertEqual(len(records), 2)
        self.assertIsInstance(header, dict)
        self.assertEqual(len(header), 4)
        self.assertEqual(header['num_findings'], 2)
        self.assertEqual(header['mal_size'], 68)
        self.assertEqual(header['mal_hash_sha1'].hex(), '3395856ce81f2b7382dee72602f798b642f14140')
        self.assertEqual(header['datetime'], datetime(2025, 3, 13, 17, 0, 5, tzinfo=timezone.utc))

    def test_parse_header(self):
        header, _ = EsetNdfParser.get_raw_records(self.data)
        parsed_header = EsetNdfParser.parse_header(header)
        self.assertIn('3395856ce81f2b7382dee72602f798b642f14140', parsed_header)
        self.assertIn('68', parsed_header)
        self.assertIn('2', parsed_header)
        self.assertEqual(parsed_header, [
            '2025-03-13T17:00:05Z',
            '3395856ce81f2b7382dee72602f798b642f14140',
            '68',
            '2',
        ])

    def test_parse_record(self):
        _, records = EsetNdfParser.get_raw_records(self.data)
        parsed = EsetNdfParser.parse_record(records[0][0], records[0][1])
        self.assertEqual(parsed[0], '0')
        self.assertEqual(len(parsed), 10)
        self.assertIn('@NAME=Eicar@TYPE=Teststring@SUSP=inf', parsed)
        self.assertIn('C:\\Users\\vboxuser\\Desktop\\eicar(1).com', parsed)
        self.assertEqual(parsed[1:5], [
            '2025-03-11T09:11:01Z',
            '2025-03-13T17:00:05Z',
            '2025-03-13T17:00:05Z',
            '2025-03-13T17:00:05Z',
        ])

    def test_parse_records(self):
        parsed_header, parsed_records = EsetNdfParser().parse_records(self.data)
        self.assertEqual(len(parsed_header), 2)
        self.assertEqual(len(parsed_records), 3)
        self.assertTrue(all(len(record) == 10 for record in parsed_records))

    def test_main(self):
        with capture() as (out, err):
            main([TEST_NDF])
        msg = out.getvalue()
        self.assertEqual(msg.count('\n'), 5)
        self.assertIn('@NAME=Eicar@TYPE=Teststring@SUSP=inf', msg)
        self.assertIn('3395856ce81f2b7382dee72602f798b642f14140', msg)
        self.assertIn(';68;2', msg)

    def test_invalid_magic(self):
        with self.assertRaisesRegex(ValueError, 'NDF magic'):
            EsetNdfParser.get_raw_records(b'not an NDF file')

    def test_truncated_file(self):
        with capture() as (out, err):
            _, records = EsetNdfParser.get_raw_records(self.data[:-1])
        self.assertEqual(len(records), 2)
        self.assertIsNone(records[-1][1]['mal_path2'])
        self.assertIn('NdfWideString does not contain enough data bytes', err.getvalue())
        self.assertIn('Info: field not found: mal_path2', err.getvalue())

    def test_unknown_block_type(self):
        block_offset = self.data.index(bytes.fromhex('4e495749'))
        data = self.data[:block_offset] + b'\xff\xff\xff\xff' + self.data[block_offset + 4:]
        with self.assertRaisesRegex(ValueError, 'block type'):
            EsetNdfParser.get_raw_records(data)

    def test_nonzero_filler(self):
        data = self.data[:16] + b'\x01\x00\x00\x00' + self.data[20:]
        with self.assertRaisesRegex(ValueError, 'header filler'):
            EsetNdfParser.get_raw_records(data)

    def test_invalid_local_block_size(self):
        block_offset = self.data.index(bytes.fromhex('4e495749'))
        size_offset = block_offset - 4
        data = self.data[:size_offset] + (33).to_bytes(4, 'little') + self.data[block_offset:]
        with self.assertRaisesRegex(ValueError, 'local threat block'):
            EsetNdfParser.get_raw_records(data)

    def test_web_threat_block(self):
        def wide(text):
            return len(text).to_bytes(4, 'little') + text.encode('utf-16-le')

        header = (
            EsetNdfParser.MAGIC
            + (1).to_bytes(4, 'little')
            + bytes(4)
            + EsetNdfParser.FILLER
            + bytes(8)
            + bytes(4)
        )
        record = (
            wide('url')
            + bytes(4)
            + int(EsetNdfParser.BlockType.WEB_THREAT_BLOCK).to_bytes(4, 'little')
            + EsetNdfParser.FILLER
            + wide('localized')
            + wide('canonical')
            + EsetNdfParser.FILLER
            + (1).to_bytes(4, 'little')
            + bytes(4)
            + bytes(4)
            + wide('url')
        )
        parsed_header, records = EsetNdfParser.get_raw_records(header + record)
        self.assertEqual(parsed_header['num_findings'], 1)
        self.assertEqual(records[0][1]['mal_path'], 'url')
        self.assertEqual(
            records[0][1]['block_type_header'],
            EsetNdfParser.BlockType.WEB_THREAT_BLOCK,
        )
        self.assertEqual(records[0][1]['web_data'], b'')

    def test_main_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            main(['test.ndf'])


if __name__ == '__main__':
    unittest.main()
