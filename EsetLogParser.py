#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco
Copyright (C) 2026 Jozef Sabo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import print_function

import argparse
import binascii
import os
import struct
import sys
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta, tzinfo

if False:
    from typing import Any, Dict, List, Text, Tuple

__author__ = "Ladislav Baco, Jozef Sabo"
__copyright__ = "Copyright (C) 2017 Ladislav Baco, 2025-2026 Jozef Sabo"
__credits__ = "Ladislav Baco, Jozef Sabo"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"

TIMEFORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECORD_HEADER = b'\x24\x00\x00\x00\x01\x00\x01\x00'


class UTC(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)


UTC_TIMEZONE = UTC()
EPOCH = datetime(1970, 1, 1, tzinfo=UTC_TIMEZONE)


def _int_from_bytes(data):
    # type: (bytes) -> int
    if not data:
        return 0
    return int(binascii.hexlify(data[::-1]), 16)


def _bytes(values):
    # type: (List[int]) -> bytes
    return bytes(bytearray(values))


class DataType(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def convert(self, data):
        # type: (bytes) -> Any
        pass


class GeneralTimestamp(DataType):
    def __init__(self, size):
        # type: (int) -> None
        self.size = size


class WinTimestamp(GeneralTimestamp):
    def __init__(self):
        # type: () -> None
        super(WinTimestamp, self).__init__(8)

    def convert(self, data):
        # type: (bytes) -> datetime
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("WinTimestamp does not contain enough bytes for size recognition")
        wintime = _int_from_bytes(data)
        magic_number = 11644473600
        timestamp = (wintime // 10000000) - magic_number
        return datetime.fromtimestamp(timestamp, tz=UTC_TIMEZONE)


class UnixTimestamp(GeneralTimestamp):
    def __init__(self, size):
        # type: (int) -> None
        super(UnixTimestamp, self).__init__(size)

    def convert(self, data):
        # type: (bytes) -> datetime
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UnixTimestamp does not contain enough bytes for size recognition")
        timestamp = _int_from_bytes(data)
        return datetime.fromtimestamp(timestamp, tz=UTC_TIMEZONE)


class UInt(DataType):
    def __init__(self, size):
        # type: (int) -> None
        self.size = size

    def convert(self, data):
        # type: (bytes) -> int
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UInt does not contain enough bytes for size recognition")
        return _int_from_bytes(data)


class WideString(DataType):
    def convert(self, data):
        # type: (bytes) -> Text
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("WideString does not contain enough bytes for size recognition")
        nbytes = _int_from_bytes(nbytes)

        text = data[:nbytes]
        if len(text) != nbytes:
            raise ValueError("WideString does not contain enough data bytes")

        text, null_bytes = text[:-2], text[-2:]
        if null_bytes != b"\x00\x00":
            raise ValueError("WideString does not contain null bytes")

        return text.decode("utf-16-le").strip()


class CString(DataType):
    def convert(self, data):
        # type: (bytes) -> Text
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("CString does not contain enough bytes for size recognition")
        nbytes = _int_from_bytes(nbytes)

        text = data[:nbytes]
        if len(text) != nbytes:
            raise ValueError("CString does not contain enough data bytes")

        text, null_bytes = text[:-1], text[-1:]
        if null_bytes != b"\x00":
            raise ValueError("CString does not contain null byte")

        return text.decode("utf-8").strip()


class Hash(DataType):
    def convert(self, data):
        # type: (bytes) -> bytes
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("Hash does not contain enough bytes for size recognition")
        nbytes = _int_from_bytes(nbytes)

        data = data[:nbytes]
        if len(data) != nbytes:
            raise ValueError("Hash does not contain enough data bytes")
        return data


def eprint(*args, **kwargs):
    """Prints debug messages to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def _warning_unexpected(field):
    eprint('Warning: unexpected bytes in field ' + field)


def _check_id(record_id, raw_record):
    little_endian_ids = [raw_record[0:4], raw_record[16:20]]
    for little_endian_id in little_endian_ids:
        if struct.unpack('<L', little_endian_id)[0] != record_id:
            _warning_unexpected('ID')


def _info_not_found(field):
    eprint('Info: field not found: ' + field)


def get_raw_records(raw_data):
    # type: (bytes) -> List[Tuple[int, bytes]]
    raw_records = raw_data.split(RECORD_HEADER)[1:]
    zip_records = zip(range(len(raw_records)), raw_records)
    records = []
    for record_id, raw_record in zip_records:
        _check_id(record_id, raw_record)
        # create 2D array instead of zip-object in Python 3
        records.append((record_id, raw_record))
    return records


def _winToUnixTimestamp(timestamp):
    converted = WinTimestamp().convert(struct.pack('<Q', timestamp))
    return int((converted - EPOCH).total_seconds())


INTERESTING_DATA_HEADERS = {
    "program_hash": (_bytes([0x9d, 0x13, 0x42, 0x00]), Hash()),
    "object_hash": (_bytes([0x9e, 0x13, 0x42, 0x00]), Hash()),
    "object_hash3": (_bytes([0xa4, 0x13, 0x42, 0x00]), Hash()),
    "object_hash2": (_bytes([0xae, 0x13, 0x42, 0x00]), Hash()),
    "win_signing_cert_pubkey_fingerprint_hash": (_bytes([0xb3, 0x13, 0x42, 0x00]), Hash()),
    "win_signing_cert_pubkey_params": (_bytes([0xb2, 0x13, 0x45, 0x00]), UInt(4)),
    "win_lang_id": (_bytes([0x87, 0x27, 0x45, 0x00]), UInt(4)),
    "firstseen": (_bytes([0x9f, 0x13, 0x46, 0x00]), UnixTimestamp(8)),
    "source_web": (_bytes([0x92, 0x27, 0x4d, 0x00]), CString()),
    "user_name": (_bytes([0xee, 0x03, 0x4e, 0x00]), WideString()),
    "win_user_sid": (_bytes([0xf5, 0x03, 0x4e, 0x00]), WideString()),
    "object_name": (_bytes([0xbe, 0x0b, 0x4e, 0x00]), WideString()),
    "program_name": (_bytes([0xc4, 0x0b, 0x4e, 0x00]), WideString()),
    "progpath_name": (_bytes([0xa7, 0x13, 0x4e, 0x00]), WideString()),
    "path_name": (_bytes([0xa9, 0x13, 0x4e, 0x00]), WideString()),
    "win_signing_cert": (_bytes([0xb4, 0x13, 0x4e, 0x00]), WideString()),
    "execution_mode": (_bytes([0x59, 0x1b, 0x4e, 0x00]), WideString()),
    "infiltration_name": (_bytes([0x4d, 0x1d, 0x4e, 0x00]), WideString()),
    "virus_db": (_bytes([0x17, 0x27, 0x4e, 0x00]), WideString()),
    "win_company_name": (_bytes([0x88, 0x27, 0x4e, 0x00]), WideString()),
    "win_product_name3": (_bytes([0x89, 0x27, 0x4e, 0x00]), WideString()),
    "win_file_version": (_bytes([0x8a, 0x27, 0x4e, 0x00]), WideString()),
    "win_product_name2": (_bytes([0x8b, 0x27, 0x4e, 0x00]), WideString()),
    "win_legal_copyright": (_bytes([0x8c, 0x27, 0x4e, 0x00]), WideString()),
    "win_exe_name": (_bytes([0x8d, 0x27, 0x4e, 0x00]), WideString()),
    "win_product_name": (_bytes([0x8e, 0x27, 0x4e, 0x00]), WideString()),
    "win_product_version": (_bytes([0x8f, 0x27, 0x4e, 0x00]), WideString()),
}


def extract_data_from_record(data):
    # type: (bytes) -> Dict[str, Any]
    record_data = {}
    try:
        record_data["timestamp"] = WinTimestamp().convert(data[4:])
    except Exception as e:
        print("Error. Cannot parse timestamp.")

    for header_name, (header, data_type) in INTERESTING_DATA_HEADERS.items():
        idx = data.find(header)
        if idx == -1:
            continue
        idx += 4
        try:
            res = data_type.convert(data[idx:])
        except Exception as e:
            eprint(
                "Error when parsing record. Data for \"" + header_name + "\" of type " + data_type.__class__.__name__ + " on position " + str(
                    idx - 4) + ": " + str(e))
        else:
            record_data[header_name] = res

    return record_data


# type mapper for backwards compatibility
RECORD_TYPE_MAPPER = {
    "VirusDB": "virus_db",
    "Object": "object_name",
    "ObjectHash": "object_hash",
    "Infiltration": "infiltration_name",
    "User": "user_name",
    "ProgName": "program_name",
    "ProgHash": "program_hash",
}


def _extract_data_type(data_type, record):
    # type: (str, Dict[str, Any]) -> Text
    if data_type in RECORD_TYPE_MAPPER:
        data_type = RECORD_TYPE_MAPPER[data_type]

    data = record.get(data_type, None)

    if data is None:
        _info_not_found(data_type)
        return ''

    if isinstance(data, bytes):
        return binascii.hexlify(data).decode('utf-8')
    if isinstance(data, datetime):
        return data.strftime(TIMEFORMAT)
    return str(data)


def parse_record(record_id, record):
    timestamp = _extract_data_type("firstseen", record)
    virusdb = _extract_data_type('virus_db', record)
    obj = _extract_data_type('object_name', record)
    objhash = _extract_data_type('object_hash', record)
    infiltration = _extract_data_type('infiltration_name', record)
    user = _extract_data_type('user_name', record)
    progname = _extract_data_type('program_name', record)
    proghash = _extract_data_type('program_hash', record)
    firstseen = _extract_data_type("firstseen", record)

    return [str(record_id), timestamp, virusdb, obj, objhash, infiltration, user, progname, proghash, firstseen]


def _parse_args(args):
    parser = argparse.ArgumentParser(
        description='EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.')
    parser.add_argument('virlog', help='path to virlog.dat file')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    return parser.parse_args(args)


def getRawRecords(rawData):
    return get_raw_records(rawData)


def parseRecord(recordId, recordData):
    return parse_record(recordId, extract_data_from_record(recordData))


def _warningUnexpected(field):
    return _warning_unexpected(field)


def _infoNotFound(field):
    return _info_not_found(field)


def main(argv):
    args = _parse_args(argv)

    if not os.path.isfile(args.virlog):
        raise Exception('Virlog file does not exist')

    with open(args.virlog, 'rb') as f:
        virlog_data = f.read()

    records = get_raw_records(virlog_data)

    records_list = []
    parsed_records = [
        ['ID', 'Timestamp', 'VirusDB', 'Object', 'ObjectHash', 'Infiltration', 'User', 'ProgName', 'ProgHash',
         'FirstSeen']]
    for idx, record in records:
        records_list.append(extract_data_from_record(record))
        parsed_records.append(parse_record(idx, records_list[-1]))

    print('\n'.join([';'.join(record) for record in parsed_records]))


if __name__ == "__main__":
    main(sys.argv[1:])
