#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Standalone parser for ESET quarantine metadata (NDF) files."""

import sys

if sys.version_info < (3, 10):
    raise ImportError("eset_ndf_parser requires Python 3.10 or newer")

import argparse
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Generic, TypeVar

__author__ = "Ladislav Baco, Jozef Sabo"
__copyright__ = "Copyright (C) 2017-2026"
__credits__ = "Ladislav Baco, Jozef Sabo"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"

TIMEFORMAT = "%Y-%m-%dT%H:%M:%SZ"
T = TypeVar("T")


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def _info_not_found(field: str) -> None:
    eprint("Info: field not found: " + field)


def _warning_unexpected(field: str) -> None:
    eprint("Warning: unexpected bytes in field " + field)


class DataTypeParseError(ValueError):
    def __init__(self, message: str, next_offset: int) -> None:
        super().__init__(message)
        self.next_offset = next_offset


class DataType(Generic[T], ABC):
    @abstractmethod
    def convert(self, data: bytes) -> T:
        pass

    @abstractmethod
    def parse(self, data: bytes, offset: int = 0) -> tuple[T, int]:
        pass


class GeneralTimestamp(DataType[datetime], ABC):
    def __init__(self, size: int) -> None:
        self.size = size

    def parse(self, data: bytes, offset: int = 0) -> tuple[datetime, int]:
        next_offset = offset + self.size
        try:
            return self.convert(data[offset:next_offset]), next_offset
        except ValueError as error:
            raise DataTypeParseError(str(error), next_offset) from error


class WinTimestamp(GeneralTimestamp):
    def __init__(self) -> None:
        super().__init__(8)

    def convert(self, data: bytes) -> datetime:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("WinTimestamp does not contain enough bytes for size recognition")
        wintime = int.from_bytes(data, byteorder="little")
        timestamp = (wintime // 10000000) - 11644473600
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)


class UnixTimestamp(GeneralTimestamp):
    def convert(self, data: bytes) -> datetime:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UnixTimestamp does not contain enough bytes for size recognition")
        timestamp = int.from_bytes(data, byteorder="little")
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)


class UInt(DataType[int]):
    def __init__(self, size: int) -> None:
        self.size = size

    def convert(self, data: bytes) -> int:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UInt does not contain enough bytes for size recognition")
        return int.from_bytes(data, byteorder="little")

    def parse(self, data: bytes, offset: int = 0) -> tuple[int, int]:
        next_offset = offset + self.size
        try:
            return self.convert(data[offset:next_offset]), next_offset
        except ValueError as error:
            raise DataTypeParseError(str(error), next_offset) from error


class Hash(DataType[bytes]):
    def convert(self, data: bytes) -> bytes:
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("Hash does not contain enough bytes for size recognition")
        nbytes = int.from_bytes(nbytes, byteorder="little")

        data = data[:nbytes]
        if len(data) != nbytes:
            raise ValueError("Hash does not contain enough data bytes")
        return data

    def parse(self, data: bytes, offset: int = 0) -> tuple[bytes, int]:
        nbytes, hash_offset = UInt(4).parse(data, offset)
        next_offset = hash_offset + nbytes
        try:
            return self.convert(data[offset:next_offset]), next_offset
        except ValueError as error:
            raise DataTypeParseError(str(error), next_offset) from error


class NdfWideString(DataType[str]):
    """NDF wide string prefixed by its UTF-16 code-unit count."""

    def convert(self, data: bytes) -> str:
        length_data, text_data = data[:4], data[4:]
        length = UInt(4).convert(length_data)
        text = text_data[:length * 2]
        if len(text) != length * 2:
            raise ValueError("NdfWideString does not contain enough data bytes")
        return text.decode("utf-16-le")

    def parse(self, data: bytes, offset: int = 0) -> tuple[str, int]:
        length, text_offset = UInt(4).parse(data, offset)
        next_offset = text_offset + length * 2
        try:
            return self.convert(data[offset:next_offset]), next_offset
        except (ValueError, UnicodeError) as error:
            raise DataTypeParseError(str(error), next_offset) from error


class EsetNdfParser:
    MAGIC = b"FQDF\xa4\x0f\x00\x00"
    FILLER = b"\x00\x00\x00\x00"

    HEADER_OUTPUT_FIELDS = (
        "datetime",
        "mal_hash_sha1",
        "mal_size",
        "num_findings",
    )
    OUTPUT_FIELDS = (
        "datetime_first_utc",
        "datetime_latest_occurence",
        "datetime_quar_enc_start",
        "datetime_quar_enc_stop",
        "mal_path",
        "mal_path2",
        "threat_canonized",
        "threat_local",
        "threat_occurrence",
    )

    class BlockType(IntEnum):
        LOCAL_THREAT_BLOCK = 0x4957494E
        WEB_THREAT_BLOCK = 0x6AF88A0C

    @classmethod
    def _expect(cls, data: bytes, expected: bytes, field: str) -> int:
        actual = data[:len(expected)]
        if len(actual) != len(expected):
            raise ValueError("Unexpected end of NDF data")
        if actual != expected:
            raise ValueError(f"Invalid {field}: expected {expected.hex()}, got {actual.hex()}")
        return len(expected)

    @staticmethod
    def _parse_data_type(data_type: DataType[Any], data: bytes, field: str) -> tuple[Any, int]:
        try:
            return data_type.parse(data)
        except DataTypeParseError as error:
            eprint(
                f"Error when parsing NDF field \"{field}\" of type "
                f"{data_type.__class__.__name__}: {error}"
            )
            _info_not_found(field)
            return None, error.next_offset

    @classmethod
    def _parse_local_block(cls, data: bytes, date_block_size: int) -> dict[str, Any]:
        block = data[:date_block_size]
        if len(block) != date_block_size:
            raise ValueError("Unexpected end of NDF data")
        if date_block_size != 32:
            raise ValueError("Unexpected trailing bytes in local threat block")
        result = {}
        for field, data_type in (
            ("datetime_quar_enc_start", WinTimestamp()),
            ("datetime_first_utc", WinTimestamp()),
            ("datetime_quar_enc_stop", WinTimestamp()),
            ("unknown_size", UInt(4)),
            ("datetime_latest_occurence", UnixTimestamp(4)),
        ):
            result[field], offset = cls._parse_data_type(data_type, block, field)
            block = block[offset:]
        return result

    @classmethod
    def _parse_block(cls, data: bytes) -> tuple[dict[str, Any], int]:
        original_size = len(data)
        date_block_size, offset = cls._parse_data_type(UInt(4), data, "date_block_size")
        data = data[offset:]
        block_type_value, offset = cls._parse_data_type(UInt(4), data, "block_type_header")
        data = data[offset:]
        try:
            block_type = cls.BlockType(block_type_value)
        except ValueError as error:
            raise ValueError("Unknown NDF threat block type") from error

        result: dict[str, Any] = {
            "date_block_size": date_block_size,
            "block_type_header": block_type,
        }
        match block_type:
            case cls.BlockType.LOCAL_THREAT_BLOCK:
                result.update(cls._parse_local_block(data, date_block_size))
            case cls.BlockType.WEB_THREAT_BLOCK:
                result["web_data"] = data[:date_block_size]
                if len(result["web_data"]) != date_block_size:
                    raise ValueError("Unexpected end of NDF data")
        return result, original_size - len(data) + date_block_size

    @classmethod
    def extract_data_from_record(cls, data: bytes) -> tuple[dict[str, Any], int]:
        original_size = len(data)
        mal_path, offset = cls._parse_data_type(NdfWideString(), data, "mal_path")
        data = data[offset:]
        record: dict[str, Any] = {"mal_path": mal_path}
        block, offset = cls._parse_block(data)
        data = data[offset:]
        record.update(block)
        offset = cls._expect(data, cls.FILLER, "first threat filler")
        data = data[offset:]
        record["threat_local"], offset = cls._parse_data_type(NdfWideString(), data, "threat_local")
        data = data[offset:]
        record["threat_canonized"], offset = cls._parse_data_type(
            NdfWideString(), data, "threat_canonized"
        )
        data = data[offset:]
        offset = cls._expect(data, cls.FILLER, "second threat filler")
        data = data[offset:]
        record["threat_occurence"], offset = cls._parse_data_type(UInt(4), data, "threat_occurence")
        data = data[offset:]
        record["unknown"], data = data[:4], data[4:]
        if len(record["unknown"]) != 4:
            raise ValueError("Unexpected end of NDF data")
        record["datetime_unix"], offset = cls._parse_data_type(UnixTimestamp(4), data, "datetime_unix")
        data = data[offset:]
        record["mal_path2"], offset = cls._parse_data_type(NdfWideString(), data, "mal_path2")
        data = data[offset:]
        return record, original_size - len(data)

    @classmethod
    def get_raw_records(cls, data: bytes) -> tuple[dict[str, Any], list[tuple[int, dict[str, Any]]]]:
        offset = cls._expect(data, cls.MAGIC, "NDF magic")
        data = data[offset:]
        num_findings, offset = cls._parse_data_type(UInt(4), data, "num_findings")
        data = data[offset:]
        timestamp, offset = cls._parse_data_type(UnixTimestamp(4), data, "datetime")
        data = data[offset:]
        header = {"num_findings": num_findings, "datetime": timestamp}
        offset = cls._expect(data, cls.FILLER, "header filler")
        data = data[offset:]
        header["mal_size"], offset = cls._parse_data_type(UInt(8), data, "mal_size")
        data = data[offset:]
        header["mal_hash_sha1"], offset = cls._parse_data_type(Hash(), data, "mal_hash_sha1")
        data = data[offset:]

        records = []
        if header["num_findings"] is None:
            eprint("Error when parsing NDF: cannot locate findings without a valid finding count")
            return header, records
        for record_id in range(header["num_findings"]):
            record, offset = cls.extract_data_from_record(data)
            data = data[offset:]
            records.append((record_id, record))
        if data:
            _warning_unexpected("trailing bytes in NDF file")
        return header, records

    @classmethod
    def _extract_data_type(cls, field: str, record: dict[str, Any]) -> str:
        data = record.get(field)
        match data:
            case None:
                return ""
            case bytes():
                return data.hex()
            case datetime():
                return data.strftime(TIMEFORMAT)
            case _:
                return str(data)

    @classmethod
    def parse_header(cls, header: dict[str, Any]) -> list[str]:
        return [cls._extract_data_type(field, header) for field in cls.HEADER_OUTPUT_FIELDS]

    @classmethod
    def parse_record(cls, record_id: int, record: dict[str, Any]) -> list[str]:
        return [str(record_id)] + [
            cls._extract_data_type(field, record) for field in cls.OUTPUT_FIELDS
        ]

    def parse_records(self, ndf_data: bytes) -> tuple[list[list[str]], list[list[str]]]:
        header, records = self.get_raw_records(ndf_data)
        parsed_header = [
            ["first_seen", "hex_SHA1", "malicious_file_size", "number_of_findings"],
            self.parse_header(header),
        ]
        parsed_records = [[
            "ID",
            "first_seen",
            "most_recent_seen",
            "quarantine_encoding_start",
            "quarantine_encoding_finished",
            "path_1",
            "path_2",
            "infiltration",
            "infiltration_localized",
            "number_of_detections",
        ]]
        parsed_records.extend(self.parse_record(record_id, record) for record_id, record in records)
        return parsed_header, parsed_records


def _parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse an ESET quarantine metadata .ndf file without external dependencies."
    )
    parser.add_argument("ndf", help="path to an .ndf file")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
    return parser.parse_args(args)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if not os.path.isfile(args.ndf):
        raise FileNotFoundError("NDF file does not exist")

    with open(args.ndf, "rb") as file:
        ndf_data = file.read()

    parsed_header, parsed_records = EsetNdfParser().parse_records(ndf_data)
    print("\n".join(";".join(row) for row in parsed_header))
    print("\n".join(";".join(row) for row in parsed_records))


if __name__ == "__main__":
    main()
