#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Deprecated compatibility interface for the modern ESET virlog parser."""

import warnings
from collections.abc import Callable
from functools import wraps
from typing import Any, cast, TypeVar

from eset_virlog_parser import (
    EsetVirlogParser,
    _info_not_found,
    _warning_unexpected,
    WinTimestamp,
)

F = TypeVar('F', bound=Callable[..., Any])


# Type mapper for backwards compatibility
RECORD_TYPE_MAPPER = {
    "VirusDB": "virus_db",
    "Object": "object_name",
    "ObjectHash": "object_hash",
    "Infiltration": "infiltration_name",
    "User": "user_name",
    "ProgName": "program_name",
    "ProgHash": "program_hash",
}


def deprecated(func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        warnings.warn(
            "{} is deprecated and will be removed in a future version".format(func.__name__),
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    return cast(F, wrapper)


@deprecated
def getRawRecords(rawData: bytes) -> list[tuple[int, bytes]]:
    return EsetVirlogParser.get_raw_records(rawData)


@deprecated
def parseRecord(recordId: int, recordData: bytes) -> list[str]:
    return EsetVirlogParser.parse_record(
        recordId, EsetVirlogParser.extract_data_from_record(recordData)
    )


@deprecated
def _warningUnexpected(field: str) -> None:
    return _warning_unexpected(field)


@deprecated
def _infoNotFound(field: str) -> None:
    return _info_not_found(field)


@deprecated
def _winToUnixTimestamp(timestamp: int) -> float:
    return WinTimestamp().convert(timestamp.to_bytes(length=8, byteorder="little")).timestamp()
