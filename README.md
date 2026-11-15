# EsetLogParser

[![Build Status](https://travis-ci.org/laciKE/EsetLogParser.svg?branch=master)](https://travis-ci.org/laciKE/EsetLogParser) [![Python 2.7|3.5|3.10](https://img.shields.io/badge/python-2.7|3.5|3.10-yellow.svg)](https://www.python.org/)

Proof of Concept

## About
Python script for parsing ESET (NOD32) `virlog.dat` file and metadata `.NDF` file. 
The `virlog.dat` file contains records about infections detected during on access scans and it is usually located in `C:\ProgramData\Eset\*\Logs`.
The file with the extension `.NDF` contains metadata about infiltrations inside the system for the specific malicious file defined by SHA1 hash. It can be usually found in `C:\Users\*\AppData\Local\ESET\ESET Security\Quarantine`.

GUI of Eset antivirus program can display content of actual `virlog.dat` file, also it is possible to use Eset Log Collector for collect logs from this file. But none of this official program can easily display content of another `virlog.dat` file, for example file exracted from offline machine for further analysis.
On live system, it is not possible to overwrite the existing `virlog.dat`, because it is used by running instance of Eset and it is not so easy to kill the Eset AV program. (turning off the resident shield is not enough).

*As far as I know, the only solution for displaying content of another virlog.dat file is to use the PC with Eset installed, shut down this PC, overwrite the original virdat.log file and reboot the system.*

This Python script can parse some content from `virlog.dat` files and convert this data to CSV format. 
This tool is based on reverse engineering the file format of `virlog.dat`, and work is in progress. 
For this reason, this scrit currently can not parse all the fields from `virlog.dat`. 
The same holds for the `.NQF` file.

### Disclaimer
Tested on current version of Eset Nod32 and Smart Security and also on versions from middle of 2016.
Correct functionality of this script is not guaranteed, because the file format of `virlog.dat` and `.NQF` file is proprietary internal format of Eset and this format may change with new versions of Eset products. 
In this case please create an Issue and if it is possible, please also provide samples of `virlog.dat`/`.NQF`.

## Supported fields

### virlog.dat
- Detected object
- Infiltration type
- User name
- Version of antivirus database
- Program name (or process) in which the infiltration was detected
- SHA1 hash of detected object
 Detected object
- First seen timestamp
- Timestamp of detection
- ID of record
- Program path which accessed malicious object
- Program path which accessed malicious object 2
- Hash of the above program
- Hash of the malicious object2
- Hash of the malicious object3
- Website which downloaded the file
- Windows Product name
- Windows Product name 2
- Windows Product name 3
- Windows Company name
- Windows Product version
- Windows File version
- Windows Legal copyright
- Windows Legal executable name
- Windows Language ID
- Windows Execution mode
- Windows User SID
- Windows Signing certificate
- Windows Signing certificate public key fingerprint
- Windows Signing certificate public key parameters

### Note
It seems that not of the above fields are always present in record. If you don't see some of the above fields in the output of EsetLogParser, but you see this value in Eset GUI (Tools -> Logs), please send me the `virlog.dat` file and screenshot of Eset GUI Log Viewer.

### .NDF file
- First seen timestamp
- Most recent seen timestamp
- Timestamp of the quarantine encoding start
- Timestamp of the quarantine encoding finish
- Path of the malicious file
- Second path of the malicious file
- Infiltration type
- Infiltration type in the local language
- Number of detections for the specific path of detection
- ID of record
- SHA1 hash of the malicious file
- Size of the malicious file
- Number of findings stored in the file
- Timestamp from the file header


## Known fields
The list of curentlly reversed fields in `virlog.dat` file that are not parsed by EsetLogParser:

## Unknown fields
The list of fields which I have not reversed in `virlog.dat` yet:
- Object type (file, etc.)
- Scanner (resident shield)
- Action (erase, quarantine)

## Usage
`python EsetLogParser.py path_to_virlog.dat`

## Modern implementation (Python 3.10+)

The `modern` directory contains a rewritten implementation for Python 3.10 and newer. It keeps the original command-line behavior while providing a reusable parser class and an expanded output format.

### Usage

Run the modern parser from the repository root:

```console
python modern/eset_virlog_parser.py path_to_virlog.dat
python modern/eset_ndf_parser.py path_to_metadata.ndf
```

The virlog output contains all fields configured in `EsetVirlogParser.INTERESTING_DATA_HEADERS`. The first columns preserve the legacy ordering for compatibility, while the remaining columns follow the configured field order. Missing values are represented by empty fields.

The NDF output consists of two semicolon-separated tables. The first table contains the malicious-file timestamp, SHA1 hash, size, and number of findings. The second table contains one row per finding, including its timestamps, paths, infiltration names, and detection count. Empty or unrecoverable values are reported as `(null)`. Parsing errors and warnings are written to standard error.

The parser can also be used directly from Python:

```python
from modern.eset_virlog_parser import EsetVirlogParser
from modern.eset_ndf_parser import EsetNdfParser
```

When importing them as part of an application, add `modern` to the module search path or use an appropriate package import. Parse binary `virlog.dat` data with `EsetVirlogParser().parse_records(data)`; the result is a list of rows, including the header row. Parse binary NDF data with `EsetNdfParser().parse_records(data)`; the result is a pair containing the header rows and finding-record rows. Both parsers operate on data already read from the file and do not require Kaitai Struct or other external dependencies.

### Advantages

- **Reusable class-based API:** `EsetVirlogParser` and `EsetNdfParser` encapsulate data decoding, record extraction, output-field ordering, and complete file parsing.
- **All configured fields:** output is no longer limited to the original selection of columns.
- **Modern static typing:** annotations with built-in generic types improve IDE auto-completion and static-analysis results.
- **Python 3.10 features:** structural pattern matching and strict ZIP processing make data handling clearer and safer.
- **Explicit compatibility checks:** Python versions older than 3.10 are rejected with a clear error.
- **Backward compatibility:** `modern/EsetLogParser.py` retains deprecated camelCase functions that delegate to the new implementation.
- **Standard library only:** no external runtime dependencies are required.
- **Tested behavior:** the modern test suites cover data types, positional NDF parsing, malformed input handling, complete parsing, CLI output, field ordering, and deprecated compatibility functions.

Run the modern tests with:

```console
python modern/eset_virlog_parser_test.py
python modern/eset_ndf_parser_test.py
```

The original `EsetLogParser.py` and `test.py` remain the Python 2.7-compatible implementation and test suite. Use the modern version for new development and integrations.

## TODO
- reversing all the fields in `virlog.dat` file
- turn this PoC into real parser
	- change fields extractor to fields parser
