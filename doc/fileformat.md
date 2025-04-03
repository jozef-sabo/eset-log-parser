# FileFormats
All the file formats mentioned here, with the structure, can be found in respective `.ksy` file.

## virlog.dat

File keeps track of on access detection. Each record starts with header `\x24\x00\x00\x00\x01\x00\x01\x00` followed by 32-bit ID, 64-bit timestamp of detection (in Microsoft filetime format), unidentified 32-bit value, 32-bit ID and suffix `\x01\x00\x00\x00\x02\00\00\00`.

Most (all except timestamp) of identified fields in records begin with 32-bit header. It seems that all of this headers have common format `\x??\x??\x4?\x??`. String values are encoded as null-prefixed and null-terminated wide-char C-strings. Values with fixed length (hashes) are not null-terminated and they are stored as a hexadecimal raw sequence. Timestamp of first seen is stored as a UnixTimestamp (seconds from Epoch).

### Headers
- Record: `\x24\x00\x00\x00\x01\x00\x01\x00 + ID(32) + MSTimestamp(64) + unknown(32) + ID(32) + \x01\x00\x00\x00\x02\00\00\00`
- Malicious object: `\xbe\x0b\x4e\x00`
- Infiltration name: `\x4d\x1d\x4e\x00`
- Username: `\x4d\x1d\x4e\x00`
- VirusDB: `\x4d\x1d\x4e\x00`
- Program which accessed malicious object: `\x4d\x1d\x4e\x00`
- Hash of the above program: `\x4d\x1d\x4e\x00`
- Hash of the malicious object: `\x9e\x13\x42\x00`
- First seen timestamp: `\x9e\x13\x42\x00`

## .NDF file 

The file keeps infomration about the specific malicious file (defined by SHA1 hash).
Each file contains a header, which consists of magic `\x46\x51\x44\x46\xa4\x0f\x00\x00`, followed by number of threats found (threat is defined by a path), then a date in UNIX-like timestamp format, size of the malicious file, SHA1 hash and the threat entries themselves.

The threat has fixed order of values, most of them magic-header-less. Threat contains path to a file detected (all the strings are in UTF-16 little endian, not null terminated, defined just by size), size of data, different timestamps, local and canonized name of the infiltration and the path again.

## Other files
TODO
