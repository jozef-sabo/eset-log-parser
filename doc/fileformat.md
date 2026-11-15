# FileFormats
All the file formats mentioned here, with the structure, can be found in respective `.ksy` files in original repo under https://github.com/jozef-sabo/eset-log-parser/tree/feature-new-parsers-kaitai.

## virlog.dat

File keeps track of on access detection. Each record starts with header `\x24\x00\x00\x00\x01\x00\x01\x00` followed by 32-bit ID, 64-bit timestamp of detection (in Microsoft filetime format), unidentified 32-bit value, 32-bit ID and suffix `\x01\x00\x00\x00\x02\00\00\00`.

Most (all except timestamp) of identified fields in records begin with 32-bit header. It seems that all of this headers have common format `\x??\x??\x4?\x??`. String values are encoded as null-prefixed and null-terminated wide-char C-strings. Values with fixed length (hashes) are not null-terminated and they are stored as a hexadecimal raw sequence. Timestamp of first seen is stored as a UnixTimestamp (seconds from Epoch).

### Headers
This section lists all the known headers

#### General Headers 
- Record: `\x24\x00\x00\x00\x01\x00\x01\x00 + ID(32) + MSTimestamp(64) + unknown(32) + ID(32)`
- Subrecords: `\x01\x00\x00\x00\x02\00\00\00 + SubrecordLength(32)`
- Malicious object: `\xbe\x0b\x4e\x00`
- Infiltration name: `\x4d\x1d\x4e\x00`
- Username: `\xee\x03\x4e\x00`
- VirusDB: `\x17\x27\x4e\x00`
- Program which accessed malicious object: `\xc4\x0b\x4e\x00`
- Program path which accessed malicious object: `\xa7\x13\x4e\x00`
- Program path which accessed malicious object 2: `\xa9\x13\x4e\x00`
- Hash of the above program: `\x9d\x13\x42\x00`
- Hash of the malicious object: `\x9e\x13\x42\x00`
- Hash of the malicious object2: `\xae\x13\x42\x00`
- Hash of the malicious object3: `\xa4\x13\x42\x00`
- First seen timestamp: `\x9f\x13\x46\x00`
- Website which downloaded the file: `\x92\x27\x4d\x00`

#### Windows Headers
*named as in [VERSIONIFO](https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource).*

- Product name: `\x8e\x27\x4e\x00`
- Product name 2: `\x8b\x27\x4e\x00`
- Product name 3: `\x89\x27\x4e\x00`
- Company name: `\x88\x27\x4e\x00`
- Product version: `\x8f\x27\x4e\x00`
- File version: `\x8a\x27\x4e\x00`
- Legal copyright: `\x8c\x27\x4e\x00`
- Legal executable name: `\x8d\x27\x4e\x00`
- Language ID: `\x87\x27\x45\x00`
- Execution mode: `\x59\x1b\x4e\x00`
- User SID: `\xf5\x03\x4e\x00`
- Signing certificate: `\xb4\x13\x4e\x00`
- Signing certificate public key fingerprint: `\xb3\x13\x42\x00`
- Signing certificate public key parameters: `\xb2\x13\x45\x00`


### Format
The file consists of multiple parts.
Each file starts with magic `\x78\xf3\x9b\xcf`, then contains 32-bit HeaderLength following by Header of length `HeaderLength - 0x08` (in bytes).
After the header, there are records of threats.

#### Header
Header of a file contains
- Number of threats (32-bit)
- Size of the file (64-bit)
- Windows timestamp
- Windows timestamp 2
- Windows timestamp 3
- Number of threats (32-bit) - again, should be equal to first occurrence
- Unknown bytes


#### Threat
Each threat consists of multiple parts
- Magic header: `\xdc\xcf\x8b\x63`
- Length of a record (32-bit): `RecordLength(32)`
- Record of size `RecordLength - 0x08` (in bytes)

#### Record of threat
Each record of threat consists of multiple parts
- Magic header: `\x24\x00\x00\x00\x01\x00\x01\x00` 
- ID of the record (32-bit)
- Windows Timestamp of detection (64-bit) 
- Unknown 32-bit value
- ID of the record (32-bit) - again, should be equal to first occurrence
- Multiple subrecords

#### Subrecords
Each record of threat consists of multiple parts
- Magic header: `\x01\x00\x00\x00\x02\00\00\00`
- Length of a subrecord (32-bit)
- Subsubrecords containing known or unknown parameters described in [Headers](#headers) section


## Other files
TODO
