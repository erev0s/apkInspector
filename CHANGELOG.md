# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 23-10-2023
 - Restructure of manifestDecoder/axml module
 - added CData in the possible chunks
 - fix output format
 - added poc for dummy attributes in tampering indicators

## [1.0.4] - 11-10-2023
 - Added functionality to report back which static analysis evasion techniques were used
 - New flag in the CLI to use the added functionality of the library

## [1.0.3] - 08-10-2023
 - New method get_manifest() in manifestDecoder module for convenience when getting the decoded AndroidManifest from an apk or a file.
 - added flag in the cli to be able to pass an encoded AndroidManifest.xml file and decode it.
 - Slight corrections in docstrings and in versioning between cli and lib.

## [1.0.2] - 25-09-2023
 - Updated decoding in central and local header to ignore non decodable bytes
 - fixed a forgotten flag in the cli

## [1.0.1] - 25-09-2023
 - Updated version to 1.0.1 as PyPI was complaining

## [1.0.0] - 25-09-2023
 - initial version
