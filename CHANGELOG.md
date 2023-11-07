# Changelog

All notable changes to this project will be documented in this file.

## [1.1.4] - 07-11-2023
 - Support for AndroidManifest.xml cases when an empty Namespace, a Namespace without the XmlStartNamespace first or multiple Namespaces in different lines occur.
 - Handling for empty attribute names in AndroidManifest.xml. Rare cases when the public.xml is required to get the actual name.
 - Fixed bug with finding the starting bytes for XMLResourceMap

## [1.1.3] - 04-11-2023
 - Fixed a bug related to datatypes and how they were processed

## [1.1.2] - 29-10-2023
 - Extraction to use local header unless something is off
 - Added test case apk with tampered size and ExtraField
 - Indicators inconsistencies between local and central header
 - Restructure of the headers module

## [1.1.1] - 24-10-2023
 - Updated extraction process to use the CD header instead of the local one

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
