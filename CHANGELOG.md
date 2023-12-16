# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 16-12-2023
 - Improved axml to detect dummy data in between attributes
 - Updated documentation

## [1.1.9] - 16-12-2023
 - Ignore bytes that can't be decoded also for comments
 - Adjust dummy attributes detection to be within range of string pool

## [1.1.8] - 09-12-2023
 - Multiple updates on the documentation https://erev0s.github.io/apkInspector/
 - Returning KeyError instead of None, when an entry is not there for local headers or central directory
 - Added more tests for better test coverage
 - Added tests.yml to have a check for the tests for any new PR

## [1.1.7] - 18-11-2023
 - Added certain method for the ZipEntry class for convenience
 - Improved axml bypassing dummy values in between elements

## [1.1.6] - 11-11-2023
 - Added test for top apps from Play Store
 - Added random integer for unknown attributes

## [1.1.5] - 11-11-2023
 - Added method in axml module to be able to directly pass the apk path.
 - Added method in extract module to be able to directly pass the apk path.

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
