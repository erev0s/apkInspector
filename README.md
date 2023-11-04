![apkInspector](https://i.imgur.com/hTzyIDG.png) 
![PyPI - Version](https://img.shields.io/pypi/v/apkInspector)[![CI](https://github.com/erev0s/apkInspector/actions/workflows/ci.yml/badge.svg)](https://github.com/erev0s/apkInspector/actions/workflows/ci.yml)
# apkInspector
apkInspector is a tool designed to provide detailed insights into the zip structure of APK files, offering the capability to extract content and decode the AndroidManifest.xml file. What sets APKInspector apart is its adherence to the zip specification during APK parsing, eliminating the need for reliance on external libraries. This independence, allows APKInspector to be highly adaptable, effectively emulating Android's installation process for APKs that cannot be parsed using standard libraries. The main goal is to enable users to conduct static analysis on APKs that employ evasion techniques, especially when conventional methods prove ineffective.

## How to install
[apkInspector is available through PyPI](https://pypi.org/project/apkInspector/)
~~~~
pip install apkInspector
~~~~

or you can clone this repository and build and install locally:
~~~~
git clone https://github.com/erev0s/apkInspector.git
cd apkInspector
poetry build
pip install dist/apkInspector-Version_here.tar.gz
~~~~

## CLI
apkInspector offers a command line tool with the same name, with the following options;

~~~~
$ apkInspector -h
usage: apkInspector [-h] [-apk APK] [-f FILENAME] [-ll] [-lc] [-la] [-e] [-x] [-xa] [-m] [-sm SPECIFY_MANIFEST] [-a] [-v]

apkInspector is a tool designed to provide detailed insights into the zip structure of APK files, offering the capability to extract
content and decode the AndroidManifest.xml file.

options:
  -h, --help            show this help message and exit
  -apk APK              APK to inspect
  -f FILENAME, --filename FILENAME
                        Filename to provide info for
  -ll, --list-local     List all files by name from local headers
  -lc, --list-central   List all files by name from central directory header
  -la, --list-all       List all files from both central directory and local headers
  -e, --export          Export to JSON. What you list from the other flags, will be exported
  -x, --extract         Attempt to extract the file specified by the -f flag
  -xa, --extract-all    Attempt to extract all files detected in the central directory header
  -m, --manifest        Extract and decode the AndroidManifest.xml
  -sm SPECIFY_MANIFEST, --specify-manifest SPECIFY_MANIFEST
                        Pass an encoded AndroidManifest.xml file to be decoded
  -a, --analyze         Check an APK for static analysis evasion techniques
  -v, --version         Retrieves version information
~~~~


## Library
The library component of apkInspector is designed with extensibility in mind, allowing other tools to seamlessly integrate its functionality. This flexibility empowers developers to leverage the capabilities of apkInspector within their own applications and workflows. To facilitate clear comprehension and ease of use, comprehensive docstrings accompany all primary methods, providing valuable insights into their functionality, expected arguments, and return values. These detailed explanations serve as invaluable guides, ensuring that developers can quickly grasp the inner workings of apkInspector's core features and smoothly incorporate them into their projects.

### Features offered
 - Find end of central directory record
 - Parse central directory of APK and get details about each entry
 - Get details local header for each entry
 - Extract single or all files within an APK
 - Decode AndroidManifest.xml file
 - Identify Tampering Indicators:
   - End of Central Directory record defined multiple times
   - Unknown compression methods
   - Unexpected starting signature of AndroidManifest.xml
   - Tampered StringCount value
   - Dummy attributes for elements
   - Dummy data between elements


The command-line interface (CLI) serves as a practical illustration of how the methods provided by the library have been employed.

## Planned todo
 - Proper documentation
 - Improve code coverage

## Disclaimer
It should be kept in mind that apkInspector is an evolving project, a work in progress. As such, users should anticipate occasional bugs and anticipate updates and upgrades as the tool continues to mature and enhance its functionality. Your feedback and contributions to apkInspector are highly appreciated as we work together to improve and refine its capabilities.

## Contributions
We welcome contributions from the open-source community to help improve and enhance apkInspector. Whether you're a developer, tester, or documentation enthusiast, your contributions are valuable.





