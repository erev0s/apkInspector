![apkInspector](https://i.imgur.com/twtQzrO.png)
![PyPI - Version](https://img.shields.io/pypi/v/apkInspector)[![CI](https://github.com/erev0s/apkInspector/actions/workflows/ci.yml/badge.svg)](https://github.com/erev0s/apkInspector/actions/workflows/ci.yml)
# apkInspector
apkInspector is a tool designed to provide detailed insights into the central directory and local headers of APK files, offering the capability to extract content and decode the AndroidManifest.xml file. What sets APKInspector apart is its adherence to the zip specification during APK parsing, eliminating the need for reliance on external libraries. This independence, allows APKInspector to be highly adaptable, effectively emulating Android's installation process for APKs that cannot be parsed using standard libraries. The main goal is to enable users to conduct static analysis on APKs that employ evasion techniques, especially when conventional methods prove ineffective.

## CLI
apkInspector offers a command line tool with the same name, with the following options;

~~~~
$ apkInspector -h
usage: apkInspector [-h] [-apk APK] [-f FILENAME] [-ll] [-lc] [-la] [-e] [-x] [-xa] [-m] [-v]

APK Inspector

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
  -v, --version         Retrieves version information
~~~~


## Library
The library component of apkInspector is designed with extensibility in mind, allowing other tools to seamlessly integrate its functionality. This flexibility empowers developers to leverage the capabilities of apkInspector within their own applications and workflows. To facilitate clear comprehension and ease of use, comprehensive docstrings accompany all primary methods, providing valuable insights into their functionality, expected arguments, and return values. These detailed explanations serve as invaluable guides, ensuring that developers can quickly grasp the inner workings of apkInspector's core features and smoothly incorporate them into their projects.

The command-line interface (CLI) serves as a practical illustration of how the methods provided by the library have been employed.

## Planned todo
 - Return indicators of what was detected to be tampered.
 - Improve code coverage

## Disclaimer
It should be kept in mind that apkInspector is an evolving project, a work in progress. As such, users should anticipate occasional bugs and anticipate updates and upgrades as the tool continues to mature and enhance its functionality. Your feedback and contributions to apkInspector are highly appreciated as we work together to improve and refine its capabilities.

## How to Contribute

We welcome contributions from the open-source community to help improve and enhance apkInspector. Whether you're a developer, tester, or documentation enthusiast, your contributions are valuable. Here's how you can get started:

### Reporting Issues

If you encounter a bug, have a feature request, or have a suggestion for improvement, please open an issue on our [GitHub issue tracker](https://github.com/erev0s/apkInspector/issues). When reporting issues, please provide as much detail as possible, including:

- A clear and descriptive title
- A detailed description of the problem or enhancement request
- Steps to reproduce the issue (if applicable)
- Any relevant error messages or screenshots

### Pull Requests

If you'd like to contribute code or documentation changes, follow these steps:

1. Fork the repository on GitHub.
2. Create a new branch with a descriptive name for your feature or bug fix.
3. Make your changes and ensure that your code adheres to our coding standards.
4. Write tests to cover your changes (if applicable).
5. Commit your changes with clear and concise commit messages.
6. Push your branch to your fork on GitHub.
7. Create a pull request (PR) against the main repository's `main` branch.
8. Clearly describe your changes in the PR, including the problem you're addressing and how you've tested your changes.
9. Be prepared to address feedback and make necessary revisions to your PR.

### Code Style

Please adhere to our code style guidelines to maintain consistency within the project. We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code and provide configuration files for linters.


Thank you for considering contributing to apkInspector! Your contributions help make this project better for everyone.





