import struct

from .helpers import pretty_print_header, save_to_json


def find_eocd(apk_file):
    """
    Method to locate the "end of central directory record signature" as the first step of the correct process of
    reading a ZIP archive. Should be noted that certain APKs do not follow the zip specification and declare multiple
    "end of central directory records". For this reason the search for the corresponding signature of the eocd starts
    from the end of the apk.
    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :return: Returns the end of central directory record with all the information available if the corresponding
    signature is found. If not, then it returns None.
    """
    chunk_size = 1024
    offset = 0
    file_size = apk_file.seek(0, 2)
    while offset < file_size:
        position = file_size - offset - chunk_size
        if position < 0:
            position = 0
        apk_file.seek(position)
        chunk = apk_file.read(chunk_size)
        if not chunk:
            break
        signature_offset = chunk.rfind(b'\x50\x4b\x05\x06')  # end of Central Directory File Header signature
        if signature_offset != -1:
            eo_central_directory_offset = position + signature_offset
            break  # Found End of central directory record (EOCD) signature
        offset += chunk_size
    if signature_offset == -1:
        return None  # End of central directory record (EOCD) signature not found
    apk_file.seek(eo_central_directory_offset)
    eocd = {}
    signature = apk_file.read(4)
    eocd["Number of this disk"] = struct.unpack('<H', apk_file.read(2))[0]
    eocd["Disk where central directory starts"] = struct.unpack('<H', apk_file.read(2))[0]
    eocd["Number of central directory records on this disk"] = struct.unpack('<H', apk_file.read(2))[0]
    eocd["Total number of central directory records"] = struct.unpack('<H', apk_file.read(2))[0]
    eocd["Size of central directory (bytes)"] = struct.unpack('<I', apk_file.read(4))[0]
    eocd["Offset of start of central directory"] = struct.unpack('<I', apk_file.read(4))[0]
    eocd["Comment length"] = struct.unpack('<H', apk_file.read(2))[0]
    eocd["Comment"] = struct.unpack(f'<{eocd["Comment length"]}s', apk_file.read(eocd["Comment length"]))[0]

    return eocd


def parse_central_directory(apk_file, central_directory_offset):
    """
    Method that is used to parse the central directory header according to the specification
    https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT
    based on the offset provided by the end of central directory record: eocd["Offset of start of central directory"].
    If multiple central directory headers are discovered this will not be handled properly!

    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param central_directory_offset: The offset as read from the end of central
    directory record : eocd["Offset of start of central directory"]
    :return: Returns a dictionary with all the entries discovered. The filename of each entry is used as the key. Besides
    the fields defined by the specification, each entry has an additional field named 'Offset in the central directory header',
    which includes the offset of the entry in the central directory itself.
    """

    apk_file.seek(central_directory_offset)
    if apk_file.tell() != central_directory_offset:
        raise ValueError(f"Failed to find the offset for the central directory within the file!")

    central_directory_entries = {}
    while True:
        c_offset = apk_file.tell()
        signature = apk_file.read(4)
        if signature != b'\x50\x4b\x01\x02':
            break  # Reached the end of the central directory
        central_directory_entry = {"Version made by": struct.unpack('<H', apk_file.read(2))[0],
                                   "Version needed to extract (minimum)": struct.unpack('<H', apk_file.read(2))[0],
                                   "General purpose bit flag": struct.unpack('<H', apk_file.read(2))[0],
                                   "Compression method": struct.unpack('<H', apk_file.read(2))[0],
                                   "File last modification time": struct.unpack('<H', apk_file.read(2))[0],
                                   "File last modification date": struct.unpack('<H', apk_file.read(2))[0],
                                   "CRC-32 of uncompressed data": struct.unpack('<I', apk_file.read(4))[0],
                                   "Compressed size": struct.unpack('<I', apk_file.read(4))[0],
                                   "Uncompressed size": struct.unpack('<I', apk_file.read(4))[0],
                                   "File name length": struct.unpack('<H', apk_file.read(2))[0],
                                   "Extra field length": struct.unpack('<H', apk_file.read(2))[0],
                                   "File comment length": struct.unpack('<H', apk_file.read(2))[0],
                                   "Disk number where file starts": struct.unpack('<H', apk_file.read(2))[0],
                                   "Internal file attributes": struct.unpack('<H', apk_file.read(2))[0],
                                   "External file attributes": struct.unpack('<I', apk_file.read(4))[0],
                                   "Relative offset of local file header": struct.unpack('<I', apk_file.read(4))[0]}
        filename_length = central_directory_entry["File name length"]
        central_directory_entry["Filename"] = struct.unpack(f'<{filename_length}s', apk_file.read(filename_length))[
            0].decode('utf-8')
        extra_field_length = central_directory_entry["Extra field length"]
        central_directory_entry["Extra Field"] = \
            struct.unpack(f'<{extra_field_length}s', apk_file.read(extra_field_length))[0].decode('utf-8', 'ignore')
        file_comment_length = central_directory_entry["File comment length"]
        central_directory_entry["File comment"] = \
            struct.unpack(f'<{file_comment_length}s', apk_file.read(file_comment_length))[0].decode('utf-8', 'ignore')

        central_directory_entry["Offset in the central directory header"] = c_offset
        central_directory_entries[central_directory_entry["Filename"]] = central_directory_entry

    return central_directory_entries


def parse_local_header(apk_file, entry_of_interest):
    """
    Method that attempts to read the local file header according to the specification
    https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT

    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param entry_of_interest: The central directory header of the specific entry of interest
    :return: Returns a dictionary with the local header information or None if it failed to find the header.
    """
    apk_file.seek(entry_of_interest["Relative offset of local file header"])
    header_signature = apk_file.read(4)

    if not header_signature == b'\x50\x4b\x03\x04':
        print(f"Does not seem to be the start of a local header!")
        return None
    else:
        local_header_info = {"Version needed to extract (minimum)": struct.unpack('<H', apk_file.read(2))[0],
                             "General purpose bit flag": struct.unpack('<H', apk_file.read(2))[0],
                             "Compression method": struct.unpack('<H', apk_file.read(2))[0],
                             "File last modification time": struct.unpack('<H', apk_file.read(2))[0],
                             "File last modification date": struct.unpack('<H', apk_file.read(2))[0],
                             "CRC-32 of uncompressed data": struct.unpack('<I', apk_file.read(4))[0],
                             "Compressed size": struct.unpack('<I', apk_file.read(4))[0],
                             "Uncompressed size": struct.unpack('<I', apk_file.read(4))[0],
                             "File name length": struct.unpack('<H', apk_file.read(2))[0],
                             "Extra field length": struct.unpack('<H', apk_file.read(2))[0]}

        filename_length = local_header_info["File name length"]
        local_header_info["Filename"] = struct.unpack(f'<{filename_length}s', apk_file.read(filename_length))[0].decode(
            'utf-8')
        extra_field_length = local_header_info["Extra field length"]
        local_header_info["Extra Field"] = struct.unpack(f'<{extra_field_length}s', apk_file.read(extra_field_length))[
            0].decode('utf-8', 'ignore')

    return local_header_info


def headers_of_filename(apk_file, central_directory_entries, filename):
    """
    Provides both the central directory header and the local header of a specific filename
    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param central_directory_entries: The dictionary with all the entries for the central directory (see
    parse_central_directory)
    :param filename: The filename of the entry of interest
    :return: Returns two dictionaries with the central directory header and the local header of the specified filename.
    If the filename is not found within the central directory dictionary it returns None.
    """
    if filename in central_directory_entries:
        cd_h_of_file = central_directory_entries[filename]
        local_header_of_file = parse_local_header(apk_file, cd_h_of_file)
        return cd_h_of_file, local_header_of_file
    else:
        print(f"Filename: {filename} does not seem to exist within the central directory entries.")
        return None


def print_headers_of_filename(cd_h_of_file, local_header_of_file):
    """
    Prints out the details for both the central directory header and the local file header. Useful for the CLI
    :param cd_h_of_file: central directory header of a filename as it may be retrieved from headers_of_filename
    :param local_header_of_file: local header dictionary of a filename as it may be retrieved from headers_of_filename
    """
    pretty_print_header("CENTRAL DIRECTORY")
    for k in cd_h_of_file:
        if k == 'Relative offset of local file header' or k == 'Offset in the central directory header':
            print(f"{k:40} : {hex(int(cd_h_of_file[k]))} | {cd_h_of_file[k]}")
        else:
            print(f"{k:40} : {cd_h_of_file[k]}")
    pretty_print_header("LOCAL HEADER")
    for k in local_header_of_file:
        print(f"{k:40} : {local_header_of_file[k]}")


def show_and_save_info_of_central(central_directory_entries, apk_name, export: bool, show: bool):
    """
    Print information for each entry for the central directory header and allow to possibly export to JSON
    :param central_directory_entries: The dictionary with all the entries for the central directory (see parse_central_directory)
    :param apk_name: String with the name of the APK, so it can be used for the export.
    :param export: Boolean for exporting or not to JSON
    :param show: Boolean for printing or not the entries
    """
    if show:
        for entry in central_directory_entries:
            pretty_print_header(entry)
            print(central_directory_entries[entry])
    if export:
        save_to_json(f"{apk_name}_central_directory_header.json", central_directory_entries)


def get_and_save_local_headers_of_all(apk_file, central_directory_entries, apk_name=None, export: bool = None, show: bool = None):
    """
    Creates a dictionary of local headers based on the entries retrieved from the central directory header.
    Additionally, allows to print the local headers and export the dictionary to JSON
    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param central_directory_entries: The dictionary with all the entries for the central directory (see parse_central_directory)
    :param apk_name: String with the name of the APK, so it can be used for the export.
    :param export: Boolean for exporting or not to JSON. If exporting it will not print.
    :param show: Boolean for printing or not the entries
    :return: Returns the dictionary created with all the local headers, where the filename is the key.
    """
    local_headers = {}
    for entry in central_directory_entries:
        entry_local_header = parse_local_header(apk_file, central_directory_entries[entry])
        local_headers[entry_local_header['Filename']] = entry_local_header
        if show:
            pretty_print_header(entry_local_header['Filename'])
            print(entry_local_header)
    if export:
        save_to_json(f"{apk_name}_local_headers.json", local_headers)
    return local_headers
