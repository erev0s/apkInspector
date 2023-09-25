import zlib
import os

from .headers import headers_of_filename


def extract_file_based_on_header_info(apk_file, offset, header_info):
    """
    Extracts a single file from the apk_file based on the information provided from the offset and the header_info.
    It takes into account that the compression method provided might not be STORED or DEFLATED and in that case
    it treats it as STORED -> TODO: inspect other cases
    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param offset: The offset at which the local header for that file is.
    :param header_info: The local header dictionary info for that specific filename (parse_local_header)
    :return: Returns the actual extracted data for that file
    """
    filename_length = header_info["File name length"]
    extra_field_length = header_info["Extra field length"]
    compressed_size = header_info["Compressed size"]
    uncompressed_size = header_info["Uncompressed size"]
    compression_method = header_info["Compression method"]
    # Skip the offset + local header to reach the compressed data
    local_header_size = 30  # Size of the local header in bytes
    apk_file.seek(offset + local_header_size + filename_length + extra_field_length)
    if compression_method == 0:  # Stored (no compression)
        compressed_data = apk_file.read(compressed_size)
        extracted_data = compressed_data
    elif compression_method == 8:
        compressed_data = apk_file.read(compressed_size)
        # -15 for windows size due to raw stream with no header or trailer
        extracted_data = zlib.decompress(compressed_data, -15)
    else:
        # Any ZIP compression method other than STORED is treated as DEFLATED by Android.
        try:
            cur_loc = apk_file.tell()
            compressed_data = apk_file.read(compressed_size)
            extracted_data = zlib.decompress(compressed_data, -15)
        except:
            apk_file.seek(cur_loc)
            compressed_data = apk_file.read(uncompressed_size)
            extracted_data = compressed_data
    return extracted_data


def extract_all_files_from_central_directory(apk_file, central_directory_entries, output_dir):
    """
    Extracts all files from an APK based on the entries detected in the central_directory_entries.
    :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
    :param central_directory_entries: The dictionary with all the entries for the central directory (see parse_central_directory)
    :param output_dir: The output directory where to save the files.
    :return: Returns 0 if no errors, 1 if an exception and 2 if the output directory already exists
    """
    try:
        # Check if the output directory already exists
        if os.path.exists(output_dir):
            print("Extraction aborted. Output directory already exists.")
            return 2
        # Create the output directory or overwrite if it already exists
        os.makedirs(output_dir, exist_ok=True)
        # Iterate over central directory entries
        for filename, cd_header_info in central_directory_entries.items():
            # Get the local header offset from the central directory entry
            local_header_offset = cd_header_info["Relative offset of local file header"]
            # Retrieve the header information for the file
            _, header_info = headers_of_filename(apk_file, central_directory_entries, filename)
            # Extract the file using the local header information
            extracted_data = extract_file_based_on_header_info(apk_file, local_header_offset, header_info)
            # Construct the output file path
            output_path = os.path.join(output_dir, filename)
            # Create directories if necessary
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            # Write the extracted data to the output file
            with open(output_path, 'wb') as output_file:
                output_file.write(extracted_data)
        return 0
    except Exception as e:
        print(f"Error extracting files: {e}")
        return 1
