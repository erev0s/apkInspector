import argparse
import io
import os

from apkInspector import __version__ as lib_version
from . import __version__ as cli_version
from apkInspector.extract import extract_file_based_on_header_info, extract_all_files_from_central_directory
from apkInspector.headers import find_eocd, parse_central_directory, headers_of_filename, print_headers_of_filename, \
    get_and_save_local_headers_of_all, show_and_save_info_of_central
from apkInspector.helpers import save_data_to_file
from apkInspector.manifestDecoder import ResChunkHeader, StringPoolType, process_headers, get_manifest


def main():
    parser = argparse.ArgumentParser(description='apkInspector is a tool designed to provide detailed insights into '
                                                 'the central directory and local headers of APK files, offering the '
                                                 'capability to extract content and decode the AndroidManifest.xml '
                                                 'file.')
    parser.add_argument('-apk', help='APK to inspect')
    parser.add_argument('-f', '--filename', help='Filename to provide info for')
    parser.add_argument('-ll', '--list-local', action='store_true', help='List all files by name from local headers')
    parser.add_argument('-lc', '--list-central', action='store_true', help='List all files by name from central '
                                                                           'directory header')
    parser.add_argument('-la', '--list-all', action='store_true',
                        help='List all files from both central directory and local headers')
    parser.add_argument('-e', '--export', action='store_true',
                        help='Export to JSON. What you list from the other flags, will be exported')
    parser.add_argument('-x', '--extract', action='store_true', help='Attempt to extract the file specified by the -f '
                                                                     'flag')
    parser.add_argument('-xa', '--extract-all', action='store_true', help='Attempt to extract all files detected in '
                                                                          'the central directory header')
    parser.add_argument('-m', '--manifest', action='store_true',
                        help='Extract and decode the AndroidManifest.xml')
    parser.add_argument('-v', '--version', action='store_true', help='Retrieves version information')
    args = parser.parse_args()

    if args.version:
        mm = """
#                 _     _____                                 _                
#                | |   |_   _|                               | |               
#    __ _  _ __  | | __  | |   _ __   ___  _ __    ___   ___ | |_   ___   _ __ 
#   / _` || '_ \ | |/ /  | |  | '_ \ / __|| '_ \  / _ \ / __|| __| / _ \ | '__|
#  | (_| || |_) ||   <  _| |_ | | | |\__ \| |_) ||  __/| (__ | |_ | (_) || |   
#   \__,_|| .__/ |_|\_\ \___/ |_| |_||___/| .__/  \___| \___| \__| \___/ |_|   
#         | |                             | |                                  
#         |_|                             |_|                                  
"""
        print(mm)
        print(f"apkInspector CLI Version: {cli_version}")
        print(f"apkInspector Library Version: {lib_version}")
        print(f"Copyright 2023 erev0s <projects@erev0s.com>\n")
        return
    print(f"apkInspector CLI Version: {cli_version}")
    print(f"apkInspector Library Version: {lib_version}")
    print(f"Copyright 2023 erev0s <projects@erev0s.com>\n")
    if args.apk is None:
        print("APK file is required")
        return
    apk_name = os.path.splitext(args.apk)[0]
    with open(args.apk, 'rb') as apk_file:
        eocd = find_eocd(apk_file)
        if eocd is None:
            print("Are you sure you are trying to parse an APK file?")
            return
        central_directory_entries = parse_central_directory(apk_file, eocd["Offset of start of central directory"])

        if args.filename and args.extract:
            try:
                cd_h_of_file, local_header_of_file = headers_of_filename(apk_file, central_directory_entries, args.filename)
            except TypeError as e:
                print(f"Are you sure the filename: {args.filename} exists?")
                exit()
            offset = cd_h_of_file["Relative offset of local file header"]
            print_headers_of_filename(cd_h_of_file, local_header_of_file)
            extracted_data = extract_file_based_on_header_info(apk_file, offset, local_header_of_file)
            save_data_to_file(f"EXTRACTED_{args.filename}", extracted_data)
        elif args.filename:
            try:
                cd_h_of_file, local_header_of_file = headers_of_filename(apk_file, central_directory_entries, args.filename)
            except TypeError as e:
                print(f"Are you sure the filename: {args.filename} exists?")
                exit()
            print_headers_of_filename(cd_h_of_file, local_header_of_file)
        elif args.extract_all:
            print(f"Number of entries: {len(central_directory_entries)}")
            if not extract_all_files_from_central_directory(apk_file, central_directory_entries, apk_name):
                print(f"Extraction successful for: {apk_name}")
        elif args.list_local:
            get_and_save_local_headers_of_all(apk_file, central_directory_entries, apk_name, args.export)
            print(f"Local headers list complete. Export: {args.export}")
        elif args.list_central:
            show_and_save_info_of_central(central_directory_entries, apk_name, args.export)
            print(f"Central header list complete. Export: {args.export}")
        elif args.list_all:
            show_and_save_info_of_central(central_directory_entries, apk_name, args.export)
            get_and_save_local_headers_of_all(apk_file, central_directory_entries, apk_name, args.export)
            print(f"Central and local headers list complete. Export: {args.export}")
        elif args.manifest:
            cd_h_of_file, local_header_of_file = headers_of_filename(apk_file, central_directory_entries,
                                                                     "AndroidManifest.xml")
            offset = cd_h_of_file["Relative offset of local file header"]
            extracted_data = io.BytesIO(extract_file_based_on_header_info(apk_file, offset, local_header_of_file))
            ResChunkHeader.from_file(extracted_data)
            string_pool = StringPoolType.from_file(extracted_data)
            string_data = string_pool.strdata
            elements = process_headers(extracted_data)
            manifest = get_manifest(elements, string_data)
            with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
                xml_file.write(manifest)
            print("AndroidManifest was saved as: decoded_AndroidManifest.xml")
        else:
            parser.print_help()


if __name__ == '__main__':
    main()
