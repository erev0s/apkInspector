import argparse
import io
import os

from apkInspector import __version__ as version
from apkInspector.extract import extract_file_based_on_header_info, extract_all_files_from_central_directory
from apkInspector.headers import print_headers_of_filename, ZipEntry, show_and_save_info_of_headers
from apkInspector.helpers import save_data_to_file, pretty_print_header
from apkInspector.indicators import apk_tampering_check
from apkInspector.axml import get_manifest


def print_nested_dict(dictionary, parent_key=''):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print_nested_dict(value, parent_key=f"{parent_key}")
        else:
            full_key = f"{parent_key}->{key}" if parent_key else key
            print(f"{full_key}: {value}")


def get_apk_files(path):
    # If the path is a single file, return it as a list if it's an APK
    if os.path.isfile(path) and path.endswith('.apk'):
        return [path]

    # If the path is a directory, return a list of all APK files in it
    elif os.path.isdir(path):
        return [os.path.join(path, f) for f in os.listdir(path) if
                f.endswith('.apk') and os.path.isfile(os.path.join(path, f))]

    # If the path is invalid or not an APK file, return an empty list
    return []

help_text = {
    'en': {
        'description': 'apkInspector is a tool designed to provide detailed insights into ' +
                        'the zip structure of APK files, offering the ' +
                        'capability to extract content and decode the AndroidManifest.xml ' +
                        'file.',
        'apk_help': 'APK to inspect',
        'f_help': 'Filename to provide info for',
        'll_help': 'List all files by name from local headers',
        'lc_help': 'List all files by name from central ' + 'directory header',
        'la_help': 'List all files from both central directory and local headers',
        'e_help': 'Export to JSON. What you list from the other flags, will be exported',
        'x_help': 'Attempt to extract the file specified by the -f ' + 'flag',
        'xa_help': 'Attempt to extract all files detected in ' + 'the central directory header',
        'm_help': 'Extract and decode the AndroidManifest.xml',
        'sm_help': 'Pass an encoded AndroidManifest.xml file to be decoded',
        'a_help': 'Check an APK for static analysis evasion techniques',
        'v_help': 'Retrieves version information',
        'l_help': 'Set language',
    },
    'zh': {
        'description': 'apkInspector 是一款专注于深度解析 APK 文件 ZIP 结构的工具，能够提取文件内容并反编译 AndroidManifest.xml 文件。',
        'apk_help': '指定 APK 文件路径',
        'f_help': '指定需要获取信息的文件名',
        'll_help': '从本地文件头（Local File Header）中按文件名列出所有文件',
        'lc_help': '从中央目录索引头（Central Directory header）中按文件名列出所有文件',
        'la_help': '同时列出中央目录索引头和本地文件头中的所有文件',
        'e_help': '导出为 JSON 格式（其他参数显示的内容将被导出）',
        'x_help': '尝试提取 -f 参数指定的文件',
        'xa_help': '尝试提取中央目录索引头中检测到的所有文件',
        'm_help': '提取并解码 AndroidManifest.xml 文件',
        'sm_help': '直接传入已编码的 AndroidManifest.xml 文件进行解码',
        'a_help': '检查 APK 是否使用了静态分析规避技术',
        'v_help': '获取版本信息',
        'l_help': '设置语言',
    },
}

hint_text = {
    'en': {
        'error_no_apk': 'APK file or AndroidManifest.xml file is required',
        'error_apk_args': 'Please specify an apk file with flag "-apk" or an AndroidManifest.xml file with flag "-sm", but not both.',
        'error_no_apk_files': 'No APK files found at:',
        'info_results': 'Results for',
        'error_no_file': 'is not among the entries of the central directory!',
        'info_number_entries': 'Number of entries:',
        'info_extraction': 'Extraction successful for:',
        'list_local': 'Local headers list complete. Export:',
        'list_central': 'Central header list complete. Export:',
        'list_all': 'Central and local headers list complete. Export:',
        'save_manifest': 'AndroidManifest was saved as: decoded_AndroidManifest.xml',
        'zip_temper': 'The zip structure was tampered with using the following patterns:',
        'no_files': 'No files were detected were a tampering in the zip structure was present.',
        'manifest_temper': 'The AndroidManifest.xml file was tampered using the following patterns:',
        'no_manifest_temper': 'The AndroidManifest.xml file does not seem to be tampered structurally.'
    },
    'zh': {
        'error_no_apk': '请提供 APK 或 AndroidManifest.xml 文件',
        'error_apk_args': '请使用 "-apk" 指定 APK 文件或使用 "-sm" 指定 AndroidManifest.xml 文件（二者不可同时使用）',
        'error_no_apk_files': '在以下路径未找到 APK 文件：',
        'info_results': '检测结果：',
        'error_no_file': '未在中央目录条目中找到该文件：',
        'info_number_entries': '目录条目数量：',
        'info_extraction': '成功提取以下文件：',
        'list_local': '本地头列表完整。导出结果：',
        'list_central': '中央头列表完整。导出结果：',
        'list_all': '中央和本地头列表完整。导出结果：',
        'save_manifest': 'AndroidManifest 已保存为：decoded_AndroidManifest.xml',
        'zip_temper': '检测到 ZIP 结构被以下模式篡改：',
        'no_files': '未检测到存在 ZIP 结构篡改的文件。',
        'manifest_temper': 'AndroidManifest.xml 文件被以下模式篡改：',
        'no_manifest_temper': 'AndroidManifest.xml 文件在结构上似乎未被篡改。'
    }
}

def main():
    # Parse language parameters first (parse once in advance)
    # 先解析语言参数（提前解析一次）
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--lang', default='en', choices=['en', 'zh'])
    args, _ = pre_parser.parse_known_args()
    lang = args.lang

    parser = argparse.ArgumentParser(description=help_text[lang]['description'])
    parser.add_argument('-apk', help=help_text[lang]['apk_help'])
    parser.add_argument('-f', '--filename', help=help_text[lang]['f_help'])
    parser.add_argument('-ll', '--list-local', action='store_true', help=help_text[lang]['ll_help'])
    parser.add_argument('-lc', '--list-central', action='store_true', help=help_text[lang]['lc_help'])
    parser.add_argument('-la', '--list-all', action='store_true', help=help_text[lang]['la_help'])
    parser.add_argument('-e', '--export', action='store_true', help=help_text[lang]['e_help'])
    parser.add_argument('-x', '--extract', action='store_true', help=help_text[lang]['x_help'])
    parser.add_argument('-xa', '--extract-all', action='store_true', help=help_text[lang]['xa_help'])
    parser.add_argument('-m', '--manifest', action='store_true', help=help_text[lang]['m_help'])
    parser.add_argument('-sm', '--specify-manifest', help=help_text[lang]['sm_help'])
    parser.add_argument('-a', '--analyze', action='store_true', help=help_text[lang]['a_help'])
    parser.add_argument('-v', '--version', action='store_true', help=help_text[lang]['v_help'])
    parser.add_argument('-l', '--lang', help=help_text[lang]['l_help'])
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
        print(f"apkInspector Library Version: {version}")
        print(f"Copyright 2024 erev0s <projects@erev0s.com>\n")
        return
    print(f"apkInspector Version: {version}")
    print(f"Copyright 2024 erev0s <projects@erev0s.com>\n")
    if args.apk is None and args.specify_manifest is None:
        parser.error(hint_text[lang]['error_no_apk'])
    if not (args.specify_manifest is None) != (args.apk is None):
        parser.error(hint_text[lang]['error_apk_args'])
    if args.apk:
        apk_files = get_apk_files(args.apk)
        if not apk_files:
            print(f"{hint_text[lang]['error_no_apk_files']} {args.apk}")
            return
        for apk in apk_files:
            pretty_print_header(f"{hint_text[lang]['info_results']} {apk}:")
            apk_name = os.path.splitext(apk)[0]
            with open(apk, 'rb') as apk_file:
                zipentry = ZipEntry.parse(apk_file)
                if args.filename and args.extract:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict(args.filename)
                    if cd_h_of_file is None:
                        print(f"It appears that file: {args.filename} {hint_text[lang]['error_no_file']}")
                        return
                    local_header_of_file = zipentry.get_local_header_dict(args.filename)
                    print_headers_of_filename(cd_h_of_file, local_header_of_file)
                    extracted_data = extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0]
                    save_data_to_file(f"EXTRACTED_{args.filename}", extracted_data)
                elif args.filename:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict(args.filename)
                    if cd_h_of_file is None:
                        print(f"It appears that file: {args.filename} {hint_text[lang]['error_no_file']}")
                        return
                    local_header_of_file = zipentry.get_local_header_dict(args.filename)
                    print_headers_of_filename(cd_h_of_file, local_header_of_file)
                elif args.extract_all:
                    print(f"{hint_text[lang]['info_number_entries']} {len(zipentry.central_directory.entries)}")
                    if not extract_all_files_from_central_directory(apk_file, zipentry.to_dict()["central_directory"], zipentry.to_dict()["local_headers"], apk_name):
                        print(f"{hint_text[lang]['info_extraction']} {apk_name}")
                elif args.list_local:
                    show_and_save_info_of_headers(zipentry.to_dict()["local_headers"], apk_name, "local", args.export, True)
                    print(f"{hint_text[lang]['list_local']} {args.export}")
                elif args.list_central:
                    show_and_save_info_of_headers(zipentry.to_dict()["central_directory"], apk_name, "central", args.export, True)
                    print(f"{hint_text[lang]['list_central']} {args.export}")
                elif args.list_all:
                    show_and_save_info_of_headers(zipentry.to_dict()["central_directory"], apk_name, "local", args.export, True)
                    show_and_save_info_of_headers(zipentry.to_dict()["local_headers"], apk_name, "local", args.export, True)
                    print(f"{hint_text[lang]['list_all']} {args.export}")
                elif args.manifest:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
                    local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
                    extracted_data = io.BytesIO(
                        extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0])
                    manifest = get_manifest(extracted_data)
                    with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
                        xml_file.write(manifest)
                    print(f"{hint_text[lang]['save_manifest']}")
                elif args.analyze:
                    tamperings = apk_tampering_check(zipentry.zip, False)
                    if tamperings['zip tampering']:
                        print(f"\n{hint_text[lang]['zip_temper']}\n")
                        print_nested_dict(tamperings['zip tampering'])
                    else:
                        print(f"{hint_text[lang]['no_files']}")
                    if tamperings['manifest tampering']:
                        print(f"\n\n{hint_text[lang]['manifest_temper']}\n")
                        print_nested_dict(tamperings['manifest tampering'])
                    else:
                        print(f"{hint_text[lang]['no_manifest_temper']}")
                else:
                    parser.print_help()
    elif args.specify_manifest:
        with open(args.specify_manifest, 'rb') as enc_manifest:
            manifest = get_manifest(io.BytesIO(enc_manifest.read()))
            with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
                xml_file.write(manifest)
            print("{hint_text[lang]['save_manifest']}")


if __name__ == '__main__':
    main()
