import io
import os
import unittest
import hashlib


from apkInspector.extract import extract_file_based_on_header_info
from apkInspector.headers import find_eocd, parse_central_directory, parse_local_header, headers_of_filename
from apkInspector.indicators import zip_tampering_indicators, manifest_tampering_indicators, apk_tampering_check
from apkInspector.manifestDecoder import ResChunkHeader, StringPoolType, process_headers, create_manifest


class ApkInspectorTestCase(unittest.TestCase):
    def setUp(self):
        # Open the test APK files here and set them as instance variables
        test_dir = os.path.dirname(os.path.abspath(__file__))
        apk_path_orig = os.path.join(test_dir, 'res', 'minimal_orig.apk')
        apk_path_mod = os.path.join(test_dir, 'res', 'minimal_def_mod.apk')
        self.apk_orig = open(apk_path_orig, "rb")
        self.apk_mod = open(apk_path_mod, "rb")

    def tearDown(self):
        # Close the test APK files in the tearDown method
        self.apk_orig.close()
        self.apk_mod.close()

    def test_find_eocd(self):
        eocd_orig = find_eocd(self.apk_orig)
        eocd_mod = find_eocd(self.apk_mod)
        orig = {'Number of this disk': 0, 'Disk where central directory starts': 0, 'Number of central directory '
                                                                                    'records on this disk': 23,
                'Total number of central directory records': 23, 'Size of central directory (bytes)': 1317,
                'Offset of start of central directory': 151552, 'Comment length': 0, 'Comment': b''}
        mod = {'Number of this disk': 0, 'Disk where central directory starts': 0, 'Number of central directory '
                                                                                   'records on this disk': 24,
               'Total number of central directory records': 24, 'Size of central directory (bytes)': 1420,
               'Offset of start of central directory': 151552, 'Comment length': 0, 'Comment': b''}
        self.assertEqual(eocd_orig, orig)
        self.assertEqual(eocd_mod, mod)

    def test_parse_central_directory(self):
        offset = 151552
        hash_orig = 'def1d06fdc88668bea390e4715c8fa6e933e67da5c1f67e5536d01f1abb521d9'
        hash_mod = '5d631f7942352f1c4544bcabeb1bea812a67d0b472d292934f154f75c8e6f503'
        central_directory_entries_orig = parse_central_directory(self.apk_orig, offset)
        central_directory_entries_mod = parse_central_directory(self.apk_mod, offset)
        tocheck_orig = hashlib.sha256(str(central_directory_entries_orig).encode('utf-8')).hexdigest()
        tocheck_mod = hashlib.sha256(str(central_directory_entries_mod).encode('utf-8')).hexdigest()
        self.assertEqual(tocheck_orig, hash_orig)
        self.assertEqual(tocheck_mod, hash_mod)

    def test_parse_local_header(self):
        offset = 151552
        central_directory_entries_orig = parse_central_directory(self.apk_orig, offset)
        central_directory_entries_mod = parse_central_directory(self.apk_mod, offset)
        cd_h_of_file_orig = central_directory_entries_orig["AndroidManifest.xml"]
        cd_h_of_file_mod = central_directory_entries_mod["AndroidManifest.xml"]
        comp = {'Version needed to extract (minimum)': 20, 'General purpose bit flag': 0, 'Compression method': 0, 'File last modification time': 2081, 'File last modification date': 545, 'CRC-32 of uncompressed data': 998929674, 'Compressed size': 2084, 'Uncompressed size': 2084, 'File name length': 19, 'Extra field length': 3, 'Filename': 'AndroidManifest.xml', 'Extra Field': '\x00\x00\x00'}
        local_header_of_file_orig = parse_local_header(self.apk_orig, cd_h_of_file_orig)
        local_header_of_file_mod = parse_local_header(self.apk_orig, cd_h_of_file_mod)
        self.assertEqual(local_header_of_file_orig, comp)
        self.assertEqual(local_header_of_file_mod, comp)

    def test_extract_file_based_on_header_info(self):
        offset = 151552
        central_directory_entries_orig = parse_central_directory(self.apk_orig, offset)
        central_directory_entries_mod = parse_central_directory(self.apk_mod, offset)
        cd_h_of_file_orig = central_directory_entries_orig["AndroidManifest.xml"]
        cd_h_of_file_mod = central_directory_entries_mod["AndroidManifest.xml"]
        local_header_of_file_orig = parse_local_header(self.apk_orig, cd_h_of_file_orig)
        local_header_of_file_mod = parse_local_header(self.apk_mod, cd_h_of_file_mod)
        ext_hash_orig = '5f37db22380177c20804d8602ffbdc048caeaa851412ab127e6fe1c9a9b1c78e'
        ext_hash_mod = '5dc10a071f28ef25c6caa3cd3aef0d93985dacb1dba08ca46632ba655129e503'
        androidManifest_extracted_orig = extract_file_based_on_header_info(self.apk_orig, 0, local_header_of_file_orig)[0]
        androidManifest_extracted_mod = extract_file_based_on_header_info(self.apk_mod, 0, local_header_of_file_mod)[0]
        self.assertEqual(hashlib.sha256(androidManifest_extracted_orig).hexdigest(), ext_hash_orig)
        self.assertEqual(hashlib.sha256(androidManifest_extracted_mod).hexdigest(), ext_hash_mod)

    def test_android_manifest_decoding_orig(self):
        offset = 151552
        central_directory_entries_orig = parse_central_directory(self.apk_orig, offset)
        cd_h_of_file, local_header_of_file = headers_of_filename(self.apk_orig, central_directory_entries_orig,
                                                                 "AndroidManifest.xml")
        offset = cd_h_of_file["Relative offset of local file header"]
        extracted_data = io.BytesIO(extract_file_based_on_header_info(self.apk_orig, offset, local_header_of_file)[0])
        ResChunkHeader.from_file(extracted_data)
        string_pool = StringPoolType.from_file(extracted_data)
        string_data = string_pool.strdata
        elements = process_headers(extracted_data)[0]
        manifest = create_manifest(elements, string_data)
        manifest_orig = '4e5928e06a5bcaf3373fd5dc0ff1cd5686c465d80ebd7f6d8b2883d58f180bb7'
        self.assertEqual(hashlib.sha256(str(manifest).encode('utf-8')).hexdigest(), manifest_orig)

    def test_android_manifest_decoding_mod(self):
        offset = 151552
        central_directory_entries_mod = parse_central_directory(self.apk_mod, offset)
        cd_h_of_file, local_header_of_file = headers_of_filename(self.apk_mod, central_directory_entries_mod,
                                                                 "AndroidManifest.xml")
        offset = cd_h_of_file["Relative offset of local file header"]
        extracted_data = io.BytesIO(extract_file_based_on_header_info(self.apk_mod, offset, local_header_of_file)[0])
        ResChunkHeader.from_file(extracted_data)
        string_pool = StringPoolType.from_file(extracted_data)
        string_data = string_pool.strdata
        elements = process_headers(extracted_data)[0]
        manifest = create_manifest(elements, string_data)
        manifest_mod = '4e5928e06a5bcaf3373fd5dc0ff1cd5686c465d80ebd7f6d8b2883d58f180bb7'
        self.assertEqual(hashlib.sha256(str(manifest).encode('utf-8')).hexdigest(), manifest_mod)

    def test_tampering_indicators(self):
        orig_val = {'zip tampering': {}, 'manifest tampering': {}}
        mod_val = {'zip tampering': {'AndroidManifest.xml': {'central compression method': 30208, 'local compression method': 30208, 'actual compression method': 'STORED_TAMPERED'}}, 'manifest tampering': {'file_type': 0, 'string_pool': {'string count': 49, 'real string count': 32}}}
        orig = apk_tampering_check(self.apk_orig)
        mod = apk_tampering_check(self.apk_mod)
        print(mod)
        print(orig)
        self.assertEqual(orig, orig_val)
        self.assertEqual(mod, mod_val)


if __name__ == '__main__':
    unittest.main()
