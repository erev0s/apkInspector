import io
import os
import unittest
import hashlib

from apkInspector.extract import extract_file_based_on_header_info
from apkInspector.headers import EndOfCentralDirectoryRecord, CentralDirectory, ZipEntry, LocalHeaderRecord
from apkInspector.indicators import apk_tampering_check
from apkInspector.axml import get_manifest


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
        eocd_orig = EndOfCentralDirectoryRecord.parse(self.apk_orig).to_dict()
        eocd_mod = EndOfCentralDirectoryRecord.parse(self.apk_mod).to_dict()
        orig = {'signature': b'PK\x05\x06', 'number_of_this_disk': 0, 'disk_where_central_directory_starts': 0,
                'number_of_central_directory_records_on_this_disk': 23, 'total_number_of_central_directory_records': 23,
                'size_of_central_directory': 1317, 'offset_of_start_of_central_directory': 151552, 'comment_length': 0,
                'comment': ''}
        mod = {'signature': b'PK\x05\x06', 'number_of_this_disk': 0, 'disk_where_central_directory_starts': 0,
               'number_of_central_directory_records_on_this_disk': 24, 'total_number_of_central_directory_records': 24,
               'size_of_central_directory': 1420, 'offset_of_start_of_central_directory': 151552, 'comment_length': 0,
               'comment': ''}
        self.assertEqual(eocd_orig, orig)
        self.assertEqual(eocd_mod, mod)

    def test_eocd_from_dict(self):
        mod = {'signature': b'PK\x05\x06', 'number_of_this_disk': 0, 'disk_where_central_directory_starts': 0,
               'number_of_central_directory_records_on_this_disk': 24, 'total_number_of_central_directory_records': 24,
               'size_of_central_directory': 1420, 'offset_of_start_of_central_directory': 151552, 'comment_length': 0,
               'comment': ''}
        eocd_instance = EndOfCentralDirectoryRecord.from_dict(mod)
        self.assertEqual(eocd_instance.size_of_central_directory, 1420)
        self.assertEqual(eocd_instance.offset_of_start_of_central_directory, 151552)
        self.assertEqual(eocd_instance.total_number_of_central_directory_records, 24)

    def test_parse_central_directory(self):
        hash_orig = 'ae178cbf4ccf180d39740060ab3bfbdfbbd8754c8a154f46d67a8ff7966a6d70'
        hash_mod = '7e6c1667c1231f5b5c667be7220775cf7a3c05746aee6e392db1f696c4ce8eea'
        central_directory_entries_orig = CentralDirectory.parse(self.apk_orig).to_dict()
        central_directory_entries_mod = CentralDirectory.parse(self.apk_mod).to_dict()
        tocheck_orig = hashlib.sha256(str(central_directory_entries_orig).encode('utf-8')).hexdigest()
        tocheck_mod = hashlib.sha256(str(central_directory_entries_mod).encode('utf-8')).hexdigest()
        self.assertEqual(tocheck_orig, hash_orig)
        self.assertEqual(tocheck_mod, hash_mod)

    def test_central_directory_from_dict(self):
        cd_orig_dict = {'AndroidManifest.xml': {'version_made_by': 788, 'version_needed_to_extract': 20,
                                                'general_purpose_bit_flag': 0, 'compression_method': 0,
                                                'file_last_modification_time': 2081, 'file_last_modification_date': 545,
                                                'crc32_of_uncompressed_data': 998929674, 'compressed_size': 2084,
                                                'uncompressed_size': 2084, 'file_name_length': 19,
                                                'extra_field_length': 0, 'file_comment_length': 0,
                                                'disk_number_where_file_starts': 0, 'internal_file_attributes': 0,
                                                'external_file_attributes': 2176057344,
                                                'relative_offset_of_local_file_header': 0,
                                                'filename': 'AndroidManifest.xml', 'extra_field': '',
                                                'file_comment': '', 'offset_in_central_directory': 151552},
                        'classes.dex': {'version_made_by': 788, 'version_needed_to_extract': 20,
                                        'general_purpose_bit_flag': 0, 'compression_method': 8,
                                        'file_last_modification_time': 2081, 'file_last_modification_date': 545,
                                        'crc32_of_uncompressed_data': 1432748217, 'compressed_size': 616,
                                        'uncompressed_size': 1032, 'file_name_length': 11, 'extra_field_length': 0,
                                        'file_comment_length': 0, 'disk_number_where_file_starts': 0,
                                        'internal_file_attributes': 0, 'external_file_attributes': 2175008768,
                                        'relative_offset_of_local_file_header': 2136, 'filename': 'classes.dex',
                                        'extra_field': '', 'file_comment': '', 'offset_in_central_directory': 151617}}
        cd_dir_instance = CentralDirectory.from_dict(cd_orig_dict)
        self.assertEqual(cd_dir_instance.entries['AndroidManifest.xml'].to_dict()['file_last_modification_time'], 2081)

    def test_parse_local_header(self):
        ze_orig = ZipEntry.parse_single(self.apk_orig, "AndroidManifest.xml")
        ze_mod = ZipEntry.parse_single(self.apk_mod, "AndroidManifest.xml")
        comp_orig = {'version_needed_to_extract': 20, 'general_purpose_bit_flag': 0, 'compression_method': 0,
                     'file_last_modification_time': 2081, 'file_last_modification_date': 545,
                     'crc32_of_uncompressed_data': 998929674, 'compressed_size': 2084, 'uncompressed_size': 2084,
                     'file_name_length': 19, 'extra_field_length': 3, 'filename': 'AndroidManifest.xml',
                     'extra_field': '\x00\x00\x00'}
        comp_mod = {'version_needed_to_extract': 20, 'general_purpose_bit_flag': 0, 'compression_method': 30208,
                    'file_last_modification_time': 45686, 'file_last_modification_date': 22321,
                    'crc32_of_uncompressed_data': 2768741858, 'compressed_size': 2084, 'uncompressed_size': 2084,
                    'file_name_length': 19, 'extra_field_length': 0, 'filename': 'AndroidManifest.xml',
                    'extra_field': ''}
        self.assertEqual(ze_orig.local_headers["AndroidManifest.xml"].to_dict(), comp_orig)
        self.assertEqual(ze_mod.local_headers["AndroidManifest.xml"].to_dict(), comp_mod)

    def test_local_header_from_dict(self):
        andro_local_dict = {'version_needed_to_extract': 20, 'general_purpose_bit_flag': 0, 'compression_method': 30208,
                            'file_last_modification_time': 45686, 'file_last_modification_date': 22321,
                            'crc32_of_uncompressed_data': 2768741858, 'compressed_size': 2084,
                            'uncompressed_size': 2084, 'file_name_length': 19, 'extra_field_length': 0,
                            'filename': 'AndroidManifest.xml', 'extra_field': ''}
        local_instance = LocalHeaderRecord.from_dict(andro_local_dict)
        self.assertEqual(local_instance.filename, 'AndroidManifest.xml')
        self.assertEqual(local_instance.compression_method, 30208)

    def test_extract_file_based_on_header_info(self):
        zipentry = ZipEntry.parse(self.apk_orig)
        cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
        local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
        ext_hash = '5f37db22380177c20804d8602ffbdc048caeaa851412ab127e6fe1c9a9b1c78e'
        androidManifest_extracted = \
            extract_file_based_on_header_info(self.apk_orig, local_header_of_file, cd_h_of_file)[0]
        self.assertEqual(hashlib.sha256(androidManifest_extracted).hexdigest(), ext_hash)

    def test_extract_modified_file_based_on_header_info(self):
        zipentry = ZipEntry.parse(self.apk_mod)
        cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
        local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
        ext_hash = '5dc10a071f28ef25c6caa3cd3aef0d93985dacb1dba08ca46632ba655129e503'
        androidManifest_extracted = extract_file_based_on_header_info(self.apk_mod, local_header_of_file, cd_h_of_file)[
            0]
        self.assertEqual(hashlib.sha256(androidManifest_extracted).hexdigest(), ext_hash)

    def test_extract_when_zero_size_and_extra_field_present(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(test_dir, 'res', 'minimal_SIZE_ExtraField.apk'), 'rb') as apk_file:
            zipentry = ZipEntry.parse(apk_file)
            cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
            local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
            ext_hash = '5f37db22380177c20804d8602ffbdc048caeaa851412ab127e6fe1c9a9b1c78e'
            androidManifest_extracted = \
                extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0]
            self.assertEqual(hashlib.sha256(androidManifest_extracted).hexdigest(), ext_hash)

    def test_zipentry_raw_and_path(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        apk_file = os.path.join(test_dir, 'res', 'minimal_orig.apk')
        zipentry_path = ZipEntry.parse(apk_file, raw=False)
        zipentry_raw = ZipEntry.parse(self.apk_orig)
        self.assertEqual(hashlib.sha256(zipentry_path.zip.read()).hexdigest(),
                         hashlib.sha256(zipentry_raw.zip.read()).hexdigest())

    def test_zipentry_read(self):
        zipentry = ZipEntry.parse(self.apk_orig)
        manifest = zipentry.read("AndroidManifest.xml")
        self.assertEqual(hashlib.sha256(manifest).hexdigest(),
                         "5f37db22380177c20804d8602ffbdc048caeaa851412ab127e6fe1c9a9b1c78e")

    def test_zipentry_read_non_existing(self):
        zipentry = ZipEntry.parse(self.apk_orig)
        with self.assertRaises(KeyError) as context:
            zipentry.read("non-existing-entry")

    def test_zipentry_central_non_existing(self):
        zipentry = ZipEntry.parse(self.apk_orig)
        with self.assertRaises(KeyError) as context:
            zipentry.get_central_directory_entry_dict("non-existing-entry")

    def test_zipentry_to_dict(self):
        zipentry = ZipEntry.parse(self.apk_mod)
        self.assertEqual(hashlib.sha256(str(zipentry.to_dict()).encode('utf-8')).hexdigest(),
                         "fbddeffe316446f47e49abe1dbf03fa2a8c0f5af3ad965609368b63932683a2d")

    def test_zipentry_infolist(self):
        zipentry = ZipEntry.parse(self.apk_mod)
        self.assertEqual(set(zipentry.infolist().keys()),
                         {'res/13.webp', 'res/Nt.webp', 'res/j_.webp', 'classes.dex', 'AndroidManifest.xml',
                          'res/sK.webp', 'res/u5.webp', 'res/0w.xml', 'res/fq.webp', 'res/qs.webp', 'res/MO.webp',
                          'res/BW.xml', 'resources.arsc', 'res/d2.webp', 'res/iE.webp', 'res/-6.webp', 'res/5c.webp',
                          'res/Fd.xml', 'res/yw.webp', 'res/0K.xml', 'res/Qr.xml', 'res/9Q.webp',
                          'META-INF/com/android/build/gradle/app-metadata.properties', 'res/Sn.webp'})

    def test_zipentry_namelist(self):
        zipentry = ZipEntry.parse(self.apk_mod)
        self.assertEqual(zipentry.namelist(), ['AndroidManifest.xml', 'classes.dex', 'resources.arsc',
                                               'META-INF/com/android/build/gradle/app-metadata.properties',
                                               'res/BW.xml', 'res/9Q.webp', 'res/Sn.webp', 'res/5c.webp', 'res/yw.webp',
                                               'res/Nt.webp', 'res/MO.webp', 'res/-6.webp', 'res/j_.webp', 'res/0K.xml',
                                               'res/Qr.xml', 'res/d2.webp', 'res/fq.webp', 'res/0w.xml', 'res/iE.webp',
                                               'res/qs.webp', 'res/Fd.xml', 'res/u5.webp', 'res/13.webp',
                                               'res/sK.webp'])

    def test_android_manifest_decoding_orig(self):
        zipentry = ZipEntry.parse(self.apk_orig)
        cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
        local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
        extracted_data = io.BytesIO(
            extract_file_based_on_header_info(self.apk_orig, local_header_of_file, cd_h_of_file)[0])
        manifest = get_manifest(extracted_data)
        manifest_orig = '2846a9e29eb2d75623246440ef02d5a098cde7d21e3948b3ece3c68e3bae13f3'
        self.assertEqual(hashlib.sha256(str(manifest).encode('utf-8')).hexdigest(), manifest_orig)

    def test_android_manifest_decoding_mod(self):
        zipentry = ZipEntry.parse(self.apk_mod)
        cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
        local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
        extracted_data = io.BytesIO(
            extract_file_based_on_header_info(self.apk_mod, local_header_of_file, cd_h_of_file)[0])
        manifest = get_manifest(extracted_data)
        manifest_mod = '2846a9e29eb2d75623246440ef02d5a098cde7d21e3948b3ece3c68e3bae13f3'
        self.assertEqual(hashlib.sha256(str(manifest).encode('utf-8')).hexdigest(), manifest_mod)

    def test_tampering_indicators(self):
        orig_val = {'zip tampering': {}, 'manifest tampering': {}}
        mod_val = {'zip tampering': {'AndroidManifest.xml': {'central compression method': 30208, 'local compression '
                                                                                                  'method': 30208,
                                                             'actual compression method': 'STORED_TAMPERED'}},
                   'manifest tampering': {'file_type': 0, 'string_pool': {'string count': 49, 'real string count': 32}}}
        orig = apk_tampering_check(self.apk_orig, False)
        mod = apk_tampering_check(self.apk_mod, False)
        self.assertEqual(orig, orig_val)
        self.assertEqual(mod, mod_val)

    def test_tampering_indicators_size(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        expected = {'zip tampering': {'AndroidManifest.xml': {
            'differing headers': ['compressed_size', 'extra_field', 'extra_field_length', 'uncompressed_size']}},
            'manifest tampering': {}}
        with open(os.path.join(test_dir, 'res', 'minimal_SIZE_ExtraField.apk'), 'rb') as apk_file:
            res = apk_tampering_check(apk_file, True)
            self.assertEqual(res, expected)

    def test_tampering_zero_end_ns(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        expected = {'zip tampering': {}, 'manifest tampering': {'wrong_end_namespace_size': 'found'}}
        with open(os.path.join(test_dir, 'res', 'minimal_zero_sized_end_ns.apk'), 'rb') as apk_file:
            res = apk_tampering_check(apk_file, False)
            self.assertEqual(res, expected)

    def test_inconsistencies_in_central_local_entries(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(test_dir, 'res', 'truncated-cd.apk'), "rb") as apk_file:
            res = apk_tampering_check(apk_file, False)
            self.assertIn('classes.dex', res['zip tampering']['unique_entries'])
            self.assertIn('classes.deP', res['zip tampering']['unique_entries'])


if __name__ == '__main__':
    unittest.main()
