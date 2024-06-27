import io
import os
import unittest
import hashlib

from apkInspector.axml import ManifestStruct, parse_manifest_lite, get_manifest_lite_info
from apkInspector.headers import ZipEntry


class ApkInspectorPackTestCase(unittest.TestCase):

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

    def test_integrity(self):
        hash_orig = "5f37db22380177c20804d8602ffbdc048caeaa851412ab127e6fe1c9a9b1c78e"
        zipentry = ZipEntry.parse(self.apk_orig)
        extracted_androidmanifest_orig = zipentry.read('AndroidManifest.xml')
        manifest_object = ManifestStruct.parse(io.BytesIO(extracted_androidmanifest_orig))
        header_data = manifest_object.header.data
        string_pool_data = manifest_object.string_pool.str_header.header.data + manifest_object.string_pool.str_header.data + manifest_object.string_pool.data
        resource_map_data = manifest_object.resource_map.header.data + manifest_object.resource_map.data
        elements = []
        for element in manifest_object.elements:
            elements.append(element.header.header.data + element.header.data + element.data)
        whole_apk = header_data + string_pool_data + resource_map_data
        for el in elements:
            whole_apk += el
        calculated_hash = hashlib.sha256(whole_apk).hexdigest()
        self.assertEqual(hash_orig, calculated_hash)

    def test_lite(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        pth = os.path.join(test_dir, 'res', 'minimal_def_mod.apk')
        zipentry = ZipEntry.parse(pth, False)
        manifest_bytes = zipentry.read('AndroidManifest.xml')
        manifest_object = ManifestStruct.parse((io.BytesIO(manifest_bytes)))

        (ResChunkHeader_data_init,
         [string_pool_ResChunkHeader_data, string_pool_data],
         [resource_map_header, resource_map_data], elements) = parse_manifest_lite(io.BytesIO(manifest_bytes))

        # checks
        self.assertEqual(manifest_object.header.data, ResChunkHeader_data_init.data)
        self.assertEqual(manifest_object.string_pool.str_header.header.data,
                         string_pool_ResChunkHeader_data.header.data)
        self.assertEqual(manifest_object.string_pool.str_header.data, string_pool_ResChunkHeader_data.data)
        self.assertEqual(manifest_object.string_pool.data, string_pool_data)
        self.assertEqual(manifest_object.resource_map.header.data, resource_map_header.data)
        self.assertEqual(manifest_object.resource_map.data, resource_map_data)

    def test_lite_info(self):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        pth = os.path.join(test_dir, 'res', 'minimal_def_mod.apk')
        zipentry = ZipEntry.parse(pth, False)
        manifest_bytes = zipentry.read('AndroidManifest.xml')
        liteInfo = get_manifest_lite_info(io.BytesIO(manifest_bytes), 2)
        self.assertEqual(liteInfo, {'versionCode': '1', 'versionName': '1.0', 'compileSdkVersion': '33',
                                    'compileSdkVersionCodename': '13', 'package': 'com.erev0s.minimal',
                                    'platformBuildVersionCode': '33', 'platformBuildVersionName': '13'})

        liteInfo = get_manifest_lite_info(io.BytesIO(manifest_bytes), 3)
        self.assertEqual(liteInfo, {'versionCode': '1', 'versionName': '1.0', 'compileSdkVersion': '33',
                                    'compileSdkVersionCodename': '13', 'package': 'com.erev0s.minimal',
                                    'platformBuildVersionCode': '33', 'platformBuildVersionName': '13',
                                    'minSdkVersion': '24', 'targetSdkVersion': '33'})
