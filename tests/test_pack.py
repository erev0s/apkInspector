import io
import os
import unittest
import hashlib

from apkInspector.axml import get_manifest, ManifestStruct
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

