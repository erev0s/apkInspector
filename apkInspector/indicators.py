import io

from .extract import extract_file_based_on_header_info
from .headers import ZipEntry
from .axml import ResChunkHeader, StringPoolType, process_elements, XmlResourceMapType, XmlStartElement


def count_eocd(apk_file):
    """

    :param apk_file:
    :return:
    """
    content = apk_file.read()
    return content.count(b'\x50\x4b\x05\x06')


def zip_tampering_indicators(apk_file, strict: bool):
    """

    :param apk_file:
    :return:
    """
    zip_tampering_indicators_dict = {}
    count = count_eocd(apk_file)
    if count > 1:
        zip_tampering_indicators_dict['eocd_count'] = count
    zipentry_dict = ZipEntry.parse(apk_file).to_dict()

    for key in zipentry_dict["central_directory"]:
        cd_entry = zipentry_dict["central_directory"][key]
        lh_entry = zipentry_dict["local_headers"][key]
        temp = {}
        if cd_entry['compression_method'] not in [0, 8]:
            temp['central compression method'] = cd_entry['compression_method']
        if lh_entry['compression_method'] not in [0, 8]:
            temp['local compression method'] = lh_entry['compression_method']
        if cd_entry['compression_method'] not in [0, 8] or lh_entry['compression_method'] not in [0, 8]:
            indicator = \
                extract_file_based_on_header_info(apk_file, lh_entry, cd_entry)[
                    1]
            temp['actual compression method'] = indicator
        df_keys = local_and_central_header_discrepancies(cd_entry, lh_entry, strict)
        if df_keys:
            temp['differing headers'] = df_keys
        if not temp:
            continue
        zip_tampering_indicators_dict[key] = temp
    return zip_tampering_indicators_dict


def local_and_central_header_discrepancies(dict1, dict2, strict: bool):
    common_keys = set(dict1.keys()) & set(dict2.keys())
    differences = {key: (dict1[key], dict2[key]) for key in common_keys if dict1[key] != dict2[key]}
    # Display the keys with differing values
    keys = []
    for key, values in dict(sorted(differences.items())).items():
        # strict checking or not: excluding these as they differ often
        if not strict and key in ['extra_field', 'extra_field_length', 'crc32_of_uncompressed_data', 'compressed_size', 'uncompressed_size']:
            continue
        keys.append(key)
    return keys


def manifest_tampering_indicators(manifest):
    """

    :param manifest:
    :return:
    """
    chunkHeader = ResChunkHeader.parse(manifest)
    manifest_tampering_indicators_dict = {}
    if chunkHeader.type != 3:
        manifest_tampering_indicators_dict['file_type'] = chunkHeader.type
    string_pool = StringPoolType.parse(manifest)
    if len(string_pool.string_offsets) != string_pool.header.string_count:
        manifest_tampering_indicators_dict['string_pool'] = {'string count': string_pool.header.string_count,
                                                             'real string count': len(string_pool.string_offsets)}
    XmlResourceMapType.parse(manifest)
    elements, dummy = process_elements(manifest)
    for element in elements:
        if isinstance(element, XmlStartElement):
            for attr in element.attributes:
                if string_pool.strdata[attr.name_index] == "":
                    manifest_tampering_indicators_dict['dummy attributes'] = 'found (verify manually)'
    if dummy:
        manifest_tampering_indicators_dict['dummy data'] = 'found'
    return manifest_tampering_indicators_dict


def apk_tampering_check(apk_file, strict: bool):
    """

    :param apk_file:
    :return:
    """
    zip_tampering_indicators_dict = zip_tampering_indicators(apk_file, strict)
    zipentry = ZipEntry.parse(apk_file)
    cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
    local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
    manifest = io.BytesIO(extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0])
    manifest_tampering_indicators_dict = manifest_tampering_indicators(manifest)
    return {'zip tampering': zip_tampering_indicators_dict, 'manifest tampering': manifest_tampering_indicators_dict}