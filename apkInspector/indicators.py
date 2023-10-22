import io

from .extract import extract_file_based_on_header_info
from .headers import find_eocd, parse_central_directory, get_and_save_local_headers_of_all, headers_of_filename
from .axml import ResChunkHeader, StringPoolType, process_elements, XmlResourceMapType, XmlStartElement


def count_eocd(apk_file):
    """

    :param apk_file:
    :return:
    """
    content = apk_file.read()
    return content.count(b'\x50\x4b\x05\x06')


def zip_tampering_indicators(apk_file):
    """

    :param apk_file:
    :return:
    """
    zip_tampering_indicators_dict = {}
    count = count_eocd(apk_file)
    if count > 1:
        zip_tampering_indicators_dict['eocd_count'] = count
    eocd = find_eocd(apk_file)
    central_directory_entries = parse_central_directory(apk_file, eocd["Offset of start of central directory"])
    local_headers = get_and_save_local_headers_of_all(apk_file, central_directory_entries)

    for key in central_directory_entries:
        cd_entry = central_directory_entries[key]
        lh_entry = local_headers[key]
        temp = {}
        if cd_entry['Compression method'] not in [0, 8]:
            temp['central compression method'] = cd_entry['Compression method']
        if lh_entry['Compression method'] not in [0, 8]:
            temp['local compression method'] = lh_entry['Compression method']
        if cd_entry['Compression method'] not in [0, 8] or lh_entry['Compression method'] not in [0, 8]:
            indicator = \
                extract_file_based_on_header_info(apk_file, cd_entry["Relative offset of local file header"], lh_entry)[
                    1]
            temp['actual compression method'] = indicator
        if not temp:
            continue
        zip_tampering_indicators_dict[key] = temp
    return zip_tampering_indicators_dict


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


def apk_tampering_check(apk_file):
    """

    :param apk_file:
    :return:
    """
    zip_tampering_indicators_dict = zip_tampering_indicators(apk_file)
    eocd = find_eocd(apk_file)
    central_directory_entries = parse_central_directory(apk_file, eocd["Offset of start of central directory"])
    cd_h_of_file, local_header_of_file = headers_of_filename(apk_file, central_directory_entries,
                                                             "AndroidManifest.xml")
    offset = cd_h_of_file["Relative offset of local file header"]
    manifest = io.BytesIO(extract_file_based_on_header_info(apk_file, offset, local_header_of_file)[0])
    manifest_tampering_indicators_dict = manifest_tampering_indicators(manifest)
    return {'zip tampering': zip_tampering_indicators_dict, 'manifest tampering': manifest_tampering_indicators_dict}