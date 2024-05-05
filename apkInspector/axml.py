import io
import logging
import struct
import random

from .extract import extract_file_based_on_header_info
from .headers import ZipEntry
from .helpers import escape_xml_entities

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d -> %(funcName)s : %(message)s'
)


class ResChunkHeader:
    """
    Chunk header used throughout the axml.
    This header is essential as it contains information about the header size but also the total size of the chunk
    the header belongs to.
    """

    def __init__(self, header_type, header_size, total_size, data):
        self.type = header_type
        self.header_size = header_size
        self.total_size = total_size
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Read the header type (2 bytes), header size (2 bytes), and entry size (4 bytes).

        :param file: the xml file e.g. with open('/path/AndroidManifest.xml', 'rb') as file
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResChunkHeader
        """
        header_data = file.read(8)
        if len(header_data) < 8:
            # End of file
            return None
        header_type, header_size, total_size = struct.unpack('<HHI', header_data)
        return cls(header_type, header_size, total_size, header_data)


class ResStringPoolHeader:
    """
    It reads the string pool header which contains information about the StringPool.
    """

    def __init__(self, header: ResChunkHeader, string_count, style_count, flags, strings_start,
                 styles_start, data):
        self.header = header
        self.string_count = string_count
        self.style_count = style_count
        self.flags = flags
        self.strings_start = strings_start
        self.styles_start = styles_start
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Read and parse ResStringPoolHeader from the file.

        :param file: the xml file right after the header has been read.
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResStringPoolHeader
        """
        header = ResChunkHeader.parse(file)
        string_pool_header_data = file.read(20)
        string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIII', string_pool_header_data)
        return cls(header, string_count, style_count, flags, strings_start,
                   styles_start, string_pool_header_data)


class StringPoolType:
    """
    The stringPool class which is a composition of the ResStringPoolHeader
    along with the string offsets and the string data.
    """

    def __init__(self, string_pool_header: ResStringPoolHeader, string_offsets, strings, string_pool_data):
        self.str_header = string_pool_header
        self.string_offsets = string_offsets
        self.string_list = strings
        self.data = string_pool_data

    @classmethod
    def read_string_offsets(cls, file, num_of_strings, end_absolute_offset):
        """
        Reads the offset available for each string. Requires to know the number of strings available beforehand.

        :param file: the xml file right after the string pool header has been read.
        :type file: bytesIO
        :param num_of_strings: the calculated number of strings available
        :type num_of_strings: int
        :param end_absolute_offset: the absolute value of the offset where the offsets finish.
        :type end_absolute_offset: int
        :return: Returns a list of strings offsets.
        :rtype: list
        """
        string_offsets = []
        for i in range(0, num_of_strings):
            string_offsets.append(struct.unpack('<I', file.read(4))[0])
        # sanity check as after reading the last string we should be at the end offset as calculated
        if file.tell() != end_absolute_offset:
            logging.warning(
                f"Current file read:{file.tell()} is not as expected to the start of the stringData:{end_absolute_offset})")
        return string_offsets

    @classmethod
    def decode_stringpool_mixed_string(cls, file, is_utf8, end_stringpool_offset):
        """
        Handling the different encoding possibilities that can be met.

        :param file: the xml file at the offset where the string is to be read
        :type file: bytesIO
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :return: Returns the decoded string
        :rtype: str
        """
        if not is_utf8:
            # Handle UTF-16 encoded strings
            u16len = struct.unpack('<H', file.read(2))[0]
            if u16len & 0x8000 == 0:
                # Regular UTF-16 string
                content = file.read(u16len * 2).decode('utf-16le')
            else:
                # UTF-16 string with fixup
                u16len_fix = struct.unpack('<H', file.read(2))[0]
                real_length = ((u16len & 0x7FFF) << 16) | u16len_fix
                if real_length > end_stringpool_offset:
                    return ""
                # TODO:a check for non null-terminated strings should be here as well
                content = file.read(real_length * 2).decode('utf-16le')
        else:
            # Handle UTF-8 encoded strings
            u16len = struct.unpack('B', file.read(1))[0]
            file.read(1)
            u8len = u16len
            content = file.read(u8len).decode('utf-8', errors='replace')
            # TODO: fixup is needed here as well, like for the utf16 case

        return content

    @classmethod
    def read_strings(cls, file, string_offsets, strings_start, is_utf8):
        """
        Gets the actual strings based on the offsets retrieved from read_string_offsets().

        :param file: the xml file right after the string pool offsets have been read
        :type file: bytesIO
        :param string_offsets: see -> read_string_offsets()
        :type string_offsets: list
        :param strings_start: the offset at which the string data starts
        :type strings_start: int
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :return: Returns a list of the string data
        :rtype: list
        """
        strings = []
        for offset in string_offsets:
            # Calculate the absolute offset within the string data +8 for the file header
            absolute_offset = strings_start + offset + 8  # TODO: update this to get the file header size
            # Move the file pointer to the start of the string
            file.seek(absolute_offset)
            # Read the length of the string (in bytes)
            content = cls.decode_stringpool_mixed_string(file, is_utf8, strings_start + string_offsets[-1])
            strings.append(content)
        return strings

    @classmethod
    def parse(cls, file):
        """
        Parse the string pool to acquire the strings used within the axml.

        :param file: the xml file right after the file header is read
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: StringPoolType
        """
        string_pool_header = ResStringPoolHeader.parse(file)
        string_pool_start = file.tell()
        size_of_strings_offsets = string_pool_header.strings_start - 28
        # it should be divisible by 4, as 4 bytes are per offset, so we can get accurately the # of strings
        num_of_strings = size_of_strings_offsets // 4
        if not (size_of_strings_offsets / 4).is_integer():
            logging.warning(f"The number of strings in the string pool is not a integer number.")
        string_offsets = cls.read_string_offsets(file, num_of_strings, string_pool_header.strings_start + 8)
        is_utf8 = bool(string_pool_header.flags & (1 << 8))
        string_list = cls.read_strings(file, string_offsets, string_pool_header.strings_start, is_utf8)
        while True:  # read any null bytes remaining
            cur_pos = file.tell()
            if file.read(2) == b'\x80\x01':
                file.seek(cur_pos)
                break
            file.seek(cur_pos)
            file.read(1)
        string_pool_end = file.tell()
        file.seek(string_pool_start)
        string_pool_data = file.read(string_pool_end - string_pool_start)
        return cls(
            string_pool_header,
            string_offsets,
            string_list,
            string_pool_data
        )


class XmlResourceMapType:
    """
    Resource map class, with the header and the resource IDs.
    """

    def __init__(self, header, resids, resids_data):
        self.header = header
        self.resids = resids
        self.data = resids_data

    @classmethod
    def parse(cls, file):
        """
        Parse the resource map and get the resource IDs.

        :param file: the xml file right after the string pool is read
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: XmlResourceMapType
        """
        header = ResChunkHeader.parse(file)
        num_resids = (header.total_size - header.header_size) // 4
        resids_data = file.read(num_resids*4)
        chunks = [resids_data[i:i + 4] for i in range(0, len(resids_data), 4)]
        resids = [struct.unpack('<I', chunk)[0] for chunk in chunks]

        return cls(header, resids, resids_data)


class ResXMLHeader:
    """
    Chunk header used as a header for the elements.
    This header represents the header for the rest of the elements besides the initial header, the string pool and
    the resource map.
    """

    def __init__(self, header: ResChunkHeader, data):
        self.header = header
        # self.xml_header_line_number = header_line_number  # not useful
        # self.xml_header_comment = header_comment          # not useful
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Supporting header for the elements besides the initial header, the string pool and
        the resource map.

        :param file: the xml file e.g. with open('/path/AndroidManifest.xml', 'rb') as file
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResXMLHeader
        """
        header = ResChunkHeader.parse(file)
        header_data = b''
        if header.header_size > 8:
            header_data = file.read(header.header_size - 8)
        return cls(header, header_data)


class XmlStartNamespace:
    """
    The actual start of the xml, after this the elements of the xml will be found.
    """

    def __init__(self, header: ResXMLHeader, ext, ext_data):
        self.header = header
        self.ext = ext  # [prefix_index, uri_index]
        self.data = ext_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the starting element of a Namespace
        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlStartNamespace
        """
        num_exts = (header_t.header.total_size - header_t.header.header_size) // 4
        ext_data = file.read(num_exts*4)
        chunks = [ext_data[i:i + 4] for i in range(0, len(ext_data), 4)]
        ext = [struct.unpack('<I', chunk)[0] for chunk in chunks]
        return cls(header_t, ext, ext_data)


class XmlEndNamespace:
    """
    Class to represent the end of a Namespace.
    """

    def __init__(self, header: ResXMLHeader, prefix_namespace_index, uri_index, end_namespace_data):
        self.header = header
        self.prefix_namespace_index = prefix_namespace_index
        self.uri_index = uri_index
        self.data = end_namespace_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the ending element of a Namespace.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlEndNamespace
        """
        end_namespace_data = file.read(8)
        prefix_namespace_index, uri_index = struct.unpack('<II', end_namespace_data)
        return cls(header_t, prefix_namespace_index, uri_index, end_namespace_data)


class XmlAttributeElement:
    """
    The attributes within each element within the axml, should be described by this class.
    """

    def __init__(self, full_namespace_index, name_index, raw_value_index, typed_value_size, typed_value_res0,
                 typed_value_datatype, typed_value_data):
        self.full_namespace_index = full_namespace_index
        self.name_index = name_index
        self.raw_value_index = raw_value_index
        self.typed_value_size = typed_value_size
        self.typed_value_res0 = typed_value_res0
        self.typed_value_datatype = typed_value_datatype
        self.typed_value_data = typed_value_data

    @classmethod
    def parse(cls, file, attr_count, attr_size):
        """
        The method is responsible to parse and retrieve the attributes of an element based on the attribute count.
        There are many datatypes that are not read according to the specification (at least for now), but that does
        not affect the main goal of the tool, therefore it is not a priority. For the presentation of the values
        another check is occurring in the process_attributes method.

        :param file: the axml already pointing at the right offset
        :type file: BytesIO
        :param attr_count: The attribute count value part of XmlStartElement.attrext
        :type attr_count: int
        :param attr_size: The attribute size value part of XmlStartElement
        :type attr_size: int
        :return: List of attributes
        :rtype: list
        """
        attrs = []
        for _ in range(0, attr_count):
            tn = file.tell()
            full_namespace_index = struct.unpack('<I', file.read(4))[0]
            name_index = struct.unpack('<I', file.read(4))[0]
            raw_value_index = struct.unpack('<I', file.read(4))[0]
            typed_value_size = struct.unpack('<H', file.read(2))[0]
            typed_value_res0 = struct.unpack('<B', file.read(1))[0]
            typed_value_datatype = struct.unpack('<B', file.read(1))[0]
            if typed_value_datatype == 4:
                typed_value_data = round(struct.unpack('<f', file.read(4))[0], 1)
            elif typed_value_datatype == 5:
                typed_value_data = struct.unpack('<I', file.read(4))[0]
            elif typed_value_datatype == 16:
                typed_value_data = struct.unpack('<i', file.read(4))[0]
            else:
                typed_value_data = struct.unpack('<I', file.read(4))[0]
            attrs.append(cls(full_namespace_index, name_index, raw_value_index, typed_value_size, typed_value_res0,
                             typed_value_datatype, typed_value_data))
            if file.tell() - tn != attr_size:  # check for any dummy data in between attributes
                file.read(attr_size-(file.tell() - tn))
        return attrs


class XmlStartElement:
    """
    The starting point of an element, its attributes are described by XmlAttributeElement.
    The attrext contains information about the element including the attribute count.
    """

    def __init__(self, header: ResXMLHeader, attrext, attributes, start_element_data):
        self.header = header
        self.attrext = attrext
        self.attributes = attributes
        self.data = start_element_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the current element

        :param file: the axml already pointing at the right offset
        :type file: BytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlStartElement
        """
        attrext_data = file.read(20)
        full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index, style_index = struct.unpack(
            '<IIHHHHHH', attrext_data)
        attrext = [full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index,
                   style_index]
        cp = file.tell()
        attributes_data = file.read(attr_size*attr_count)
        file.seek(cp)
        attributes = XmlAttributeElement.parse(file, attr_count, attr_size)
        return cls(header_t, attrext, attributes, (attrext_data + attributes_data))


class XmlEndElement:
    """
    The end of an element, where the attrext contains the necessary information on which element it ends.
    """

    def __init__(self, header: ResXMLHeader, attrext, attrext_data):
        self.header = header
        self.attrext = attrext
        self.data = attrext_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the end of an element.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlEndElement
        """
        attrext_data = file.read(8)
        full_namespace_index, name_index = struct.unpack('<II', attrext_data)
        attrext = [full_namespace_index, name_index]
        return cls(header_t, attrext, attrext_data)


class XmlcDataElement:
    """
    A class to cover any CDATA section
    https://developer.android.com/reference/org/w3c/dom/CDATASection
    """

    def __init__(self, header: ResXMLHeader, data_index, typed_value_size, typed_value_res0,
                 typed_value_datatype, typed_value_data, cdata_data):
        self.header = header
        self.data_index = data_index
        self.typed_value_size = typed_value_size
        self.typed_value_res0 = typed_value_res0
        self.typed_value_datatype = typed_value_datatype
        self.typed_value_data = typed_value_data
        self.data = cdata_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the CDATA element.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlcDataElement
        """
        cdata_data = file.read(12)
        data_index = struct.unpack('<I', cdata_data)
        typed_value_size = struct.unpack('<H', cdata_data)[0]
        typed_value_res0 = struct.unpack('<B', cdata_data)[0]
        typed_value_datatype = struct.unpack('<B', cdata_data)[0]
        typed_value_data = struct.unpack('<I', cdata_data)[0]
        return cls(header_t, data_index, typed_value_size, typed_value_res0,
                   typed_value_datatype, typed_value_data, cdata_data)


class ManifestStruct:
    """
    A class to represent the AndroidManifest as a composition
    """

    def __init__(self, header: ResChunkHeader, string_pool: StringPoolType, resource_map: XmlResourceMapType, elements):
        self.header = header
        self.string_pool = string_pool
        self.resource_map = resource_map
        self.elements = elements

    def get_manifest(self):
        """
        Method to return the AndroidManifest created from this instance

        :return: The AndroidManifest.xml as a string
        :rtype: str
        """
        manifest = create_manifest(self.elements, self.string_pool.string_list)
        return manifest

    @classmethod
    def parse(cls, file):
        """
        A composition of the rest of the classes available in the apkInspector.axml module, to form the AndroidManifest structure.

        :param file: the axml that will be processed
        :type file: bytesIO
        :return: an instance of itself
        :rtype: ManifestStruct
        """
        header = ResChunkHeader.parse(file)
        string_pool = StringPoolType.parse(file)
        resource_map = XmlResourceMapType.parse(file)
        elements = process_elements(file)[0]
        return cls(header, string_pool, resource_map, elements)


chunk_type_handlers = {
    '0x100': XmlStartNamespace.parse,   # RES_XML_START_NAMESPACE_TYPE
    '0x101': XmlEndNamespace.parse,     # RES_XML_END_NAMESPACE_TYPE
    '0x102': XmlStartElement.parse,     # RES_XML_START_ELEMENT_TYPE
    '0x103': XmlEndElement.parse,       # RES_XML_END_ELEMENT_TYPE
    '0x104': XmlcDataElement.parse,     # RES_XML_CDATA_TYPE
}


def parse_next_header(file):
    """
    Dispatcher method to parse the next available header. It takes into account to move on past the header if it
    contains extra info besides the standard ones.
    The dispatcher automatically picks the correct processing method for each chunk type.

    :param file: the axml that will be processed
    :type file: bytesIO
    :raises NotImplementedError: The chunk type identified is not supported
    :return: Dispatches to the appropriate processing method for each chunk type.
    """
    chunk_header_total = ResXMLHeader.parse(file)
    chunk_header = chunk_header_total.header
    if chunk_header is None:  # end of file
        return None
    chunk_type = hex(chunk_header.type)
    if chunk_type in chunk_type_handlers:
        return chunk_type_handlers[chunk_type](file, chunk_header_total)
    else:
        raise NotImplementedError(f"Unsupported chunk type: {chunk_type}")


def process_elements(file):
    """
    It starts processing the remaining chunks **after** the resource map chunk.
    It also returns whether dummy data have been found between the elements, so it can be reported that the apk employed
    this evasion technique.

    :param file: the axml that will be processed
    :type file: BytesIO
    :return: Returns all the elements found as their corresponding classes and whether dummy data were found in between.
    :rtype: set(list, set(bool, bool))
    """
    elements = []
    dummy_data_between_elements = False
    wrong_end_namespace_size = False
    possible_types = {256, 257, 258, 259, 260}
    min_size = 8
    while True:
        cur_pos = file.tell()
        if file.getbuffer().nbytes < cur_pos + min_size:
            # we reached the end of the file
            break
        _type, _header_size, _size = struct.unpack('<HHL', file.read(8))
        file.seek(cur_pos)
        if cur_pos == 0 or (
                _type in possible_types and _header_size >= min_size):
            if _size < min_size and _type == 257:
                wrong_end_namespace_size = True
            chunk_type = parse_next_header(file)
            elements.append(chunk_type)
            continue
        file.read(1)
        dummy_data_between_elements = True
    return elements, (dummy_data_between_elements, wrong_end_namespace_size)


def process_attributes(attributes, string_data, ns_dict):
    """
    Helps in processing the representation of attributes found in each element of the axml. It should be noted that not
    all datatypes are taken into account, meaning that the values of certain attributes might not be represented properly.

    :param attributes: the attributes of an XmlStartElement object as returned by XmlAttributeElement.parse()
    :type attributes: list
    :param string_data: the string data list from the String Pool
    :type string_data: list
    :param ns_dict: a namespace dictionary based on the XmlStartNamespace elements found
    :type ns_dict: dict
    :return: returns a string of all the attributes with their values
    :rtype: str
    """
    attribute_list = []
    for attr in attributes:
        name = string_data[attr.name_index]
        if not name:  # It happens that the attr.name_index points to an empty string in StringPool and you have to use
            # the public.xml. It falls outside the scope of the tool, so I am not going to solve it for now.
            name = f'Unknown_Attribute_Name_{random.randint(1000, 9999)}'
        if attr.typed_value_datatype == 1:  # reference type
            value = f"@{attr.typed_value_data}"
        elif attr.typed_value_datatype == 3:  # string type
            try:
                value = escape_xml_entities(string_data[attr.typed_value_data])
            except:
                value = attr.typed_value_data
        elif attr.typed_value_datatype == 17:  # int-hex type
            value = "0x{:08X}".format(attr.typed_value_data)
        elif attr.typed_value_datatype == 18:  # boolean type
            value = "true" if bool(attr.typed_value_data) else "false"
        elif attr.typed_value_datatype == 0:  # null, used for CData
            return name
        else:
            # TODO: Not accurate enough, values should be represented based on which datatype. Good enough for now
            value = str(attr.typed_value_data)
        if attr.full_namespace_index < len(string_data):
            namespace = string_data[attr.full_namespace_index]
            if not namespace:  # Same as with the empty name, points to an empty string in StringPool.
                namespace = 'android'
            try:
                attribute_list.append(f'{ns_dict[namespace]}:{name}="{value}"')
            except:
                attribute_list.append(f'{namespace.split("/")[-1]}:{name}="{value}"')
        else:
            attribute_list.append(f'{name}="{value}"')

    return ' '.join(attribute_list)


def create_manifest(elements, string_data):
    """
    Method to create the AndroidManifest.xml file based on the elements discovered from the processed APK

    :param elements: The parsed elements as returned by process_elements()[0]
    :type elements: list
    :param string_data: The string pool data
    :type string_data: list
    :return: The AndroidManifest.xml as a string
    :rtype: str
    """
    android_manifest_xml = []
    namespaces = {}
    ns_dict = {}
    ns_declared = []
    for element in elements:
        if isinstance(element, XmlStartNamespace):
            namespaces[
                string_data[element.ext[0]]] = f'xmlns:{string_data[element.ext[0]]}="{string_data[element.ext[1]]}"'
            ns_dict[string_data[element.ext[1]]] = string_data[element.ext[0]]
        elif isinstance(element, XmlStartElement):
            attributes = process_attributes(element.attributes, string_data, ns_dict)
            attr_ns_list = set(ns.split(':')[0] for ns in attributes.split(' ') if ':' in ns)
            tmp_ns = []  # TODO: Somewhat hacky way to add namespaces/ Maybe improve in future depending on needs
            for vl in attr_ns_list:
                if vl not in ns_declared:
                    if vl in namespaces:
                        tmp_ns.append(namespaces[vl])
                    elif vl == 'android':
                        tmp_ns.append(f'xmlns:android="http://schemas.android.com/apk/res/android"')
                    ns_declared.append(vl)
            if tmp_ns:
                tag_line = f"<{string_data[element.attrext[1]]} {' '.join(tmp_ns)} {attributes}>\n" if attributes else f"<{string_data[element.attrext[1]]}>\n"
            else:
                tag_line = f"<{string_data[element.attrext[1]]} {attributes}>\n" if attributes else f"<{string_data[element.attrext[1]]}>\n"
            android_manifest_xml.append(tag_line)
        elif isinstance(element, XmlcDataElement):
            if android_manifest_xml[-1][-1] == '\n':
                android_manifest_xml[-1] = android_manifest_xml[-1].replace('\n', string_data[element.data_index[0]])
        elif isinstance(element, XmlEndElement):
            name = string_data[element.attrext[1]]
            closing_tag = f"</{name}>" if name == "manifest" else f"</{name}>\n"
            android_manifest_xml.append(closing_tag)
    return ''.join(android_manifest_xml)


def get_manifest(raw_manifest):
    """
    Helper method to directly return the AndroidManifest file as created by create_manifest()

    :param raw_manifest: expects the encoded AndroidManifest.xml file as a file-like object
    :type raw_manifest: bytesIO
    :return: returns the decoded AndroidManifest file
    :rtype: str
    """
    manifest_object = ManifestStruct.parse(raw_manifest)
    return manifest_object.get_manifest()


def parse_apk_for_manifest(apk_file, save: bool = False):
    """
    Helper method to retrieve the AndroidManifest.xml directly from an APK path

    :param apk_file: The path of the APK file
    :type apk_file: str
    :param save: Boolean parameter to define whether to save the manifest or not
    :type save: bool
    :return: Returns the AndroidManifest.xml as string
    :rtype: str
    """
    with open(apk_file, 'rb') as apk:
        zipentry = ZipEntry.parse(apk)
        cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
        local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
        extracted_data = io.BytesIO(
            extract_file_based_on_header_info(apk, local_header_of_file, cd_h_of_file)[0])
    manifest = get_manifest(extracted_data)
    if save:
        with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
            xml_file.write(manifest)
        print("AndroidManifest was saved as: decoded_AndroidManifest.xml")
    return manifest
