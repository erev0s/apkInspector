import struct


class ResChunkHeader:
    """
    It is the starting header of the AndroidManifest.xml file.
    Although the header specification states to start with \x03\x00 it is not validate by Android itself.
    """

    def __init__(self, header_type, header_size, total_size):
        self.type = header_type
        self.header_size = header_size
        self.total_size = total_size

    @classmethod
    def from_file(cls, file):
        """
        Read the header type (2 bytes), header size (2 bytes), and entry size (4 bytes)
        :param file: the xml file e.g. with open('/path/AndroidManifest.xml', 'rb') as file:
        :return: Returns an instance of itself
        """
        header_data = file.read(8)
        if len(header_data) < 8:
            # End of file
            return None
        header_type, header_size, total_size = struct.unpack('<HHI', header_data)
        return cls(header_type, header_size, total_size)


class ResStringPoolHeader:
    """
    It reads the string pool header which contains information about the StringCount etc.
    It is a common practice to have a stringCount value that does not reflect the actual strings in place. Android
    itself does not take into account the stringCount when getting the string offsets and the string data!
    """

    def __init__(self, header_type, header_size, total_size, string_count, style_count, flags, strings_start,
                 styles_start):
        self.header = ResChunkHeader(header_type, header_size, total_size)
        self.string_count = string_count
        self.style_count = style_count
        self.flags = flags
        self.strings_start = strings_start
        self.styles_start = styles_start

    @classmethod
    def from_file(cls, file):
        """
        Read and parse ResStringPoolHeader from the file
        :param file: the xml file right after the header has been read.
        :return: Returns an instance of itself
        """
        header = ResChunkHeader.from_file(file)
        string_pool_header_data = file.read(20)
        string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIII', string_pool_header_data)
        return cls(header.type, header.header_size, header.total_size, string_count, style_count, flags, strings_start,
                   styles_start)


class StringPoolType:
    """
    The stringPool class which contains the header defined before: ResStringPoolHeader
    along with the string offsets and the string data.
    """
    def __init__(self, header_type, header_size, total_size, string_count, style_count, flags, strings_start,
                 styles_start, string_offsets, strdata):
        self.header = ResStringPoolHeader(header_type, header_size, total_size, string_count, style_count, flags,
                                          strings_start,
                                          styles_start)
        self.string_offsets = string_offsets
        self.strdata = strdata

    @classmethod
    def read_string_offsets(cls, file, num_of_strings, end_absolute_offset):
        """
        Reads the offsets available for each string. The important thing to notice is that the number of strings being
        passed as a parameter should not be the stringCount retrieved from the string pool header, it should be
        calculated!
        :param file: the xml file right after the string pool header has been read.
        :param num_of_strings: the calculated number of strings available
        :param end_absolute_offset: the absolute value of the offset where the offsets finish.
        :return: Returns a list of strings offsets.
        """
        string_offsets = []
        for i in range(0, num_of_strings):
            string_offsets.append(struct.unpack('<I', file.read(4))[0])
        # sanity check as after reading the last string we should be at the end offset as calculated
        if file.tell() != end_absolute_offset:
            print(
                f"Current file read:{file.tell()} is not as expected to the start of the stringData:{end_absolute_offset})")
        return string_offsets

    @classmethod
    def decode_stringpool_mixed_string(cls, file, is_utf8):
        """
        Handling the different encoding possibilities that can be met.
        :param file: the xml file at the offset where the string is to be read
        :param is_utf8: boolean to check if a utf8 string is expected
        :return: Returns the decoded string
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
                content = file.read(real_length * 2).decode('utf-16le')
        else:
            # Handle UTF-8 encoded strings
            u16len = struct.unpack('B', file.read(1))[0]
            file.read(1)
            u8len = u16len
            content = file.read(u8len).decode('utf-8', errors='replace')

        return content

    @classmethod
    def read_strings(cls, file, string_offsets, strings_start, is_utf8):
        """
        Gets the actual strings based on the offsets retrieved from read_string_offsets()
        :param file: the xml file right after the string pool offsets have been read
        :param string_offsets: see -> read_string_offsets()
        :param strings_start:
        :param is_utf8: the offset at which the string data starts
        :return: Returns a list of the string data
        """
        strings = []
        for offset in string_offsets:
            # Calculate the absolute offset within the string data +8 for the file header
            absolute_offset = strings_start + offset + 8  # TODO: update this to get the file header size
            # Move the file pointer to the start of the string
            file.seek(absolute_offset)
            # Read the length of the string (in bytes)
            content = cls.decode_stringpool_mixed_string(file, is_utf8)
            strings.append(content)
        return strings

    @classmethod
    def from_file(cls, file):
        """
        Handle the string pool
        :param file: the xml file right after the file header is read
        :return: Returns an instance of itself
        """
        string_pool_header = ResStringPoolHeader.from_file(file)
        size_of_strings_offsets = string_pool_header.strings_start - 28
        # it should be divisible by 4, as 4 bytes are per offset, so we can get accurately the # of strings
        num_of_strings = size_of_strings_offsets // 4
        if not (size_of_strings_offsets / 4).is_integer():
            print(f"The number of strings in the string pool is not a integer number.")
        string_offsets = cls.read_string_offsets(file, num_of_strings, string_pool_header.strings_start + 8)
        is_utf8 = bool(string_pool_header.flags & (1 << 8))
        string_data = cls.read_strings(file, string_offsets, string_pool_header.strings_start, is_utf8)
        file.read(2)  # the +2 is to account for the null bytes after the last strPool element
        return cls(
            string_pool_header.header.type,
            string_pool_header.header.header_size,
            string_pool_header.header.total_size,
            string_pool_header.string_count,
            string_pool_header.style_count,
            string_pool_header.flags,
            string_pool_header.strings_start,
            string_pool_header.styles_start,
            string_offsets,
            string_data
        )


class XmlResourceMapType(ResChunkHeader):
    """
    Resource map class, with the header and the resource IDs
    """
    def __init__(self, header_type, header_size, total_size, resids):
        super().__init__(header_type, header_size, total_size)
        self.resids = resids

    @classmethod
    def parse(cls, file, header: ResChunkHeader):
        """
        Parse the resourse map and get the resource IDs
        :param file: the xml file right after the string pool is read
        :param header: the header ResChunkHeader
        :return: Returns an instance of itself
        """
        num_resids = (header.total_size - header.header_size) // 4
        resids = [struct.unpack('<I', file.read(4))[0] for _ in range(num_resids)]

        return cls(header.type, header.header_size, header.total_size, resids)


class XmlStartNamespace(ResChunkHeader):
    """
    The actual start of the xml, after this the elements of the xml will be found.
    """
    def __init__(self, header_type, header_size, total_size, ext):
        super().__init__(header_type, header_size, total_size)
        self.ext = ext

    @classmethod
    def parse(cls, file, header: ResChunkHeader):
        num_exts = (header.total_size - header.header_size) // 4
        ext = [struct.unpack('<I', file.read(4))[0] for _ in range(num_exts)]

        return cls(header.type, header.header_size, header.total_size, ext)


class XmlEndNamespace(ResChunkHeader):
    """
    Indicator for the end of the xml file.
    """
    def __init__(self, header_type, header_size, total_size, prefix_namespace_index, uri_index):
        super().__init__(header_type, header_size, total_size)
        self.prefix_namespace_index = prefix_namespace_index
        self.uri_index = uri_index

    @classmethod
    def parse(cls, file, header: ResChunkHeader):
        prefix_namespace_index = struct.unpack('<I', file.read(4))[0]
        uri_index = struct.unpack('<I', file.read(4))[0]

        return cls(header.type, header.header_size, header.total_size, prefix_namespace_index, uri_index)


class XmlAttributeElement:
    """
    The attributes within each element within the xml, should be described by this class
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
        attrs = []
        for _ in range(0, attr_count):
            full_namespace_index = struct.unpack('<I', file.read(4))[0]
            name_index = struct.unpack('<I', file.read(4))[0]
            raw_value_index = struct.unpack('<I', file.read(4))[0]
            typed_value_size = struct.unpack('<H', file.read(2))[0]
            typed_value_res0 = struct.unpack('<B', file.read(1))[0]
            typed_value_datatype = struct.unpack('<B', file.read(1))[0]
            typed_value_data = struct.unpack('<I', file.read(4))[0]
            attrs.append(cls(full_namespace_index, name_index, raw_value_index, typed_value_size, typed_value_res0,
                             typed_value_datatype, typed_value_data))
        return attrs


class XmlStartElement(ResChunkHeader):
    """
    The starting point of an element, its attributes are described by XmlAttributeElement
    The attrext contains information about the element including the attribute count.
    """
    def __init__(self, header_type, header_size, total_size, attrext, attributes):
        super().__init__(header_type, header_size, total_size)
        self.attrext = attrext
        self.attributes = attributes

    @classmethod
    def parse(cls, file, header: ResChunkHeader):
        full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index, style_index = struct.unpack(
            '<IIHHHHHH', file.read(20))

        attrext = [full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index,
                   style_index]
        attributes = XmlAttributeElement.parse(file, attr_count, attr_size)
        return cls(header.type, header.header_size, header.total_size, attrext, attributes)


class XmlEndElement(ResChunkHeader):
    """
    The end of an element, where the attrext contains the necessary information on which element it ends.
    """
    def __init__(self, header_type, header_size, total_size, attrext):
        super().__init__(header_type, header_size, total_size)
        self.attrext = attrext

    @classmethod
    def parse(cls, file, header: ResChunkHeader):
        full_namespace_index, name_index = struct.unpack('<II', file.read(8))
        attrext = [full_namespace_index, name_index]
        return cls(header.type, header.header_size, header.total_size, attrext)


def process_xml_resource_map(file, chunk_header: ResChunkHeader):
    return XmlResourceMapType.parse(file, chunk_header)


def process_xml_start_namespace(file, chunk_header: ResChunkHeader):
    return XmlStartNamespace.parse(file, chunk_header)


def process_xml_end_namespace(file, chunk_header: ResChunkHeader):
    return XmlEndNamespace.parse(file, chunk_header)


def process_xml_start_element(file, chunk_header: ResChunkHeader):
    return XmlStartElement.parse(file, chunk_header)


def process_xml_end_element(file, chunk_header: ResChunkHeader):
    return XmlEndElement.parse(file, chunk_header)


chunk_type_handlers = {
    '0x180': process_xml_resource_map,      # RES_XML_RESOURCE_MAP_TYPE
    '0x100': process_xml_start_namespace,   # RES_XML_START_NAMESPACE_TYPE
    '0x102': process_xml_start_element,     # RES_XML_START_ELEMENT_TYPE
    '0x103': process_xml_end_element,       # RES_XML_END_ELEMENT_TYPE
    '0x101': process_xml_end_namespace,      # RES_XML_END_NAMESPACE_TYPE
}


def parse_next_header(file):
    """
    Dispatcher method to parse the next available header. It takes into account to move on past the header if it
    contains extra info besides the standard ones.
    The dispatcher automatically picks the correct processing method for each chunk type.
    :param file: the xml file that is being read
    :return: Dispatches to the appropriate processing method for each chunk type.
    """
    chunk_header = ResChunkHeader.from_file(file)
    if chunk_header is None:  # end of file
        return None
    if chunk_header.header_size > 8:
        # read the rest of the header
        file.read(chunk_header.header_size - 8)
    chunk_type = hex(chunk_header.type)
    if chunk_type in chunk_type_handlers:
        return chunk_type_handlers[chunk_type](file, chunk_header)
    else:
        raise NotImplementedError(f"Unsupported chunk type: {chunk_type}")


def process_headers(file):
    """
    It starts processing the remaining headers after the string pool chunk.
    Takes into account that the resource map, the start namespace and end namespace chunks are only to be found once
    within the file.
    :param file: the xml file after the string pool chunk
    :return: Returns all the elements found as their corresponding classes
    """
    elements = []
    possible_headers = {b'\x80\x01', b'\x00\x01', b'\x02\x01', b'\x03\x01', b'\x01\x01'}
    while True:
        # Parse the next header
        cur_pos = file.tell()
        check = file.read(2)
        file.seek(cur_pos)
        if not check:
            # End of file
            break
        if check not in possible_headers:
            file.read(1)
            continue
        chunk_type = parse_next_header(file)
        elements.append(chunk_type)
        if check in {b'\x80\x01', b'\x00\x01', b'\x01\x01'}:
            possible_headers.remove(check)
    return elements


def get_manifest(elements, string_data):
    """
    Method to go over all elements and attempt to create the AndroidManifest.xml file.
    :param elements: Elements as retrieved from process_headers()
    :param string_data: The string data contained within the string pool
    :return: Returns the string of the AndroidManifest.xml
    """
    android_manifest_xml = '<?xml version="1.0" encoding="utf-8"?>\n'
    namespace = ""
    for element in elements:
        if isinstance(element, XmlStartNamespace):
            namespace = f'xmlns:{string_data[element.ext[0]]}="{string_data[element.ext[1]]}"'
        elif isinstance(element, XmlStartElement):
            ln_list = []
            for attr in element.attributes:
                if attr.typed_value_datatype == 1:  # reference type
                    name = string_data[attr.name_index]
                    value = f"@{attr.typed_value_data}"
                elif attr.typed_value_datatype == 3:  # string type
                    name = string_data[attr.name_index]
                    try:
                        value = string_data[attr.typed_value_data]
                    except:
                        value = attr.typed_value_data
                elif attr.typed_value_datatype == 16:  # integer type
                    name = string_data[attr.name_index]
                    value = attr.typed_value_data
                elif attr.typed_value_datatype == 17:  # int-hex type
                    name = string_data[attr.name_index]
                    value = f"{attr.typed_value_data} ({hex(attr.typed_value_data)})"
                elif attr.typed_value_datatype == 18:  # boolean type
                    name = string_data[attr.name_index]
                    value = "true" if bool(attr.typed_value_data) else "false"
                else:
                    print(f"An unknown datatype came up: {attr.typed_value_datatype}")
                ln_list.append(f'android:{name}="{value}"')
            if ln_list:
                if string_data[element.attrext[1]] == "manifest":
                    android_manifest_xml += f"<{string_data[element.attrext[1]]} {namespace} {' '.join(ln_list)}>\n"
                else:
                    android_manifest_xml += f"<{string_data[element.attrext[1]]} {' '.join(ln_list)}>\n"
            else:
                android_manifest_xml += f"<{string_data[element.attrext[1]]}>\n"
        elif isinstance(element, XmlEndElement):
            name = string_data[element.attrext[1]]
            if name == "manifest":
                android_manifest_xml += f"</{string_data[element.attrext[1]]}>"
            else:
                android_manifest_xml += f"</{string_data[element.attrext[1]]}>\n"
    return android_manifest_xml


# def beautify_validate_xml(xml_string):
#     import xml.etree.ElementTree as ET
#     ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
#     root = ET.fromstring(xml_string)
#     xml_pretty = ET.tostring(root, encoding='utf-8', method='xml').decode("utf-8")
#     return xml_pretty



