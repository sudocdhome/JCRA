#!/usr/bin/python3

import sys
import json
from zipfile import ZipFile

"""
"""


def b2i(bytes, endianes="big"):
    return int.from_bytes(bytes, "big")


class CAPFileParser:
    def __init__(self):
        self.cap_json = dict()
        self.is_extended = False

    @staticmethod
    def get_components(cap_file_path):
        cap_archive = ZipFile(cap_file_path, "r")
        components = dict()
        for path in cap_archive.namelist():
            if path.lower().endswith(".cap") or path.lower().endswith(".capx"):
                components[path.split("/")[-1].lower()] = {
                    "raw": cap_archive.read(path)
                }
        return components

    @staticmethod
    def get_cap_file_flags(flags):
        _flags = list()
        if flags & 0x01:
            _flags.append("ACC_INT")
        if flags & 0x02:
            _flags.append("ACC_EXPORT")
        if flags & 0x04:
            _flags.append("ACC_APPLET")
        if flags & 0x08:
            _flags.append("ACC_EXTENDED")
            self.is_extended = True
        return _flags

    def parse_header_component(self):
        header = self.cap["header.cap"]
        raw_data = header["raw"]

        header["tag"] = raw_data[0]
        header["size"] = b2i(raw_data[1:3])
        header["magic"] = raw_data[3:7].hex()
        header["CAP_format_version"] = f"{raw_data[8]}.{raw_data[7]}"
        header["flags"] = self.get_cap_file_flags(raw_data[9])

        offset = 10
        if self.is_extended:
            header["CAP_format_version"] = f"{raw_data[11]}.{raw_data[10]}"
            offset += 2
            aid_len = raw_data[offset]
            header["cap_aid_len"] = aid_len
            offset += 1
            header["aid"] = raw_data[offset : offset + aid_len].hex()
            offset += aid_len
            header["packages_count"] = raw_data[offset]
            offset += 1
            header["packages"] = list()
            for _ in range(header["packages_count"]):
                header["packages"].append(dict())
                header["packages"][-1][
                    "version"
                ] = f"{raw_data[offset+1]}.{raw_data[offset]}"
                offset += 2
                aid_len = raw_data[offset]
                header["packages"][-1]["aid_len"] = aid_len
                offset += 1
                header["packages"][-1]["aid"] = raw_data[
                    offset : offset + aid_len
                ].hex()
                offset += aid_len

            for index in range(header["packages_count"]):
                package_name_len = raw_data[offset]
                offset += 1
                package_name = raw_data[offset : offset + package_name_len].decode()
                offset += package_name_len
                header["packages"][index]["package_name"] = {
                    "length": package_name_len,
                    "name": package_name,
                }

        else:
            header["package"] = {"version": f"{raw_data[offset+1]}.{raw_data[offset]}"}
            offset += 2
            aid_len = raw_data[offset]
            header["package"]["aid_len"] = aid_len
            offset += 1
            header["package"]["aid"] = raw_data[offset : offset + aid_len].hex()
            offset += aid_len
            package_name_len = raw_data[offset]
            offset += 1
            package_name = raw_data[offset : offset + package_name_len].decode()
            offset += package_name_len
            header["package"]["package_name"] = {
                "length": package_name_len,
                "name": package_name,
            }

        header["raw"] = raw_data.hex()

    def parse_directory_component(self):
        directory = self.cap["directory.cap"]
        raw_data = directory["raw"]

        directory["tag"] = raw_data[0]
        directory["size"] = b2i(raw_data[1:3])
        offset = 3

        directory["component_sizes"] = dict()
        directory["component_sizes"]["header"] = b2i(raw_data[offset : offset + 2])
        directory["component_sizes"]["directory"] = b2i(
            raw_data[offset + 2 : offset + 4]
        )
        directory["component_sizes"]["applet"] = b2i(raw_data[offset + 4 : offset + 6])

        directory["component_sizes"]["import"] = b2i(raw_data[offset + 6 : offset + 8])
        directory["component_sizes"]["constant_pool"] = b2i(
            raw_data[offset + 8 : offset + 10]
        )
        directory["component_sizes"]["class"] = b2i(raw_data[offset + 10 : offset + 12])
        offset += 12
        format_dependent_length = 4 if self.is_extended else 2
        directory["component_sizes"]["method"] = b2i(
            raw_data[offset : offset + format_dependent_length]
        )
        offset += format_dependent_length
        directory["component_sizes"]["static_field"] = b2i(
            raw_data[offset : offset + format_dependent_length]
        )
        directory["component_sizes"]["reference_location"] = b2i(
            raw_data[offset : offset + 2]
        )
        offset += 2
        directory["component_sizes"]["export"] = b2i(raw_data[offset : offset + 2])
        offset += 2
        directory["component_sizes"]["descriptor"] = b2i(
            raw_data[offset : offset + format_dependent_length]
        )
        offset += format_dependent_length
        directory["component_sizes"]["debug"] = b2i(
            raw_data[offset : offset + format_dependent_length]
        )
        offset += format_dependent_length
        directory["component_sizes"]["static_resources"] = b2i(
            raw_data[offset : offset + 4]
        )

        directory["raw"] = raw_data.hex()

    def parse_applet_component(self):
        applet = self.cap["applet.cap"]
        raw_data = applet["raw"]

        applet["tag"] = raw_data[0]
        applet["size"] = b2i(raw_data[1:3])
        applet["count"] = raw_data[3]
        offset = 4

        applet["applets"] = list()
        for _ in range(applet["count"]):
            applet["applets"].append(dict())
            aid_len = raw_data[offset]
            applet["applets"][-1]["aid_len"] = aid_len
            offset += 1
            applet["applets"][-1]["aid"] = raw_data[offset : offset + aid_len].hex()
            if self.is_extended:
                applet["applets"][-1][
                    "install_method_component_block_index"
                ] = raw_data[offset]
                offset += 1
            applet["applets"][-1]["install_method_offset"] = raw_data[offset]

        applet["raw"] = raw_data.hex()

    def parse_import_component(self):
        _import = self.cap["import.cap"]
        raw_data = _import["raw"]

        _import["tag"] = raw_data[0]
        _import["size"] = b2i(raw_data[1:3])
        _import["count"] = raw_data[3]
        offset = 4

        _import["packages"] = list()
        for _ in range(_import["count"]):
            _import["packages"].append(dict())
            _import["packages"][-1][
                "version"
            ] = f"{raw_data[offset+1]}.{raw_data[offset]}"
            offset += 2
            aid_len = raw_data[offset]
            _import["packages"][-1]["aid_len"] = aid_len
            offset += 1
            _import["packages"][-1]["aid"] = raw_data[
                offset : offset + aid_len
            ].hex()
            offset += aid_len

        _import["raw"] = raw_data.hex()

    def parse_constantpool_component(self):
        constantpool = self.cap["constantpool.cap"]
        raw_data = constantpool["raw"]

        constantpool["tag"] = raw_data[0]
        constantpool["size"] = b2i(raw_data[1:3])
        constantpool["count"] = b2i(raw_data[3:5])
        offset = 5

        constantpool["cp_info"] = list()
        for _ in range(constantpool["count"]):
            constantpool["cp_info"].append(dict())
            constantpool["cp_info"][-1]["tag"] = raw_data[offset]
            offset += 1
            constantpool["cp_info"][-1]["info"] = raw_data[offset:offset+3].hex()
            offset += 3

        constantpool["raw"] = raw_data.hex()

    def parse_class_component(self):
        _class = self.cap["class.cap"]
        raw_data = _class["raw"]

        _class["tag"] = raw_data[0]
        _class["size"] = b2i(raw_data[1:3])
        _class["signature_pool_length"] = b2i(raw_data[3:5])
        offset = 5

        _class["signature_pool"] = list()
        for _ in range(_class["count"]):
            _class["signature_pool"].append(dict())
            _class["signature_pool"][-1]["nibble_count"] = raw_data[offset]
            type_length = int((raw_data[offset] + 1)/2)
            offset += 1
            _class["signature_pool"][-1]["type"] = raw_data[offset:offset+type_length].hex()
            offset += type_length

        _class["interfaces"] = list()
        for _ in range(_class["count"]):
            _class["interfaces"].append(dict())
            _class["interfaces"][-1]["nibble_count"] = raw_data[offset]
            type_length = int((raw_data[offset] + 1)/2)
            offset += 1
            _class["interfaces"][-1]["type"] = raw_data[offset:offset+type_length].hex()
            offset += type_length

        constantpool["raw"] = raw_data.hex()

    def parse(self, cap_file_path):
        self.cap = self.get_components(cap_file_path)
        self.parse_header_component()
        self.parse_directory_component()
        self.parse_applet_component()
        self.parse_import_component()
        self.parse_constantpool_component()
        self.parse_class_component()()
        self.cap["method.cap"]["raw"] = self.cap["method.cap"]["raw"].hex()
        self.cap["staticfield.cap"]["raw"] = self.cap["staticfield.cap"]["raw"].hex()
        self.cap["reflocation.cap"]["raw"] = self.cap["reflocation.cap"]["raw"].hex()
        self.cap["descriptor.cap"]["raw"] = self.cap["descriptor.cap"]["raw"].hex()
        print(json.dumps(self.cap, indent=4))


parser = CAPFileParser()
parser.parse(sys.argv[1])
