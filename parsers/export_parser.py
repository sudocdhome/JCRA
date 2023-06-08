#!/usr/bin/python3

import sys
import json

"""
|ExportFile {
|  u4 magic
|  u1 minor_version
|  u1 major_version
|
|  u2 constant_pool_count
|  cp_info [constant_pool_count]
|
|  u2 this_package ----> A valid index into the constant_pool; that index must be of type "PackageInfo";
|
|  u1 referenced_package_count (since Export File format 2.3)
|  u2 referenced_packages[referenced_package_count] (since ExportFile format 2.3) ----> An index into the constant_pool; that index must be of type "PackageInfo";
|
|  u1 export_class_count
|  class_info classes[export_class_count] ----> Gives the description of a publicly accessible class or interface declared in this package.
|}


    |cp_info {
    |  u1 tag      --------> 1: UTF8, 3: Integer, 7: ClassRef, 13: Package
    |  u1 info[]
    |}


        |CONSTANT_Utf8_info {
        |  u1 tag
        |  u2 length
        |  u1 bytes[length]
        |}
        
        |CONSTANT_Integer_info {
        |  u1 tag
        |  u4 bytes
        |}

        |CONSTANT_Classref_info { <--- It can be either a class or an interface
        |  u1 tag
        |  u2 name_index ----> UTF8 type entry in constant pool
        |}

        |CONSTANT_Package_info {
        |  u1 tag
        |  u1 flags
        |  u2 name_index ----> A valid index into the constant_pool; that index must be of type "UTF8";
        |  u1 minor_version
        |  u1 major_version
        |  u1 aid_length
        |  u1 aid[aid_length]
        |}

    |class_info {
    |  u1 token
    |  u2 access_flags
    |  u2 name_index
    |
    |  u2 export_supers_count
    |  u2 supers[export_supers_count]
    |
    |  u1 export_interfaces_count
    |  u2 interfaces[export_interfaces_count]
    |
    |  u2 export_fields_count
    |  field_info fields[export_fields_count]
    |
    |  u2 export_methods_count
    |  method_info methods[export_methods_count]
    |
    |  u1 CAP22_inheritable_public_method_token_count (since Export File format 2.3)
    |}

        |field_info {
        |  u1 token
        |  u2 access_flags
        |  u2 name_index
        |  u2 descriptor_index
        |  u2 attributes_count
        |  attribute_info attributes[attributes_count]
        |}

            |attribute_info {
            |  u2 attribute_name_index
            |  u4 attribute_length
            |  u1 info[attribute_length]
            |}

        |method_info {
        |  u1 token
        |  u2 access_flags
        |  u2 name_index
        |  u2 descriptor_index
        |}
"""

class ExportFileParser:

  def __init__(self, export_file_path):
    self.export_json = dict()
    self.export_file = bytes(open(export_file_path, "rb").read())
    self.offset = 0
    magic = self.export_file[:4].hex()
    self.offset = 4
    self.version = f"{self.export_file[5]}.{self.export_file[4]}"
    self.offset = 6

    self.export_json["magic"] = magic
    self.export_json["version"] = self.version

  @staticmethod
  def get_access_modifiers(flags):
    access_modifiers = list()
    
    if flags & 0x0001:
      access_modifiers.append("Public")
    if flags & 0x0010:
      access_modifiers.append("Final")
    if flags & 0x0200:
      access_modifiers.append("Interface")
    if flags & 0x0400:
      access_modifiers.append("Abstract")
    if flags & 0x0800:
      access_modifiers.append("Shareable")
    if flags & 0x1000:
      access_modifiers.append("Remote")
    
    if flags & 0x0004:
      access_modifiers.append("Protected")
    if flags & 0x0008:
      access_modifiers.append("Static")

    return "-".join(access_modifiers)

  def cp_utf8_parser(self):
    length = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    string = self.export_file[self.offset:self.offset+length].decode()
    self.offset += length

    self.export_json["constant_pool"][-1]["type"] = "utf8"
    self.export_json["constant_pool"][-1]["string"] = string

  def cp_integer_parser(self):
    integer = int.from_bytes(self.export_file[self.offset:self.offset+4], "big")
    self.offset += 4

    self.export_json["constant_pool"][  -1]["type"] = "integer"
    self.export_json["constant_pool"][-1]["integer"] = hex(integer)

  def cp_classref_parser(self):
    name_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2

    self.export_json["constant_pool"][-1]["type"] = "classRef"
    self.export_json["constant_pool"][-1]["name_index"] = name_index

  def cp_package_parser(self):
    flags = self.export_file[self.offset]
    self.offset += 1
    name_index = int.from_bytes(self.export_file[self.offset: self.offset+2], "big")
    self.offset += 2
    major_minor_version = f"{self.export_file[self.offset+1]}.{self.export_file[self.offset]}"
    self.offset += 2
    aid_len = self.export_file[self.offset]
    self.offset += 1
    package_aid = self.export_file[self.offset:self.offset+aid_len].hex()
    self.offset += aid_len

    self.export_json["constant_pool"][-1]["type"] = "packageInfo"
    self.export_json["constant_pool"][-1]["flags"] = {0: "Applet-Package", 1: "Library-Pakcage"}[flags]
    self.export_json["constant_pool"][-1]["name_index"] = name_index
    self.export_json["constant_pool"][-1]["package_version"] = major_minor_version
    self.export_json["constant_pool"][-1]["aid_len"] = aid_len
    self.export_json["constant_pool"][-1]["package_aid"] = package_aid

  def method_info_parser(self):
    token = self.export_file[self.offset]
    self.offset += 1
    access_flags = self.get_access_modifiers(int.from_bytes(self.export_file[self.offset:self.offset+2], "big"))
    self.offset += 2
    name_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    descriptor_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2

    self.export_json["export_class"][-1]["export_methods"].append(dict())
    self.export_json["export_class"][-1]["export_methods"][-1]["token"] = token
    self.export_json["export_class"][-1]["export_methods"][-1]["access_flags"] = access_flags
    self.export_json["export_class"][-1]["export_methods"][-1]["name_index"] = name_index
    self.export_json["export_class"][-1]["export_methods"][-1]["descriptor_index"] = descriptor_index

  def field_info_parser(self):
    token = self.export_file[self.offset]
    self.offset += 1
    access_flags = self.get_access_modifiers(int.from_bytes(self.export_file[self.offset:self.offset+2], "big"))
    self.offset += 2
    name_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    descriptor_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    attribute_count = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2

    self.export_json["export_class"][-1]["export_fields"].append(dict())
    self.export_json["export_class"][-1]["export_fields"][-1]["token"] = token
    self.export_json["export_class"][-1]["export_fields"][-1]["access_flag"] = access_flags
    self.export_json["export_class"][-1]["export_fields"][-1]["name_index"] = name_index
    self.export_json["export_class"][-1]["export_fields"][-1]["descriptor_index"] = descriptor_index
    self.export_json["export_class"][-1]["export_fields"][-1]["attribute_count"] = attribute_count

    self.export_json["export_class"][-1]["export_fields"][-1]["attributes"] = list()
    for _ in range(attribute_count):
      attribute_name_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
      self.offset += 2
      attribute_length = int.from_bytes(self.export_file[self.offset:self.offset+4], "big")
      self.offset += 4
      info = self.export_file[self.offset:self.offset+attribute_length].hex()
      self.offset += attribute_length
      
      self.export_json["export_class"][-1]["export_fields"][-1]["attributes"].append(dict())
      self.export_json["export_class"][-1]["export_fields"][-1]["attributes"][-1]["attribute_name_index"] = attribute_name_index
      self.export_json["export_class"][-1]["export_fields"][-1]["attributes"][-1]["attribute_length"] = attribute_length
      self.export_json["export_class"][-1]["export_fields"][-1]["attributes"][-1]["info"] = info

  def class_info_parser(self):
    token = self.export_file[self.offset]
    self.offset += 1
    access_flags = self.get_access_modifiers(int.from_bytes(self.export_file[self.offset:self.offset+2], "big"))
    self.offset += 2
    name_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2

    self.export_json["export_class"][-1]["token"] = token
    self.export_json["export_class"][-1]["access_flags"] = access_flags
    self.export_json["export_class"][-1]["name_index"] = name_index

    export_supers_count = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    self.export_json["export_class"][-1]["export_supers_count"] = export_supers_count
    self.export_json["export_class"][-1]["export_supers"] = list()

    for _ in range(export_supers_count):
      super_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
      self.offset += 2
      self.export_json["export_class"][-1]["export_supers"].append(super_index)
    
    export_interfaces_count = self.export_file[self.offset]
    self.offset += 1
    self.export_json["export_class"][-1]["export_interfaces_count"] = export_interfaces_count
    self.export_json["export_class"][-1]["export_interfaces"] = list()

    for _ in range(export_interfaces_count):
      export_interface_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
      self.offset += 2
      self.export_json["export_class"][-1]["export_interfaces"].append(export_interface_index)

    export_fields_count = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    self.export_json["export_class"][-1]["export_fields_count"] = export_fields_count
    self.export_json["export_class"][-1]["export_fields"] = list()
    for _ in range(export_fields_count):
      self.field_info_parser()
    
    export_methods_count = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    self.export_json["export_class"][-1]["export_methods_count"] = export_methods_count
    self.export_json["export_class"][-1]["export_methods"] = list()
    for _ in range(export_methods_count):
      self.method_info_parser()

    if self.version == "2.3":
      CAP22_inheritable_public_method_token_count = self.export_file[self.offset]
      self.offset += 1
      self.export_json["export_class"][-1]["CAP22_inheritable_public_method_token_count"] = CAP22_inheritable_public_method_token_count


  def parse(self):
    constant_pool_count = int.from_bytes(self.export_file[6:8], "big")
    self.offset = 8
    self.export_json["constant_pool_count"] = constant_pool_count
    self.export_json["constant_pool"] = list()

    for index in range(constant_pool_count):
      tag = self.export_file[self.offset]
      self.offset += 1
      self.export_json["constant_pool"].append(dict({"index": index, "tag":tag}))

      match tag:
        case 1: # UTF8
          self.cp_utf8_parser()
        case 3: # Integer
          self.cp_integer_parser()
        case 7: # ClassRef
          self.cp_classref_parser()
        case 13: # Package
          self.cp_package_parser()
        case _:
          print(f"Incorrect CP_INFO tag: {_}")
          exit()

    this_package = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
    self.offset += 2
    self.export_json["this_package"] = this_package

    if self.version == "2.3":
      referenced_packages_count = self.export_file[self.offset]
      self.offset += 1
      self.export_json["referenced_packages_count"] = referenced_packages_count

      self.export_json["referenced_packages"] = list()
      for _ in range(referenced_packages_count):
        referenced_package_index = int.from_bytes(self.export_file[self.offset:self.offset+2], "big")
        self.offset += 2
        self.export_json["referenced_packages"].append(referenced_package_index)


    export_class_count = self.export_file[self.offset]
    self.offset += 1
    self.export_json["export_class_count"] = export_class_count

    self.export_json["export_class"] = list()
    for _ in range(export_class_count):
      self.export_json["export_class"].append(dict())
      self.class_info_parser()

    print(json.dumps(self.export_json, indent=4))

parser = ExportFileParser(sys.argv[1])
parser.parse()
