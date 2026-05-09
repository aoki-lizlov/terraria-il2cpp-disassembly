import idaapi
import idautils
import idc
import ida_kernwin
import ida_typeinf
import os
import re
import json

def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|?*]', '_', name)

def get_index_path(type_name):
    safe_name = sanitize_filename(type_name)

    if len(safe_name) == 0:
        return ["_", "_"]
    elif len(safe_name) == 1:
        return [safe_name[0].upper(), "_"]
    else:
        return [safe_name[0].upper(), safe_name[1].upper()]

def is_il2cpp_special(type_name):
    il2cpp_suffixes = ["__Boxed", "__Array", "__Fields", "__VTable", "__StaticFields", "__Class", "__Enum"]
    for suffix in il2cpp_suffixes:
        if type_name.endswith(suffix):
            return True, suffix
    return False, None

output_dir = ida_kernwin.ask_str("types", 0, "enter output directory:")
if not output_dir:
    output_dir = "types"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

til = ida_typeinf.get_idati()

ordinal = 1
total_types = ida_typeinf.get_ordinal_count(til)
current = 0

while True:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(til, ordinal):
        ordinal += 1
        if ordinal > 100000:
            break
        continue

    type_name = tif.get_type_name()
    if not type_name:
        ordinal += 1
        continue

    index_path = get_index_path(type_name)
    type_dir = os.path.join(output_dir, index_path[0], index_path[1])

    if not os.path.exists(type_dir):
        os.makedirs(type_dir)

    safe_name = sanitize_filename(type_name)
    filepath = os.path.join(type_dir, f"{safe_name}.h")

    type_str = str(tif)
    type_size = tif.get_size()

    is_special, special_suffix = is_il2cpp_special(type_name)

    type_metadata = {
        "name": type_name,
        "ordinal": ordinal,
        "size": type_size if type_size != idaapi.BADSIZE else None,
        "isStruct": tif.is_struct(),
        "isUnion": tif.is_union(),
        "isEnum": tif.is_enum(),
        "isPtr": tif.is_ptr(),
        "isArray": tif.is_array(),
        "isFunc": tif.is_func(),
        "isTypedef": tif.is_typedef(),
    }

    current += 1
    print(f"[{current}/{total_types}] on {type_name}")

    with open(filepath, "w") as f:
        f.write("/**\n")
        f.write(f" * @file {safe_name}.h\n")
        f.write(" *\n")
        f.write(" * ### File metadata\n")
        f.write(" * @code\n")
        for line in json.dumps(type_metadata, indent=2).split('\n'):
            f.write(f" * {line}\n")
        f.write(" * @endcode\n")
        f.write(" */\n\n")

        if tif.is_struct() or tif.is_union():
            udt_data = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt_data):
                if tif.is_union():
                    f.write(f"union {type_name} {{\n")
                else:
                    f.write(f"struct {type_name} {{\n")

                for i in range(udt_data.size()):
                    member = udt_data[i]
                    member_name = member.name
                    member_type = str(member.type)
                    member_offset = member.offset // 8
                    member_size = member.size // 8

                    if is_special:
                        f.write(f"    {member_type} {member_name}; /**< offset: 0x{member_offset:X}, size: 0x{member_size:X} */\n")
                    else:
                        f.write(f"    {member_type} {member_name}; ///< offset: 0x{member_offset:X}, size: 0x{member_size:X}\n")

                f.write("};\n")
            else:
                f.write(f"{type_str};\n")

        elif tif.is_enum():
            enum_data = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(enum_data):
                f.write(f"enum {type_name} {{\n")

                for i in range(enum_data.size()):
                    member = enum_data[i]
                    f.write(f"    {member.name} = {member.value},\n")

                f.write("};\n")
            else:
                f.write(f"{type_str};\n")

        else:
            f.write(f"{type_str};\n")

    ordinal += 1

print(f"\nexported {current} types")

