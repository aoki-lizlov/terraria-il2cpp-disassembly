import idaapi
import idautils
import idc
import ida_kernwin
import ida_name
import ida_hexrays
import ida_xref
import os
import re
import json
import subprocess

def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|?*]', '_', name)

def sanitize_c_identifier(name):
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name and name[0].isdigit():
        name = '_' + name
    return name

def extract_simple_name(demangled):
    if not demangled:
        return None
    parts = demangled.replace("(", " ").split()
    if parts:
        full_path = parts[0]
        path_parts = full_path.split("::")
        return path_parts[-1]
    return None

def parse_c_signature(signature):
    if not signature:
        return "void", []

    match = re.match(r'(.+?)\s+\w+\s*\((.*?)\)', signature)
    if not match:
        return "void", []

    return_type = match.group(1).strip()
    params_str = match.group(2).strip()

    if not params_str or params_str == "void":
        params = []
    else:
        params = [p.strip() for p in params_str.split(',')]

    return return_type, params

def get_pseudocode(func_ea):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            return str(cfunc)
    except:
        pass
    print("  pseudocode fetch failed")
    return None

def get_xrefs(func_ea):
    xrefs_to = []
    xrefs_from = []

    for xref in idautils.XrefsTo(func_ea, 0):
        caller_name = idc.get_func_name(xref.frm)
        if caller_name:
            demangled = ida_name.demangle_name(caller_name, idc.get_inf_attr(idc.INF_SHORT_DN))
            xrefs_to.append({
                "address": f"0x{xref.frm:X}",
                "mangledName": caller_name,
                "demangledName": demangled if demangled else caller_name
            })

    for xref in idautils.XrefsFrom(func_ea, 0):
        callee_name = idc.get_func_name(xref.to)
        if callee_name:
            demangled = ida_name.demangle_name(callee_name, idc.get_inf_attr(idc.INF_SHORT_DN))
            xrefs_from.append({
                "address": f"0x{xref.to:X}",
                "mangledName": callee_name,
                "demangledName": demangled if demangled else callee_name
            })

    return xrefs_to, xrefs_from

metadata_file = ida_kernwin.ask_file(0, "*.json", "select metadata JSON file:")
if not metadata_file:
    print("no metadata file selected")
else:
    output_dir = ida_kernwin.ask_str("dasm", 0, "enter output directory:")
    if not output_dir:
        output_dir = "dasm"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(metadata_file, "r") as f:
        metadata = json.load(f)

    addr_to_metadata = {}
    for method in metadata.get("addressMap", {}).get("methodDefinitions", []):
        addr = int(method["virtualAddress"], 16)
        method["isConstructedGeneric"] = False
        addr_to_metadata[addr] = method

    for method in metadata.get("addressMap", {}).get("constructedGenericMethods", []):
        addr = int(method["virtualAddress"], 16)
        method["isConstructedGeneric"] = True
        addr_to_metadata[addr] = method

    groups = {}

    total_funcs = len(list(idautils.Functions()))
    current = 0

    for func_ea in idautils.Functions():
        current += 1
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        func_name = idc.get_func_name(func_ea)
        demangled = ida_name.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        simple_name = extract_simple_name(demangled)

        if func_ea in addr_to_metadata:
            meta = addr_to_metadata[func_ea]
            group = meta["group"]

            if group not in groups:
                groups[group] = []

            groups[group].append({
                "ea": func_ea,
                "func": func,
                "name": func_name,
                "demangled": demangled,
                "simple_name": simple_name if simple_name else func_name,
                "meta": meta
            })

            print(f"[{current}/{total_funcs}] grouped {func_name} -> {group}")
        else:
            if demangled:
                parts = demangled.replace("(", " ").split()
                if parts:
                    full_path = parts[0]
                    path_parts = full_path.split("::")

                    if len(path_parts) > 1:
                        group = "::".join(path_parts[:-1])
                    else:
                        group = "Global"
                else:
                    group = "Global"
            else:
                group = "Global"

            if group not in groups:
                groups[group] = []

            groups[group].append({
                "ea": func_ea,
                "func": func,
                "name": func_name,
                "demangled": demangled,
                "simple_name": simple_name if simple_name else func_name,
                "meta": None
            })

            print(f"[{current}/{total_funcs}] grouped {func_name} -> {group}")

    total_funcs = sum(len(funcs) for funcs in groups.values())
    current = 0

    for group, functions in groups.items():
        if ida_kernwin.user_cancelled():
            break

        parts = group.split("/")
        if len(parts) > 1:
            assembly = parts[0]
            class_path = "/".join(parts[1:])

            subdir_parts = [sanitize_filename(p) for p in parts]
            subdir = os.path.join(output_dir, *subdir_parts)
        else:
            assembly = "Unknown"
            class_path = group
            subdir = os.path.join(output_dir, sanitize_filename(group))

        if not os.path.exists(subdir):
            os.makedirs(subdir)

        safe_group = sanitize_filename(parts[-1] if parts else group)
        filename = f"{safe_group}.c"
        filepath = f"{subdir}.c"

        if group != "Global" and ".dll" not in group: continue

        print(f"writing {group} ({len(functions)} methods)")

        with open(filepath, "w") as f:
            file_metadata = {
                "assembly": assembly,
                "class": class_path,
                "functionCount": len(functions)
            }

            f.write(f"/**\n")
            f.write(f" * @file {safe_group}.c\n")
            f.write(f" * ### File metadata\n")
            f.write(f" * @code\n")
            for line in json.dumps(file_metadata, indent=2).split('\n'):
                f.write(f" * {line}\n")
            f.write(f" * @endcode\n")
            f.write(f" */\n\n")

            for func_data in functions:
                current += 1
                if ida_kernwin.user_cancelled():
                    break

                func_ea = func_data["ea"]
                func = func_data["func"]
                func_name = func_data["name"]
                func_demangled = func_data["demangled"]
                simple_name = func_data["simple_name"]
                meta = func_data["meta"]

                safe_func_name = sanitize_c_identifier(simple_name)

                return_type = "void"
                params = []

                if meta and meta.get("signature"):
                    return_type, params = parse_c_signature(meta["signature"])

                print(f"[{current}/{total_funcs}] on 0x{func_ea:X}: {func_demangled if func_demangled else func_name}")

                xrefs_to, xrefs_from = get_xrefs(func_ea)

                func_metadata = {
                    "address": f"0x{func_ea:X}",
                    "mangledName": func_name,
                    "demangledName": func_demangled if func_demangled else func_name,
                    "xrefs": {
                        "calledBy": xrefs_to,
                        "calls": xrefs_from
                    }
                }

                if meta:
                    func_metadata["cSignature"] = meta.get("signature")
                    func_metadata["dotNetSignature"] = meta.get("dotNetSignature")
                    func_metadata["group"] = meta.get("group")
                    func_metadata["isConstructedGeneric"] = meta.get("isConstructedGeneric", False)

                f.write(f"/**\n")
                f.write(f" * ### Metadata\n")
                f.write(f" * @code\n")
                for line in json.dumps(func_metadata, indent=2).split('\n'):
                    f.write(f" * {line}\n")
                f.write(f" * @endcode\n")

                pseudocode = get_pseudocode(func_ea)
                if pseudocode:
                    f.write(f" * ### Pseudocode\n")
                    f.write(f" * @code\n")
                    for line in pseudocode.split('\n'):
                        f.write(f" * {line}\n")
                    f.write(f" * @endcode\n")
                else:
                    f.write(f" * ### Pseudocode\n")
                    f.write(f" * @code\n")
                    f.write(f" * Unavailable, only pseudocodes for <16KB (of machine code) functions are generated\n")
                    f.write(f" * @endcode\n")

                f.write(" * ### Disassembly\n")
                f.write(" * @code\n")
                asm_lines = []
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    disasm = idc.generate_disasm_line(head, 0)
                    asm_lines.append(f' * {disasm}')

                f.write("\n".join(asm_lines))
                f.write("\n * @endcode\n")

                if params:
                    params_str = ", ".join(params)
                else:
                    params_str = "void"
                f.write(f"{return_type} {safe_func_name}({params_str});\n")

    print(f"\nexported {len(groups)} groups, {current} functions")

    subprocess.run(["find", output_dir, "-type", "d", "-empty", "-delete"])

