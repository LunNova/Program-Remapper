from typing import Dict, List, Optional, Any, Tuple

import reloc_sections
import reloc_functions
import os
import shutil
import pickle
import skse_offset_finder
import boltons.setutils
from binja_dumper import Executable, ExeFunction, ExeSegment


def load_or_create(path, create):
    try:
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                return pickle.load(f)
    except Exception as e:
        print("Failed to load " + path + " " + str(e))

    with open(path, 'wb') as f:
        result = create()
        pickle.dump(result, f)
        return result


def map(address):
    r: reloc_sections.RelocationRange
    for r in moved_ranges:
        if r.original_start <= address < r.original_end:
            return address + (r.relocated_start - r.original_start)

    return None


def check_ranges_against_functions():
    # should be 0x1403a1190
    print(hex(map(0x1403b0800)))
    print(hex(map(0x1403b0830)))
    matched = 0
    mismatched = 0
    for match in moved_functions:
        mapped = map(match.b.address)
        if mapped is None:
            continue
        if mapped == match.a.address:
            matched += 1
        else:
            mismatched += 1
    print(f"matched {matched}  mismatched {mismatched}")
    print("Moved_ranges " + str([str(x) for x in moved_ranges]))

# Skyrim SE 1.5.39 (with creation club)
# original_version = [1, 5, 39, 0]
# original = '../Unpacked/SkyrimSE - 1.5.39.0.exe.unpacked.exe'
# skse_original = "../skse64_2_00_07/"
# skse_from = "skse64_2_00_07"

# Skyrim SE 1.4.2 (without creation club)
original_version = [1, 4, 2, 0]
original = '../Unpacked/SkyrimSE - 1.4.2.0.exe.unpacked.exe'
skse_original = "../skse64_2_00_02/"
skse_from = "skse64_2_00_02"

# Skyrim VR 1.3.64 (first patch release)
target_version = [1, 3, 64, 0]
target = '../Unpacked/SkyrimVR - 1.3.64.0.exe.unpacked.exe'

original_version_str = '.'.join([str(x) for x in original_version])
target_version_str = '.'.join([str(x) for x in target_version])
combo_version_str = f"{original_version_str}-{target_version_str}"

cache_prefix = f"cache/{combo_version_str}-"

# moved ranges too broken currently...
# moved_ranges = load_or_create("cache/moved_ranges.obj", lambda: reloc_sections.find_moved(original, target))
moved_functions: reloc_functions.Matches = load_or_create(cache_prefix + "moved_functions.obj",
                                                          lambda: reloc_functions.find_moved_functions(original,
                                                                                                       target))
# moved_functions = reloc_functions.find_moved_functions(original, target)

skse_to = "skseVR-" + combo_version_str
skse_target = skse_original.replace(skse_from, skse_to)

try:
    os.mkdir(skse_target)
except FileExistsError:
    pass

if os.path.isdir(skse_target):
    shutil.rmtree(skse_target, ignore_errors=True)


# shutil.copytree(skse_original, skse_target)

def map_functions(fns: List[ExeFunction]) -> Dict[int, ExeFunction]:
    return {fn.address: fn for fn in fns}


# moved_functions = reloc_functions.find_moved_functions(original, target)

offset = 0x140000000


def map_function(address):
    address += offset
    if address in original_functions:
        fn = original_functions[address]
        if fn.match:
            return hex(fn.match.address - offset)
        if fn.prev.match and fn.next.match and fn.prev.match.next.next.match == fn.next:
            print("\tBetween for " + hex(address))
            return hex(fn.prev.match.next.address - offset)
    return None


replacements = {
    r"\\My Games\\Skyrim Special Edition\\SKSE\\": r"\\My Games\\Skyrim VR\\SKSE\\",
    "_1_5_39": "_vr_1_3_64",
    "1_5_39": "1_3_64",
}


def hex(arg):
    return f"0x{arg:0{8}X}"


for fn in skse_offset_finder.find_all_functions(skse_original):
    (clazz, name, address, address_string) = fn
    if address == 0:
        continue
    address += offset
    if address not in moved_functions.dict_a:
        print("\t" + clazz + " " + name + " " + hex(address) + " MISSING")
        continue
    mapped = moved_functions.map(address)
    if mapped is None:
        print("\t" + clazz + " " + name + " " + hex(address) + " NONE")
        try:
            # moved_functions.dump(address)
            print("\t" + hex(moved_functions.dict_a[address].prev.match.address))
            print("\t" + hex(moved_functions.dict_a[address].next.match.address))
        except:
            pass
    else:
        replacements[address_string] = hex(mapped - offset)
        print(clazz + " " + name + " " + hex(address) + " " + hex(mapped))


def dv_map(dv_refs: List[Tuple[int, int, int]]):
    matches = []
    mapped_dv_addresses = boltons.setutils.IndexedSet()
    for dv in dv_refs:
        function_start, function_reference_address, dv_address = dv
        offset = function_reference_address - function_start

        mapped = moved_functions.map(function_start)
        if not mapped:
            return None

        if mapped not in moved_functions.data_vars_b:
            print(f"\t\tSuspect mapping {hex(function_start)} -> {hex(mapped)}")
            continue

        dv_refs_b = moved_functions.data_vars_b[mapped]
        for dv_b in dv_refs_b:
            function_start_b, function_reference_address_b, dv_address_b = dv_b
            offset_b = function_reference_address_b - function_start_b
            if offset_b == offset:
                # print(f"Match! {dv} == {dv_b}")
                matches.append((dv, dv_b))
                mapped_dv_addresses.add(dv_address_b)

        if map:
            function_start = mapped

    if len(mapped_dv_addresses) != 1:
        print(f"Multiple results {' '.join([hex(x) for x in mapped_dv_addresses])}")
    else:
        return mapped_dv_addresses[0]


for ptr in skse_offset_finder.find_all_ptrs(skse_original):
    print(ptr)
    address = int(ptr[1], 16)
    if address == 0:
        print("\tNULL")
        continue
    address += offset
    result = None

    if address in moved_functions.dict_a:
        mapped = moved_functions.map(address)
        if not mapped:
            moved_functions.dump(address, 'a')
            # 0x1405ad0d0 is not mapped, should map to
            # moved_functions.dump(0x1405b40d0, 'b')
            continue
        result = mapped
    elif address in moved_functions.data_vars_a:
        result = dv_map(moved_functions.data_vars_a[address])
    else:
        print("\tnot in data vars or functions!")

    if result:
        replacements[ptr[1]] = hex(result - offset)

file_replacements = {
    "IdentifyEXE.cpp": {
        "version < kCurVersion": "versionInternal < kCurVersion",
        "version > kCurVersion": "versionInternal > kCurVersion",
        "0x0001000500270000": "MAKE_EXE_VERSION(1, 3, 64)",
    },
    "main.cpp": {
        r"\\skse64_": r"\\skse64_vr_",
        "SkyrimSE.exe": "SkyrimVR.exe",
    }
}

for root, dirs, files in os.walk(skse_original):
    for file in files:
        path = os.path.join(root, file)
        target_path = path.replace(skse_from, skse_to)
        if not os.path.isfile(target_path):
            try:
                os.makedirs(os.path.dirname(target_path))
            except FileExistsError:
                pass
            shutil.copy2(path, target_path)
            file_name = os.path.basename(target_path)
            file_extension = os.path.splitext(file_name)[1]
            if file_extension in ['.cpp', '.h', '.vcxproj'] or file_name in file_replacements:
                with open(target_path, 'r') as f:
                    contents: str = f.read()
                r_contents = contents
                for old, new in replacements.items():
                    r_contents = r_contents.replace(old, new)
                if file_name in file_replacements:
                    for old, new in file_replacements[file_name].items():
                        r_contents = r_contents.replace(old, new)
                if r_contents == contents:
                    continue
                # print("Replacing in " + target_path)
                with open(target_path, 'w') as f:
                    f.write(r_contents)
# SkyrimSE method which does Loading game... then calls
# LoadRegSleepEventHandles_Internal 0x140930230
# moved_functions.dump(0x14092f4e0, 'a')
# moved_functions.dump(0x140966e30, 'b')
# moved_functions.dump(0x140930230, 'a')
# moved_functions.dump(0x140967b80, 'b')

# moved_functions.dump(0x1411b8de0, 'a')
# moved_functions.dump(0x1411b8e00, 'a')
# Impl_FN10 A
moved_functions.dump(0x141267ed0, 'a')
# IMpl_FN10 B
moved_functions.dump(0x14129a450, 'b')

print("Loaded")
