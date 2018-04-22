#! python3
import re, glob, os

reFlags = re.RegexFlag.MULTILINE | re.RegexFlag.ASCII
memberFnPrefixRegex = re.compile(r'MEMBER_FN_PREFIX\s*?\(([^)]+)\)', reFlags)
memberFnRegex = re.compile(r'DEFINE_MEMBER_FN\s*?\(([^)]+)\)', reFlags)
pointerRegex = re.compile(r'(?:RelocPtr|RelocAddr)\s*?<[^>]+?>\s*?([^(\n\s;]+?)\s*?\(([^)]+)\)', reFlags)


def find_all_functions(path):
    functions = []
    for file in glob.glob(path + 'src/skse64/skse64/**/*.h', recursive=True):
        functions.extend(find_functions(file))
    return functions


def find_all_ptrs(path):
    pointers = []
    for file in glob.glob(path + 'src/skse64/skse64/**/*.h', recursive=True):
        pointers.extend(find_pointers(file))
    for file in glob.glob(path + 'src/skse64/skse64/**/*.cpp', recursive=True):
        pointers.extend(find_pointers(file))
    return pointers

def is_commented(string, pos):
    commentPos = string.rfind('//', max(0, pos - 50), pos)
    if commentPos == -1:
        return False
    # print(f"{commentPos} {pos}")
    # print(string[commentPos:pos])
    if string.find('\n', commentPos, pos) != -1:
        return False
    return True

def find_pointers(path: str):
    pointers = []
    with open(path, 'r') as f:
        contents = f.read()
        for result in pointerRegex.finditer(contents):
            address = result.group(2)
            offset = None
            if address.find('+') != -1:
                parts = address.split(' + ')
                address = parts[0]
                offset = parts[1]
            pointers.append((result.group(1).strip(), address, offset))
    return pointers


def find_functions(path: str):
    functions = []
    with open(path, 'r') as f:
        contents = f.read()
        for result in memberFnRegex.finditer(contents):
            args = result.group(1).split(',')
            if is_commented(contents, result.start(0)):
                print(str(result) + "  is commented")
                continue
            prefix_pos = contents.rfind("MEMBER_FN_PREFIX", 0, result.start(1) + 1)
            # print("'" + contents[result.start(0):result.start()+100] + "'")
            # print("'" + contents[prefix_pos:prefix_pos+100] + "'")
            prefix = memberFnPrefixRegex.match(contents, prefix_pos, prefix_pos + 100)
            # if prefix is None:
            #     print('\t\t' + args[0] + ' ' + args[2] + ' ' + str(prefix_pos) + ' ' + str(
            #         result.start(0)))
            # print('\t\t' + prefix.group(1) + ' ' + args[0] + ' ' + args[2])
            functions.append((prefix.group(1).strip(), args[0].strip(), int(args[2], 16), args[2].strip()))
    return functions


if __name__ == '__main__':
    print(f"0x{267:0{8}X}")
    # find_all_functions('../skse64_2_00_07/')
    # print(find_all_ptrs('../skse64_2_00_07/'))
