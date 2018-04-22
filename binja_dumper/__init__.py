#! python2

from __future__ import division
from __future__ import print_function
from boltons.setutils import IndexedSet

# import imp; binja_dumper = imp.load_source('binja_dumper', r"PATH_TO_BINJA_DUMPER\__init__.py"); binja_dumper.do_dump(bv)

from collections import defaultdict
import operator

try:
    from binaryninja import *
except:
    pass

# noinspection PyPep8Naming
try:
    import cPickle as pickle
except:
    import pickle

from typing import List, Dict, Tuple


class Executable(object):
    def __init__(self):
        self.name = ""  # type: str
        self.segments = []  # type: List[ExeSegment]
        self.function_address_constants = {}
        self.datavars = {}  # type: Dict[int, Tuple[int, DataVariable]]


class ExeSegment(object):
    def __init__(self):
        self.name = ""  # type: str
        self.start_address = 0  # type: int
        self.end_address = 0  # type: int
        self.functions = []  # type: List[ExeFunction]


class ExeFunction(object):
    __slots__ = (
        'name',
        'address',
        'instructions',
        'called_by',
        'referenced_strings',
        # 'referenced_imports',
        'match',
        'prev',
        'next',
        'calls'
    )

    def __init__(self):
        self.name = ""  # type: str
        self.address = 0  # type: int
        self.instructions = []  # type: List[str]
        self.called_by = []  # type: List[int]
        self.referenced_strings = []  # type: List[str]
        # self.referenced_imports = []  # type: List[str]
        self.match = None  # type: ExeFunction

        # Transient fields after here
        self.prev = None  # type: ExeFunction
        self.next = None  # type: ExeFunction
        self.calls = None  # type: List[int]

    def __str__(self):
        return hex(self.address) + ' ' + self.name

    def __getstate__(self):
        state = {slot: getattr(self, slot) for slot in self.__slots__}
        del state['prev']
        del state['next']
        del state['calls']
        return state

    def __setstate__(self, state):
        for slot in state:
            setattr(self, slot, state[slot])
        self.prev = None
        self.next = None
        self.calls = None


def load_functions(bv, start, end, data_vars):
    functions = []  # type: List[ExeFunction]

    i = 0
    for fn in bv:  # type: Function
        fn_address = fn.start
        if fn_address < start or fn_address >= end:
            continue

        i += 1
        # if i > 20:
        #     raise Exception("abort")
        if i % 1000 == 0:
            print("Loaded " + str(i) + " functions")

        efn = ExeFunction()
        efn.address = fn_address
        efn.name = fn.name
        functions.append(efn)

        try:
            instructions = ([valid_instruction(x) for x in fn.instructions])
        except:
            instructions = ["ERROR"]

        efn.instructions = instructions
        efn.called_by = [x.function.start for x in bv.get_code_refs(efn.address)]
        if efn.address in data_vars:
            efn.referenced_strings = data_vars[efn.address]

    return functions


normal_chars = [chr(i) for i in range(ord('a'), ord('z') + 1)]
normal_chars.extend([chr(i) for i in range(ord('A'), ord('Z') + 1)])
normal_chars.extend([chr(i) for i in range(ord('0'), ord('9') + 1)])
normal_chars.append(' ')
normal_chars.append('\\')
normal_chars.append('.')
normal_chars.append('(')
normal_chars.append(')')


def suspicious(string):
    length = len(string)
    if length == 0:
        return True
    if length > 8:
        return False
    normal = 0
    for s in string:
        if s in normal_chars:
            normal += 1
    return normal / length < 0.6


def load_constants(bv):
    constant_refs = defaultdict(list)

    for string in bv.get_strings():  # type: StringReference
        start = string.start
        if bv.is_offset_executable(start):
            continue
        val = string.value.strip()
        if suspicious(val):
            continue
        #     print("Suspicious " + val + " at " + hex(start))
        # if val.find(']Y@') != -1:
        #     print("Found " + val + " at " + hex(start) + " suspicious " + str(suspicious(val)))
        #     raise Exception("")
        refs = bv.get_code_refs(start)
        for ref in refs:  # type: ReferenceSource
            constant_refs[ref.function.start].append(val)

    import_symbols = bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)  # type: List[Symbol]
    import_symbols.extend(bv.get_symbols_of_type(SymbolType.ImportAddressSymbol))
    import_symbols.extend(bv.get_symbols_of_type(SymbolType.ImportedDataSymbol))

    for symbol in import_symbols:
        refs = bv.get_code_refs(symbol.address)
        name = 'SYM-' + symbol.name
        for ref in refs:  # type: ReferenceSource
            constant_refs[ref.function.start].append(name)

    # jump tables
    # data_symbols = bv.get_symbols_of_type(SymbolType.DataSymbol, bv.start, bv.end)
    # print data_symbols

    return constant_refs


def load_datavars(bv):
    """
    :type bv: BinaryView
    """
    datavars = defaultdict(IndexedSet)

    for segment in bv.segments:
        if segment.executable or not segment.readable:
            continue
        current = segment.start
        end = segment.end
        while current < end:
            next = bv.get_next_data_var_after(current)
            if next <= current or next > end:
                break
            current = next
            if current in datavars:
                continue
            for ref in bv.get_code_refs(current):  # type: ReferenceSource
                dv = (ref.function.start, ref.address, current)
                datavars[current].add(dv)
                datavars[ref.function.start].add(dv)

    return datavars


def load_executable(bv):
    """
    :type bv: BinaryView
    """
    exe = Executable()  # type: Executable
    exe.name = bv.name

    print("Loading constants")
    constants = load_constants(bv)

    print("Loading datavars")
    exe.datavars = load_datavars(bv)

    print("Loading segments")
    i = 0
    for segment in sorted(bv.segments, key=operator.attrgetter("start")):  # type: Segment
        exe_segment = ExeSegment()
        exe.segments.append(exe_segment)
        exe_segment.name = "SEGMENT " + str(i)
        exe_segment.start_address = segment.start
        exe_segment.end_address = segment.end
        if segment.executable:
            print("Loading " + exe_segment.name)
            exe_segment.functions.extend(load_functions(bv, segment.start, segment.end, constants))
            print("Loaded " + str(len(exe_segment.functions)) + " functions")
        i += 1

    return exe


def valid_instruction(x):
    if x is None:
        return ""
    x = x[0]
    if x is None:
        return ""
    offset = ""
    for test in xrange(0, len(x)):
        itt = x[test]  # type: InstructionTextToken
        if itt.text.startswith('0x'):
            val = int(itt.text, 16)
            if val < 1000:
                offset += " +" + itt.text
    x = x[0]
    return str(x) + offset


def function_dump(writer, prefix, bv, segment):
    """
    :type writer: cStringIO.StringIO
    :type prefix: str
    :type bv: BinaryView
    :type segment: Segment
    """
    dumped = 0
    f_prefix = prefix + "\t"
    current = segment.start - 1
    while True:
        found = bv.get_next_function_start_after(current)
        if found == current:
            break
        current = found
        fn = bv.get_function_at(current)  # type: Function
        if fn is None:
            break
        writer.write(prefix + "FUNCTION" + "\n")
        try:
            instructions = ("\n" + f_prefix).join([valid_instruction(x) for x in fn.instructions])
        except:
            instructions = "ERROR"
        writer.write(f_prefix + instructions + "\n")
        writer.write("\n")
        dumped += 1
        if dumped > 10000:
            return


def write_properties(writer, prefix, o):
    """
    :type writer: cStringIO.StringIO
    :type prefix: str
    :type o: object
    """
    attrs = sorted([attr for attr in dir(o) if not callable(getattr(o, attr)) and not attr.startswith("__")])
    for attr in attrs:
        writer.write(prefix + str(attr) + " = " + str(getattr(o, attr)) + "\n")


def text_dump(writer, bv):
    """
    :type writer: cStringIO.StringIO
    :type bv: BinaryView
    """
    prefix = "\t"

    for section_name in sorted(bv.sections, key=lambda x: bv.sections[x].start):
        section = bv.sections[section_name]  # type: Section
        writer.write("SECTION " + section_name + "\n")
        write_properties(writer, prefix, section)
        writer.write("\n")
        writer.write("\n")

    i = 0
    for segment in sorted(bv.segments, key=operator.attrgetter("start")):  # type: Segment
        writer.write("SEGMENT " + str(i) + "\n")
        write_properties(writer, prefix, segment)
        writer.write("\n")
        writer.write("\n")
        if segment.executable:
            function_dump(writer, prefix, bv, segment)
        i += 1

    pass


def print_segments(exe):
    # for s in exe.segments:
    #     for function in s.functions:
    #         print(function.name + " " + hex(function.address) + " " + str(function.instructions))
    print("Segments: " + str(len(exe.segments)))


def serialize(obj):
    """JSON serializer for objects not serializable by default json code"""
    return obj.__dict__


def dump_name(path):
    import os
    return os.path.splitext(path)[0] + ".bndmp"


def load(exe_path):
    with open(dump_name(exe_path), 'rb') as f:
        return pickle.load(f)


def do_dump(bv):
    """
    :type bv: BinaryView
    """
    bv.update_analysis_and_wait()
    path = dump_name(bv.file.filename)

    exe = load_executable(bv)
    print("Dumping to " + path)
    with open(path, "wb") as f:
        pickle.dump(exe, f, pickle.HIGHEST_PROTOCOL)
