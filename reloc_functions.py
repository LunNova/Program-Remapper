from collections import defaultdict
import Levenshtein
import difflib
from typing import Optional, Any, List, Tuple, Dict, Callable

import os
import binja_dumper
from binja_dumper import Executable, ExeFunction, ExeSegment


class Matches(object):
    dict_a: Dict[int, ExeFunction]
    dict_b: Dict[int, ExeFunction]
    unmatched_a: List[ExeFunction]
    unmatched_b: List[ExeFunction]
    data_vars_a: Dict[int, List[Tuple[int, int, int]]]
    data_vars_b: Dict[int, List[Tuple[int, int, int]]]
    __slots__ = 'list_a', 'list_b', 'dict_a', 'dict_b', 'unmatched_a', 'unmatched_b', 'data_vars_a', 'data_vars_b'

    def __init__(self):
        self.list_a = []
        self.list_b = []
        self.dict_a = None
        self.dict_b = None
        self.data_vars_a = {}
        self.data_vars_b = {}

    def __getstate__(self):
        state = {slot: getattr(self, slot) for slot in self.__slots__}
        del state['dict_a']
        del state['dict_b']
        del state['unmatched_a']
        del state['unmatched_b']
        return state

    def __setstate__(self, state):
        for slot in state:
            setattr(self, slot, state[slot])
        self.update(True)

    def find_moved_functions_in_segment(self, original: ExeSegment, target: ExeSegment):
        fns_a = original.functions
        fns_b = target.functions

        l_a = -1
        l_b = -1

        done = 0
        while True:
            done += 1
            if done % 10000 == 0:
                print("Mapping function " + str(done))
            a = l_a + 1
            b = l_b + 1

            fn_a = None
            if a < len(fns_a):
                fn_a = fns_a[a]

            fn_b = None
            if b < len(fns_b):
                fn_b = fns_b[b]

            if not (fn_a and fn_b):
                break

            if fn_a and fn_b and fn_a.instructions == fn_b.instructions:
                l_a = a
                l_b = b
                link(fn_a, fn_b)
                continue
            else:
                offset = 1
                match = False
                while offset < 200:
                    if a + offset < len(fns_a):
                        fn_a2 = fns_a[a + offset]
                        if fn_b.instructions == fn_a2.instructions:
                            link(fn_a2, fn_b)
                            l_a = a + offset
                            l_b = b
                            match = True
                            break

                    if b + offset < len(fns_b):
                        fn_b2 = fns_b[b + offset]
                        if fn_a.instructions == fn_b2.instructions:
                            link(fn_a, fn_b2)
                            l_a = a
                            l_b = b + offset
                            match = True
                            break
                    offset += 1
                if match:
                    continue
            l_a = a
            l_b = b

        self.list_a.extend(original.functions)
        self.list_b.extend(target.functions)

    def analyse_unmapped_functions(self):
        total = len(self.list_a) + len(self.list_b)

        self.analyse_and_link(None, total)

        last_unmatched = -1
        for linker in link_stages:
            last_unmatched = self.analyse_and_link(linker, total)

        outer_last_unmatched = last_unmatched
        while True:
            for linker in repeat_link_stages:
                last_unmatched = self.analyse_and_link(linker, total)
            if last_unmatched == outer_last_unmatched:
                break
            outer_last_unmatched = last_unmatched

    def analyse_and_link(self, linker, total):
        r = ''
        i = 0
        while True:
            last_unmatched = len(self.unmatched_a) + len(self.unmatched_b)
            if linker is not None:
                i += 1
                print(r + "Running " + linker.__name__ + " " + str(i) + ' ' + str(
                    (total - last_unmatched) * 100 / total) + "%")
                r = '\r'
                linker(self, self.unmatched_a, self.unmatched_b)
            self.update()
            unmatched = len(self.unmatched_a) + len(self.unmatched_b)
            if unmatched == last_unmatched:
                break
        print(f"Unmatched percentage: " + str(unmatched * 100 / total) + "%")
        return unmatched

    def map(self, address: int):
        fn = self.dict_a[address]
        match = fn.match
        if match:
            ratio = levenshtein_ratio(fn, match)
            if ratio < 0.5:
                print(f"Suspect match! {ratio}")
                self.dump(address, 'a')
            return match.address
        return None

    def update(self, added=False):
        if added:
            link_next_prev(self.list_a)
            link_next_prev(self.list_b)
            self.dict_a = {fn.address: fn for fn in self.list_a}
            self.dict_b = {fn.address: fn for fn in self.list_b}
            link_calls(self.list_a, self.dict_a)
            link_calls(self.list_b, self.dict_b)
        self.unmatched_a = [x for x in self.list_a if not x.match]
        self.unmatched_b = [x for x in self.list_b if not x.match]
        pass

    def dump(self, address, side, recurse=True):
        def minidump(address):
            if side == 'a':
                f: ExeFunction = self.dict_a[address]
            if side == 'b':
                f: ExeFunction = self.dict_b[address]
            if f.match:
                return hex(f.address) + " -> " + hex(f.match.address)
            return hex(f.address) + " -> None"

        if side == 'a':
            fn: ExeFunction = self.dict_a[address]
        if side == 'b':
            fn: ExeFunction = self.dict_b[address]
        print(fn)
        print('Match: ' + str(fn.match))
        print('Strings: ' + comma_sep(fn.referenced_strings))
        print('CStrings: ' + comma_sep(self.cumulative_strings(fn, side)))
        print(comma_sep([minidump(x) for x in fn.calls]))
        print(comma_sep([minidump(x) for x in fn.called_by]))

        # if recurse:
        #     print("Calls")
        #     for x in fn.calls:
        #         self.dump(x, side, False)
        #     print("Called By")
        #     for x in fn.called_by:
        #         self.dump(x, side, False)
        pass

    def find_moved_functions(self, original_exe, target_exe):
        self.data_vars_a.update(original_exe.datavars)
        self.data_vars_b.update(target_exe.datavars)
        for i in range(0, max(len(original_exe.segments), len(target_exe.segments))):
            seg_a = original_exe.segments[i]
            seg_b = target_exe.segments[i]
            if len(seg_a.functions) == 0 and len(seg_b.functions) == 0:
                continue
            self.find_moved_functions_in_segment(seg_a, seg_b)

    def cumulative_strings(self, fn: ExeFunction, side: str):
        target = []
        visited = set()
        self._cumulative_strings(fn, side, target, visited)
        return target

    def _cumulative_strings(self, fn: ExeFunction, side: str, target: list, visited: set):
        if fn.address in visited:
            return
        visited.add(fn.address)
        target.extend(sorted(set(fn.referenced_strings)))
        for c in fn.calls:
            if side == 'a':
                self._cumulative_strings(self.dict_a[c], side, target, visited)
            if side == 'b':
                self._cumulative_strings(self.dict_b[c], side, target, visited)


def comma_sep(list):
    return '\'' + "', '".join([str(x) for x in list]) + '\''


def link_calls(fns: List[ExeFunction], dict: Dict[int, ExeFunction]):
    for fn in fns:
        if fn.calls is None:
            fn.calls = []
        for call in fn.called_by:
            try:
                caller = dict[call]
                if not caller.calls:
                    caller.calls = []
                caller.calls.append(fn.address)
            except KeyError:
                print(f"{hex(call)} missing, calls {hex(fn.address)} (jump table?)")
                raise


def link_next_prev(fns: List[ExeFunction]):
    last_fn = None
    for fn in fns:
        if last_fn:
            if fn.address < last_fn.address:
                raise Exception("out of order")
            last_fn.next = fn
            fn.prev = last_fn
        last_fn = fn


def find_moved_functions(original: str, target: str) -> Matches:
    original_exe: Executable = binja_dumper.load(original)
    target_exe: Executable = binja_dumper.load(target)

    original_exe.name = os.path.basename(original)
    target_exe.name = os.path.basename(target)
    print(original_exe.function_address_constants)

    matches = Matches()

    matches.find_moved_functions(original_exe, target_exe)

    matches.update(True)
    matches.analyse_unmapped_functions()

    return matches


def link(a: ExeFunction, b: ExeFunction):
    if a.match or b.match:
        raise Exception(f"already matched {a} {b} {a.match} {b.match}")
    a.match = b
    b.match = a

    # TODO: check calling xrefs when doing this part to avoid false positives
    # link_by_instrs(a_unmatched, b_unmatched)
    #
    # a_unmatched = [x for x in fns_a if not x.match]
    # b_unmatched = [x for x in fns_b if not x.match]
    # print(f"unmatchedA {len(a_unmatched)} unmatchedB {len(b_unmatched)}")
    # print(f"unmatched percentage: " + str((len(a_unmatched) + len(b_unmatched)) * 100 / total) + "%")

    # print("A Matched: \n\t" + "\n\t".join([str(x) for x in matched]))
    # print("A Unmatched: \n\t" + "\n\t".join([str(x) for x in a_unmatched]))
    # print("B Unmatched: \n\t" + "\n\t".join([str(x) for x in b_unmatched]))


def match_by_instructions_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched,
                 lambda matcher, fn, side: '!'.join(fn.referenced_strings) + '&'.join(fn.instructions))


def match_by_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, lambda matcher, fn, side: '&'.join(fn.referenced_strings))


def match_by_cumulative_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched,
                 lambda matcher, fn, side: '&'.join(matcher.cumulative_strings(fn, side)))


def match_by_sorted_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched,
                 lambda matcher, fn, side: '&'.join(sorted(set([x for x in fn.referenced_strings if len(x) > 4]))))


def match_by_prev_next_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, prev_next_key)


def match_by_prev_or_next_instrs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, prev_or_next_instructions_str_key)


def match_by_prev_or_next_instrs_levenshtein(matches: Matches, a_unmatched: List[ExeFunction],
                                             b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, prev_or_next_key, instruction_levenshtein_distance)


levenshtein_fail_cache = {}


def instruction_levenshtein_distance(a: ExeFunction, b: ExeFunction):
    cache_key = str(a) + ' ' + str(b)
    if cache_key in levenshtein_fail_cache:
        return False
    ains = '\t'.join(a.instructions)
    bins = '\t'.join(b.instructions)
    if ains == "ERROR" or bins == "ERROR":
        return False
    if ains == bins:
        return True
    # dis = Levenshtein.ratio(ains, bins)
    dis = difflib.SequenceMatcher(None, ains, bins).ratio()
    min_ratio = 0.8
    # if dis > min_ratio:
    #     print(f"{a} to {b} ratio {dis}")
    #     print(f"{ains}")
    #     print(f"{bins}")
    match = dis > min_ratio
    if not match:
        levenshtein_fail_cache[cache_key] = False
    return match


levenshtein_fail_cache_lenient = {}


def instruction_levenshtein_distance_lenient(a: ExeFunction, b: ExeFunction):
    cache_key = str(a) + ' ' + str(b)
    if cache_key in levenshtein_fail_cache_lenient:
        return False
    ains = '\t'.join(a.instructions)
    bins = '\t'.join(b.instructions)
    if ains == "ERROR" or bins == "ERROR":
        return False
    if ains == bins:
        return True
    # dis = Levenshtein.ratio(ains, bins)
    dis = difflib.SequenceMatcher(None, ains, bins).ratio()
    min_ratio = 0.5
    # if dis > min_ratio:
    #     print(f"{a} to {b} ratio {dis}")
    #     print(f"{ains}")
    #     print(f"{bins}")
    match = dis > min_ratio
    if not match:
        levenshtein_fail_cache_lenient[cache_key] = False
    return match


def levenshtein_ratio(a: ExeFunction, b: ExeFunction):
    ains = '\t'.join(a.instructions)
    bins = '\t'.join(b.instructions)
    if ains == "ERROR" or bins == "ERROR":
        return 0
    # return Levenshtein.ratio(ains, bins)
    return difflib.SequenceMatcher(None, ains, bins).ratio()


def match_by_prev_or_next_calls(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, prev_or_next_calls_key)


def prev_next_key(matches: Matches, fn: ExeFunction, side: str):
    if not fn.prev or not fn.next:
        return None
    if not fn.prev.match or not fn.next.match:
        return None
    if side == 'a':
        return hex(fn.prev.address) + ' ' + hex(fn.next.address) + '&'.join(fn.referenced_strings)
    return hex(fn.prev.match.address) + ' ' + hex(fn.next.match.address) + '&'.join(fn.referenced_strings)


def prev_or_next_key(matches: Matches, fn: ExeFunction, side: str):
    if not fn.prev or not fn.next:
        return None
    if not (fn.prev.match or fn.next.match):
        return None
    if fn.prev.match and fn.next.match:
        if side == 'a':
            return hex(fn.prev.address) + ' ' + hex(fn.next.address)
        return hex(fn.prev.match.address) + ' ' + hex(fn.next.match.address)
    if fn.prev.match:
        if side == 'a':
            return 'p' + hex(fn.prev.address)
        return 'p' + hex(fn.prev.match.address)
    if side == 'a':
        return 'n' + hex(fn.next.address)
    return 'n' + hex(fn.next.match.address)


def prev_or_next_calls_key(matches: Matches, fn: ExeFunction, side: str):
    if not fn.prev or not fn.next:
        return None
    if not (fn.prev.match or fn.next.match):
        return None
    k = calls_called_strs_key(matches, fn, side)
    if not k or k == '':
        return None
    if fn.prev.match and fn.next.match:
        if side == 'a':
            return hex(fn.prev.address) + ' ' + hex(fn.next.address) + k
        return hex(fn.prev.match.address) + ' ' + hex(fn.next.match.address) + k
    if fn.prev.match:
        if side == 'a':
            return 'p' + hex(fn.prev.address) + k
        return 'p' + hex(fn.prev.match.address) + k
    if side == 'a':
        return 'n' + hex(fn.next.address) + k
    return 'n' + hex(fn.next.match.address) + k


def prev_or_next_instructions_str_key(matches: Matches, fn: ExeFunction, side: str):
    if not fn.prev or not fn.next:
        return None
    if not (fn.prev.match or fn.next.match):
        return None
    k = '&'.join(fn.instructions) + '&'.join(fn.referenced_strings)
    if not k or k == '':
        return None
    if fn.prev.match and fn.next.match:
        if side == 'a':
            return hex(fn.prev.address) + ' ' + hex(fn.next.address) + k
        return hex(fn.prev.match.address) + ' ' + hex(fn.next.match.address) + k
    if fn.prev.match:
        if side == 'a':
            return 'p' + hex(fn.prev.address) + k
        return 'p' + hex(fn.prev.match.address) + k
    if side == 'a':
        return 'n' + hex(fn.next.address) + k
    return 'n' + hex(fn.next.match.address) + k


def xref_str(fn: ExeFunction, attr):
    return "!".join([str(x) for x in getattr(fn, attr)])


def mapped_xref_str(matches: Matches, fn: ExeFunction, attr):
    calls = []
    for x in getattr(fn, attr):
        mfn = matches.dict_b[x]
        if mfn.match:
            calls.append(str(mfn.match.address))
        else:
            return ""
    return "!".join(calls)


def match_by_calls_called_strs(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, calls_called_strs_key)


def match_by_instructions_calls_called_strs(matches: Matches, a_unmatched: List[ExeFunction],
                                            b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, instructions_calls_called_strs_key)


def match_by_instructions(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    match_by_key(matches, a_unmatched, b_unmatched, lambda matcher, fn, side: '!'.join(fn.instructions))


def match_by_name(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    def function1(matcher, fn: ExeFunction, side):
        return fn.name if fn.name.find('!') != -1 else None

    match_by_key(matches, a_unmatched, b_unmatched,
                 function1)


def instructions_calls_called_strs_key(matches: Matches, fn: ExeFunction, side: str):
    res = calls_called_strs_key(matches, fn, side)
    if not res or res == '':
        return None
    return ';'.join(fn.instructions) + ';' + res


def calls_called_strs_key(matches: Matches, fn: ExeFunction, side: str):
    parts = []
    parts.extend(fn.referenced_strings)
    d = getattr(matches, 'dict_' + side)
    for call in fn.calls:
        called: ExeFunction = d[call]
        if called.match:
            if side == 'a':
                parts.append('!' + hex(called.address))
            else:
                parts.append('!' + hex(called.match.address))
    for call in fn.called_by:
        called: ExeFunction = d[call]
        if called.match:
            if side == 'a':
                parts.append('^' + hex(called.address))
            else:
                parts.append('^' + hex(called.match.address))
    parts.sort()
    return "#".join(parts)


def match_by_key(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction], key, valid=None):
    b_unmatched_xrefs = {}
    for fn in b_unmatched:
        s = key(matches, fn, "b")
        db = fn.address in debug
        if db:
            print(f"{hex(fn.address)} keyed to:\n{s}")
        if not s or s == "":
            if db:
                print("skip")
            continue
        if s in b_unmatched_xrefs:
            if db:
                print("duplicate")
            if isinstance(b_unmatched_xrefs[s], ExeFunction) and b_unmatched_xrefs[s].address in debug:
                print(f"{hex(b_unmatched_xrefs[s].address)} duplicated by {hex(fn.address)}")
            b_unmatched_xrefs[s] = False
        else:
            b_unmatched_xrefs[s] = fn
    a_unmatched_xrefs = {}
    for fn in a_unmatched:
        s = key(matches, fn, "a")
        db = fn.address in debug
        if db:
            print(f"{hex(fn.address)} keyed to:\n{s}")
        if not s or s == "":
            if db:
                print("skip")
            continue
        if s in a_unmatched_xrefs:
            if db:
                print("duplicate")
            if isinstance(a_unmatched_xrefs[s], ExeFunction) and a_unmatched_xrefs[s].address in debug:
                print(f"{hex(a_unmatched_xrefs[s].address)} duplicated by {hex(fn.address)}")
            a_unmatched_xrefs[s] = False
        else:
            a_unmatched_xrefs[s] = fn

    for s, fn in a_unmatched_xrefs.items():
        if not fn or s not in b_unmatched_xrefs:
            continue
        match = b_unmatched_xrefs[s]
        if match and (not valid or valid(fn, match)):
            link(fn, match)


def link_by_called_by(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    link_by_addresses_attr(matches, a_unmatched, b_unmatched, 'called_by')


def link_by_calls(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction]):
    link_by_addresses_attr(matches, a_unmatched, b_unmatched, 'calls')


def link_by_addresses_attr(matches: Matches, a_unmatched: List[ExeFunction], b_unmatched: List[ExeFunction], attr: str):
    b_unmatched_xrefs = {}
    for fn in b_unmatched:
        s = mapped_xref_str(matches, fn, attr)
        if s == "":
            continue
        if s in b_unmatched_xrefs:
            b_unmatched_xrefs[s] = False
        else:
            b_unmatched_xrefs[s] = fn
    a_unmatched_xrefs = {}
    for fn in a_unmatched:
        s = xref_str(fn, attr)
        if s == "":
            continue
        if s in a_unmatched_xrefs:
            a_unmatched_xrefs[s] = False
        else:
            a_unmatched_xrefs[s] = fn

    for s, fn in a_unmatched_xrefs.items():
        if not fn or s not in b_unmatched_xrefs:
            continue
        match = b_unmatched_xrefs[s]
        if match:
            link(fn, match)

    # a_refs = defaultdict(list)
    # b_refs = defaultdict(list)
    # for fn in a:
    #     for xref in fn.called_by:
    #         a_refs[]
    #     a_refs[]
    # for


def link_by_instrs(a_unmatched, b_unmatched):
    b_lookup = {",".join(x.instructions): x for x in b_unmatched}

    for fn_a in a_unmatched:
        if fn_a.match:
            continue
        try:
            fn_b = b_lookup[",".join(fn_a.instructions)]
            if fn_b.match:
                continue
            link(fn_a, fn_b)
        except KeyError:
            pass


def make_function(a, instrs):
    f = ExeFunction()
    f.address = a
    f.instructions.extend(instrs)
    return f


link_stages = [
    match_by_name,
    match_by_instructions_strs,
    match_by_strs,
    # Too slow - not very useful anyway
    # match_by_cumulative_strs,
    match_by_sorted_strs
]

repeat_link_stages = [
    match_by_calls_called_strs,
    match_by_instructions,
    match_by_instructions_calls_called_strs,
    link_by_called_by,
    link_by_calls,
    match_by_prev_or_next_instrs_levenshtein,
    match_by_prev_next_strs,
    match_by_prev_or_next_instrs,
    match_by_prev_or_next_calls
]

debug = {
    # BGSSaveLoadManager Save_Internal
    # 0x140587290: True,
    # 0x14058e100: True,

    # SYM-KERNEL32!TryAcquireSRWLockShared@IAT
    # 0x1411b8de0: True,

    # NativeFunction Impl_Fn10
    # 0x141267eb0: True
}

if __name__ == '__main__':
    a = ExeSegment()
    a.functions = [
        make_function(0x10, ["nop", "nop"]),
        make_function(0x20, ["nop", "push", "nop"]),
        make_function(0x30, ["nop", "push", "ret"]),
        make_function(0x40, ["jmp", "push", "ret"]),
        make_function(0x50, ["add", "push", "ret"]),
        make_function(0x60, ["jmp", "push", "ret"]),
        make_function(0x70, ["add", "push", "ret"]),
    ]
    b = ExeSegment()
    b.functions = [
        make_function(0x10, ["nop", "nop"]),
        make_function(0x20, ["nop", "push", "ret"]),
        make_function(0x30, ["jmp", "push", "ret"]),
        make_function(0x40, ["add", "push", "ret"]),
        make_function(0x50, ["jmp", "push", "ret"]),
        make_function(0x60, ["add", "push", "ret"]),
        make_function(0x70, ["add", "push", "ret"]),
    ]
    matches = Matches()
    matches.find_moved_functions_in_segment(a, b)
