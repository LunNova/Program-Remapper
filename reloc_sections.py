#! python3
from typing import List

import humanize
import pefile
from pefile import *


def null_relocate(self: pefile):
    """Changes all relocated addresses in this pe file to NULL
    """
    relocation_difference = 0
    reloc_constant = 0xDEADBEEF
    if self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size:
        if not hasattr(self, 'DIRECTORY_ENTRY_BASERELOC'):
            self.parse_data_directories(
                directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
        for reloc in self.DIRECTORY_ENTRY_BASERELOC:

            # We iterate with an index because if the relocation is of type
            # IMAGE_REL_BASED_HIGHADJ we need to also process the next entry
            # at once and skip it for the next iteration
            #
            entry_idx = 0
            while entry_idx < len(reloc.entries):
                entry = reloc.entries[entry_idx]
                entry_idx += 1

                if entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                    # Nothing to do for this type of relocation
                    pass

                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:
                    # Fix the high 16-bits of a relocation
                    #
                    # Add high 16-bits of relocation_difference to the
                    # 16-bit value at RVA=entry.rva

                    self.set_word_at_rva(
                        entry.rva,
                        reloc_constant & 0xffff)

                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:
                    # Fix the low 16-bits of a relocation
                    #
                    # Add low 16 bits of relocation_difference to the 16-bit value
                    # at RVA=entry.rva

                    self.set_word_at_rva(
                        entry.rva,
                        reloc_constant & 0xffff)

                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    # Handle all high and low parts of a 32-bit relocation
                    #
                    # Add relocation_difference to the value at RVA=entry.rva

                    self.set_dword_at_rva(
                        entry.rva,
                        reloc_constant)

                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']:
                    # Fix the high 16-bits of a relocation and adjust
                    #
                    # Add high 16-bits of relocation_difference to the 32-bit value
                    # composed from the (16-bit value at RVA=entry.rva)<<16 plus
                    # the 16-bit value at the next relocation entry.
                    #

                    # If the next entry is beyond the array's limits,
                    # abort... the table is corrupt
                    #
                    if entry_idx == len(reloc.entries):
                        break

                    entry_idx += 1
                    self.set_word_at_rva(entry.rva, reloc_constant)

                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    # Apply the difference to the 64-bit value at the offset
                    # RVA=entry.rva

                    self.set_qword_at_rva(entry.rva, reloc_constant)

        # correct VAs(virtual addresses) occurrences in directory information
        if hasattr(self, 'IMAGE_DIRECTORY_ENTRY_IMPORT'):
            for dll in self.DIRECTORY_ENTRY_IMPORT:
                for func in dll.imports:
                    func.address += relocation_difference
        if hasattr(self, 'IMAGE_DIRECTORY_ENTRY_TLS'):
            self.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData += relocation_difference
            self.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData += relocation_difference
            self.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex += relocation_difference
            self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks += relocation_difference
        if hasattr(self, 'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'):
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.LockPrefixTable:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.LockPrefixTable += relocation_difference
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.EditList:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.EditList += relocation_difference
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie += relocation_difference
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable += relocation_difference
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer += relocation_difference
            if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable:
                self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable += relocation_difference


def null_relocate_pe(target: str):
    pe = pefile.PE(target)
    null_relocate(pe)
    pe.write('../NullRelocated/' + os.path.basename(target))


def section_name(section: pefile.SectionStructure):
    return section.Name.decode("windows-1252").rstrip('\x00')


def find_pdata(target: pefile):
    section: SectionStructure
    for section in target.sections:
        if section_name(section) == '.pdata':
            find_pdata_functions(section.get_data())

# This part is currently stupid, slow, and broken
# Don't use it!
def find_moved(original_file: str, target_file: str):
    target: pefile = pefile.PE(target_file)
    original: pefile = pefile.PE(original_file)

    print("Relocating " + target_file + " " + str(target.get_warnings()))
    null_relocate(target)
    print("Relocating " + original_file + " " + str(original.get_warnings()))
    null_relocate(original)
    print("Relocated")

    all_ranges: List[RelocationRange] = []
    for i in range(0, min(len(original.sections), len(target.sections))):
        target_section: pefile.SectionStructure = target.sections[i]
        original_section: pefile.SectionStructure = original.sections[i]
        print(f"Section {i} {section_name(target_section)}"
              f" {section_name(original_section)}"
              f" {target_section.SizeOfRawData}"
              f" {original_section.SizeOfRawData}")
        ranges = find_moved_section(target_section, original_section)
        length = target_section.SizeOfRawData
        mapped_length = 0
        for r in ranges:
            mapped_length += r.length
        print(
            f"Mapped {mapped_length * 100.0 / length}% {humanize.naturalsize(mapped_length)} / {humanize.naturalsize(length)}")
        all_ranges.extend(ranges)

    return all_ranges


class RelocationRange(object):
    original_start: int = 0
    relocated_start: int = 0
    length: int = 0

    @property
    def relocated_end(self):
        return self.relocated_start + self.length

    @property
    def original_end(self):
        return self.original_start + self.length

    def __str__(self):
        return f"{hex(self.original_start)} -> {hex(self.relocated_start)} {hex(self.length)}"


class FunctionTableEntry(object):
    start_address: int
    end_address: int
    unwind_information: int

    def __str__(self) -> str:
        return f"start {hex(self.start_address)} end {hex(self.end_address)} unwind {hex(self.unwind_information)}"


def find_pdata_functions(pdata: bytes):
    index = 0
    functions: List[FunctionTableEntry] = []
    print("pdata align: " + str(len(pdata) / 12))
    while index < len(pdata):
        fn = FunctionTableEntry()
        fn.start_address = struct.unpack('<L', pdata[index: index + 4])[0]
        index += 4
        fn.end_address = struct.unpack('<L', pdata[index: index + 4])[0]
        index += 4
        fn.unwind_information = struct.unpack('<L', pdata[index: index + 4])[0]
        index += 4
        print(fn)
        functions.append(fn)
    return functions


def find_moved_section(target_section: pefile.SectionStructure, original_section: pefile.SectionStructure):
    section_size = 256
    index = 0
    target = target_section.get_data()
    original = original_section.get_data()

    size_diff = abs(len(target) - len(original)) + section_size * 16

    finish = math.ceil(len(target) / section_size)

    ranges: List[RelocationRange] = []
    current_range: RelocationRange = None
    last_range: RelocationRange = None
    misses: int = 0

    while index < finish:
        start = index * section_size
        part = target[start: start + section_size]

        pos: int = -1
        if current_range is not None:
            spos = current_range.relocated_end
            pos = original.find(part, spos, spos + section_size * 2)
        if pos == -1 and last_range is not None:
            spos = last_range.relocated_end
            pos = original.find(part, spos, spos + section_size * (4 + misses))
        if pos == -1:
            pos = original.find(part, max(0, start - size_diff), max(len(original), start + size_diff))

        if pos == -1:
            misses += 1
            current_range = None
        else:
            misses = 0
            # print(str(current_range))
            # print(hex(pos))
            # if current_range is not None:
            #     print(hex(current_range.relocated_end))
            if current_range is not None and pos == current_range.relocated_end:
                current_range.length += section_size
            else:
                current_range = RelocationRange()
                current_range.original_start = start
                current_range.length = section_size
                current_range.relocated_start = pos
                ranges.append(current_range)

        if current_range is not None:
            last_range = current_range

        # if pos == -1:
        #     print("\tFound block {} at None".format(hex(target_section.get_rva_from_offset(start))))
        # else:
        #     print("\tFound block {} at {}".format(hex(target_section.get_rva_from_offset(start)),
        #                                           hex(original_section.get_rva_from_offset(pos))))
        # print(part.hex())
        index += 1

    for range in ranges:
        range.original_start = target_section.pe.OPTIONAL_HEADER.ImageBase + target_section.get_rva_from_offset(
            range.original_start)
        range.relocated_start = original_section.pe.OPTIONAL_HEADER.ImageBase + original_section.get_rva_from_offset(
            range.relocated_start)

    return ranges


if __name__ == '__main__':
    find_moved('../Unpacked/SkyrimSE - 1.5.39.0.exe.unpacked.exe', '../Unpacked/SkyrimVR - 1.3.64.0.exe.unpacked.exe')
