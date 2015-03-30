/*
 * Copyright (c) 2015 Andrew Pietila
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "decode/elf.hpp"
#include <iostream>
#include <bitset>

int main(int argc, char *argv[]) {
	FILE *file;
	file = fopen(argv[1], "r");
	//file = fopen("elfdump", "r"); //temp
	if (is32BitElf(file)) {
	} else if (is64BitElf(file)) {
		std::cout << argv[1] << ": 64-bit elf\n"; //temp

		elf64_t elf_header = getElf64Header(file);
		std::cout << "\tMagic:                    0x" << std::hex
				<< (int) elf_header.e_ident.EI_MAG0
				<< (int) elf_header.e_ident.EI_MAG1
				<< (int) elf_header.e_ident.EI_MAG2
				<< (int) elf_header.e_ident.EI_MAG3;
		std::cout << "\n";
		std::cout << "\tClass:                    " << std::dec
				<< (int) elf_header.e_ident.EI_CLASS << " (64-bit elf)\n";
		std::cout << "\tData Format:              " << std::dec
				<< (int) elf_header.e_ident.EI_CLASS;
		if (elf_header.e_ident.EI_CLASS == 2) {
			std::cout << " (big-endian)\n";
		} else {
			std::cout << " (little-endian)\n";
		}
		std::cout << "\tIdent Version:            " << std::dec
				<< (int) elf_header.e_ident.EI_VERSION;
		if (elf_header.e_ident.EI_VERSION == 0) {
			std::cout << " (invalid)\n";
		} else if (elf_header.e_ident.EI_VERSION == 1) {
			std::cout << " (current)\n";
		} else {
			std::cout << " (future)\n";
		}
		std::cout << "\tOS ABI:                   " << std::dec
				<< (int) elf_header.e_ident.EI_OSABI << " ("
				<< elfAbiDecode(elf_header.e_ident.EI_OSABI) << ")\n";
		std::cout << "\tABI Version:              " << std::dec
				<< (int) elf_header.e_ident.EI_ABIVERSION << "\n";
		std::cout << "\tPadding:                  0x";
		for (int i = 0; i < 7; i++) {
			std::cout << std::hex << elf_header.e_ident.EI_PAD[i];
		}
		std::cout << "\n";
		std::cout << "\tType:                     " << std::dec << elf_header.e_type << " ("
				<< elfTypeDecode(elf_header.e_type) << ")\n";
		std::cout << "\tMachine:                  0x" << std::hex << elf_header.e_machine << " ("
				<< elfMachineDecode(elf_header.e_machine) << ")\n";
		std::cout << "\tElf Version:              " << std::dec << elf_header.e_version;
		if (elf_header.e_ident.EI_VERSION == 0) {
			std::cout << " (invalid)\n";
		} else if (elf_header.e_version == 1) {
			std::cout << " (current)\n";
		} else {
			std::cout << " (future)\n";
		}
		std::cout << "\tEntry Point:              0x" << std::hex << elf_header.e_entry
				<< "\n";
		std::cout << "\tProgram Header Offset:    0x" << std::hex
				<< elf_header.e_phoff << "\n";
		std::cout << "\tSection Header Offset:    0x" << std::hex
				<< elf_header.e_shoff << "\n";
		std::cout << "\tElf Flags:                0b" << std::bitset<32>(elf_header.e_flags)
				<< "\n";
		std::cout << "\tElf Header Size:          " << std::dec << elf_header.e_ehsize
				<< "\n";
		std::cout << "\tElf Program Header Size:  0x" << std::hex
				<< elf_header.e_phentsize << "\n";
		std::cout << "\tElf Program Header Count: " << std::dec
				<< elf_header.e_phnum << "\n";
		std::cout << "\tElf Section Header Size:  0x" << std::hex
				<< elf_header.e_shentsize << "\n";
		std::cout << "\tElf Section Header Count: " << std::dec
				<< elf_header.e_shnum << "\n";
		std::cout << "\tStrings Table Index:      " << std::dec
				<< elf_header.e_shstrndx << "\n\n";

		for (int i = 0; i < elf_header.e_phnum; i++) {
			elf64_pheader_t program_header = getElf64ProgramHeader(file,
					elf_header.e_phoff, i);
			std::cout << "Program Header Index <" << std::dec << i << ">\n";
			std::cout << "\tProgram Header Type: " << std::hex
					<< program_header.p_type << " ("
					<< elfProgramHeaderTypeDecode(program_header.p_type)
					<< ")\n";
			std::cout << "\tSegment Offset:      0x" << std::hex
					<< program_header.p_offset << "\n";
			std::cout << "\tVirtual Address:     0x" << std::hex
					<< program_header.p_vaddr << "\n";
			std::cout << "\tPhysical Address:    0x" << std::hex
					<< program_header.p_paddr << "\n";
			std::cout << "\tSegment Filesize:    " << std::dec
					<< program_header.p_filesz << "\n";
			std::cout << "\tSegment Memsize:     " << std::dec
					<< program_header.p_memsz << "\n";
			char* segFlags = elfProgramHeaderDecodeFlags(
					program_header.p_flags);
			std::cout << "\tSegment Flags:       0b"
					<< std::bitset<32>(program_header.p_flags) << " ("
					<< segFlags << ")\n";
			free(segFlags);
			std::cout << "\tSegment Alignment:   0x" << std::hex
					<< program_header.p_align << "\n";

			std::cout << "\n";
		}

		elf64_sheader_t strings_section = getElf64SectionHeader(file,
				elf_header.e_shoff, elf_header.e_shstrndx);
		for (int i = 0; i < elf_header.e_shnum; i++) {
			elf64_sheader_t section_header = getElf64SectionHeader(file,
					elf_header.e_shoff, i);
			char* section_name = getStringsTableValue(file,
					elf_header.e_shstrndx, section_header.sh_name);
			std::cout << "Section Header Index <" << std::dec << i << ">\n";
			std::cout << "\tSection Name Index:   0x" << std::hex
					<< section_header.sh_name << "\n";
			std::cout << "\tSection Name:         '" << section_name << "'\n";
			free(section_name);
			std::cout << "\tSection Type:         0x" << std::hex
					<< section_header.sh_type << " ("
					<< elfSectionHeaderTypeDecode(section_header.sh_type)
					<< ")\n";
			std::cout << "\tSection Header Flags: 0b"
					<< std::bitset<64>(section_header.sh_flags) << "\n";
			std::cout << "\tSection Memaddr:      0x" << std::hex
					<< section_header.sh_addr << "\n";
			std::cout << "\tSection Offset:       0x" << std::hex
					<< section_header.sh_offset << "\n";
			std::cout << "\tSection Size:         " << std::dec
					<< section_header.sh_size << "\n";
			std::cout << "\tSection Link:         " << std::dec
					<< section_header.sh_link << "\n";
			std::cout << "\tSection Alignment:    0x" << std::hex
					<< section_header.sh_addralign << "\n";
			std::cout << "\tSection Entry Size:   " << std::dec
					<< section_header.sh_entsize << "\n";

			std::cout << "\n";
		}
	}
	return 0;
}
