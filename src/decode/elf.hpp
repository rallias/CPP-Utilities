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

#include <cstdint>
#include <cstdio>
#ifndef DECODE_ELF_HPP
#define DECODE_ELF_HPP

typedef struct {
	uint8_t EI_MAG0;
	uint8_t EI_MAG1;
	uint8_t EI_MAG2;
	uint8_t EI_MAG3;
	uint8_t EI_CLASS;
	uint8_t EI_DATA;
	uint8_t EI_VERSION;
	uint8_t EI_OSABI;
	uint8_t EI_ABIVERSION;
	uint8_t EI_PAD[7];
} elf_ident_t;

typedef struct {
	elf_ident_t e_ident;
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} elf32_t;

typedef struct {
	elf_ident_t e_ident;
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} elf64_t;

typedef struct {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
} elf32_sheader_t;

typedef struct {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
} elf64_sheader_t;

typedef struct {
	uint32_t	p_type;
	uint32_t	p_offset;
	uint32_t	p_vaddr;
	uint32_t	p_paddr;
	uint32_t	p_filesz;
	uint32_t	p_memsz;
	uint32_t	p_flags;
	uint32_t	p_align;
} elf32_pheader_t;

typedef struct {
	uint32_t	p_type;
	uint32_t	p_flags;
	uint64_t	p_offset;
	uint64_t	p_vaddr;
	uint64_t	p_paddr;
	uint64_t	p_filesz;
	uint64_t	p_memsz;
	uint64_t	p_align;
} elf64_pheader_t;

bool is32BitElf (FILE* stream);
elf32_t getElf32Header(FILE* stream);
bool is64BitElf (FILE* stream);
elf64_t getElf64Header(FILE* stream);
elf32_sheader_t getElf32SectionHeader(FILE* stream, uint16_t e_shoff, uint16_t index);
elf64_sheader_t getElf64SectionHeader(FILE* stream, uint16_t e_shoff, uint16_t index);
char* elfAbiDecode(uint8_t osAbiVal);
char* elfTypeDecode(uint16_t typeVal);
char* elfMachineDecode(uint16_t machineVal);
elf32_pheader_t getElf32ProgramHeader(FILE* stream, uint16_t e_phoff, uint16_t index);
elf64_pheader_t getElf64ProgramHeader(FILE* stream, uint16_t e_phoff, uint16_t index);
char* elfProgramHeaderTypeDecode(uint32_t p_type);
char* elfProgramHeaderDecodeFlags(uint32_t p_flags);
char* getStringsTableValue(FILE* stream, uint64_t sh_offset, uint64_t index);
char* elfSectionHeaderTypeDecode(uint32_t sh_type);

#endif
