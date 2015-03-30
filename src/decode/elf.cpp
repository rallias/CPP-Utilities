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

#include "elf.hpp"
#include <cstring>
#include <cstdlib>

void readBlock(FILE* stream, uint64_t offset, uint64_t size, void* object) {
	long long pos = ftello(stream);
	long long posRead = pos + offset;
	fseeko(stream, posRead, SEEK_SET);
	fread(object, size, 1, stream);
	fseeko(stream, pos, SEEK_SET);
}

char* getStringsTableValue(FILE* stream, uint64_t sh_offset, uint64_t index) {
	char* retData = (char*)malloc(128);
	long long pos = ftello(stream);
	long long posRead = pos + sh_offset + index;
	fseeko(stream, posRead, SEEK_SET);
	fgets(retData, 128, stream);
	fseeko(stream, pos, SEEK_SET);
	return retData;
}

bool uint32FlagCheck(uint32_t flags, uint32_t check) {
	return flags & check;
}

bool is32BitElf(FILE* stream) {
	uint8_t readData;
	bool retData;
	readBlock(stream, 0x04, sizeof(uint8_t), &readData);
	return readData == 1;
}

elf32_t getElf32Header(FILE* stream) {
	elf32_t retData;
	readBlock(stream, 0, sizeof(elf32_t), &retData);
	return retData;
}

bool is64BitElf(FILE* stream) {
	uint8_t readData;
	bool retData;
	readBlock(stream, 0x04, sizeof(uint8_t), &readData);
	return readData == 2;
}

elf64_t getElf64Header(FILE* stream) {
	elf64_t retData;
	readBlock(stream, 0, sizeof(elf64_t), &retData);
	return retData;
}

elf32_sheader_t getElf32SectionHeader(FILE* stream, uint16_t e_shoff,
		uint16_t index) {
	elf32_sheader_t retData;
	readBlock(stream, e_shoff + (index * sizeof(elf32_sheader_t)),
			sizeof(elf32_sheader_t), &retData);
	return retData;
}

elf64_sheader_t getElf64SectionHeader(FILE* stream, uint16_t e_shoff,
		uint16_t index) {
	elf64_sheader_t retData;
	readBlock(stream, e_shoff + (index * sizeof(elf64_sheader_t)),
			sizeof(elf64_sheader_t), &retData);
	return retData;
}

elf32_pheader_t getElf32ProgramHeader(FILE* stream, uint16_t e_phoff,
		uint16_t index) {
	elf32_pheader_t retData;
	readBlock(stream, e_phoff + (index * sizeof(elf32_pheader_t)),
			sizeof(elf32_pheader_t), &retData);
	return retData;
}

elf64_pheader_t getElf64ProgramHeader(FILE* stream, uint16_t e_phoff,
		uint16_t index) {
	elf64_pheader_t retData;
	readBlock(stream, e_phoff + (index * sizeof(elf64_pheader_t)),
			sizeof(elf64_pheader_t), &retData);
	return retData;
}

char* elfAbiDecode(uint8_t osAbiVal) {
	switch (osAbiVal) {
	case 0:
		return "System V";
		break;
	case 1:
		return "HP-UX";
		break;
	case 2:
		return "NetBSD";
		break;
	case 3:
		return "Linux";
		break;
	case 6:
		return "Solaris";
		break;
	case 7:
		return "AIX";
		break;
	case 8:
		return "IRIX";
		break;
	case 9:
		return "FreeBSD";
		break;
	case 12:
		return "OpenBSD";
		break;
	case 13:
		return "OpenVMS";
		break;
	default:
		return "Unknown";
		break;
	}
}

char* elfTypeDecode(uint16_t typeVal) {
	switch (typeVal) {
	case 1:
		return "Relocatable";
		break;
	case 2:
		return "Executable";
		break;
	case 3:
		return "Shared";
		break;
	case 4:
		return "Core";
		break;
	default:
		return "Default";
		break;
	}
}

char* elfMachineDecode(uint16_t machineVal) {
	switch (machineVal) {
	case 0x02:
		return "SPARC";
		break;
	case 0x03:
		return "x86";
		break;
	case 0x08:
		return "MIPS";
		break;
	case 0x14:
		return "PowerPC";
		break;
	case 0x28:
		return "ARM";
		break;
	case 0x2A:
		return "SuperH";
		break;
	case 0x32:
		return "IA-64";
		break;
	case 0x3E:
		return "x86_64";
		break;
	case 0xB7:
		return "AArch64";
		break;
	default:
		return "Unknown";
		break;
	}
}

char* elfProgramHeaderTypeDecode(uint32_t p_type) {
	switch (p_type) {
	case 0:
		return "PT_NULL";
		break;
	case 1:
		return "PT_LOAD";
		break;
	case 2:
		return "PT_DYNAMIC";
		break;
	case 3:
		return "PT_INTERP";
		break;
	case 4:
		return "PT_NOTE";
		break;
	case 5:
		return "PT_SHLIB";
		break;
	case 6:
		return "PT_PHDR";
		break;
	case 7:
		return "PT_TLS";
		break;
	case 0x6474e550:
		return "OS-Defined, PT_GNU_EH_FRAME";
		break;
	case 0x6474e551:
		return "OS-Defined, PT_GNU_STACK";
		break;
	default:
		if (p_type >= 0x60000000 && p_type <= 0x6FFFFFFF) {
			return "OS-Defined";
		} else if (p_type >= 0x70000000 && p_type <= 0x7FFFFFFF) {
			return "Processor-Defined";
		} else {
			return "Unknown";
		}
	}
}

char* elfProgramHeaderDecodeFlags(uint32_t p_flags) {
	bool osDefinedFlags; // OS-Defined
	for (int i = 20; i < 28; i++) {
		osDefinedFlags = osDefinedFlags || (p_flags & 0x1 << i);
	}

	bool processorDefinedFlags; // Processor-Defined
	for (int i = 28; i < 32; i++) {
		processorDefinedFlags = processorDefinedFlags
				|| uint32FlagCheck(p_flags, 0x1 << i);
	}

	bool executeFlag = uint32FlagCheck(p_flags, 0x1); // Execute
	bool writeFlag = uint32FlagCheck(p_flags, 0x2); // Write
	bool readFlag = (p_flags & 0x4); // Read

	int alloc = 1;
	if (readFlag) {
		alloc += 6;
	}

	if (writeFlag) {
		alloc += 7;
	}

	if (executeFlag) {
		alloc += 9;
	}

	if (osDefinedFlags) {
		alloc += 12;
	}

	if (processorDefinedFlags) {
		alloc += 19;
	}

	char* retData = (char*) malloc(alloc);
	char* retDataInLieu;
	retDataInLieu = retData;

	if (processorDefinedFlags) {
		strcpy(retDataInLieu, "Processor-Defined, ");
		retDataInLieu += 19;
	}

	if (osDefinedFlags) {
		strcpy(retDataInLieu, "OS-Defined, ");
		retDataInLieu += 12;
	}

	if (readFlag) {
		strcpy(retDataInLieu, "Read, ");
		retDataInLieu += 6;
	}

	if (writeFlag) {
		strcpy(retDataInLieu, "Write, ");
		retDataInLieu += 7;
	}

	if (executeFlag) {
		strcpy(retDataInLieu, "Execute, ");
		retDataInLieu += 9;
	}

	retDataInLieu -= 2;

	*retDataInLieu = 0;

	return retData;
}

char* elfSectionHeaderTypeDecode(uint32_t sh_type) {
	switch (sh_type) {
	case 0:
		return "SHT_NULL";
		break;
	case 1:
		return "SHT_PROGBITS";
		break;
	case 2:
		return "SHT_SYMTAB";
		break;
	case 3:
		return "SHT_STRTAB";
		break;
	case 4:
		return "SHT_RELA";
		break;
	case 5:
		return "SHT_HASH";
		break;
	case 6:
		return "SHT_DYNAMIC";
		break;
	case 7:
		return "SHT_NOTE";
		break;
	case 8:
		return "SHT_NOBITS";
		break;
	case 9:
		return "SHT_REL";
		break;
	case 10:
		return "SHT_SHLIB";
		break;
	case 11:
		return "SHT_DYNSYM";
		break;
	case 14:
		return "SHT_INIT_ARRAY";
		break;
	case 15:
		return "SHT_FINI_ARRAY";
		break;
	case 16:
		return "SHT_PREINIT_ARRAY";
		break;
	case 17:
		return "SHT_GROUP";
		break;
	case 18:
		return "SHT_SYMTAB_SHNDX";
		break;
	default:
		if (sh_type >= 0x60000000 && sh_type <= 0x6FFFFFFF) {
			return "OS-Specific";
		} else if (sh_type >= 0x70000000 && sh_type <= 0x7FFFFFFF) {
			return "Processor-Specific";
		} else if (sh_type >= 0x80000000 && sh_type <= 0xFFFFFFFF) {
			return "User-Defined";
		} else {
			return "Unknown";
		}
	}
}
