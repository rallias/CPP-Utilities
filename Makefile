all: elfdump

elfdump: elfdump.o decode/elf.o
	g++ -o elfdump build/elfdump.o build/decode/elf.o
	
elfdump.o:
	g++ -o build/elfdump.o -c src/elfdump.cpp -std=c++11

decode/elf.o:
	g++ -o build/decode/elf.o -c src/decode/elf.cpp -std=c++11