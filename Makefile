all:
	gcc -o loader utils/loader.c
	gcc -o payload utils/sample_payload.c
	gcc -o payload-static --static utils/sample_payload.c
	nasm -f elf64 utils/payload-asm.s
	ld --dynamic-linker=/lib64/ld-linux-x86-64.so.2 -pie utils/payload-asm.o -o payload-asm
	rm utils/payload-asm.o

clean:
	rm loader payload payload-static payload-asm