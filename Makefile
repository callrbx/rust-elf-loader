all:
	gcc -o loader utils/loader.c
	gcc -o payload utils/sample_payload.c

clean:
	rm loader payload