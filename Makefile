all: main
sqlifirewall: sqlifirewall.c
	gcc -c sqlifirewall.c -lpcre
main: sqlifirewall.o
	gcc sqlifirewall.o -o sqlifirewall -lpcre

