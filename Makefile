all: build

build: arpdetect.o
	gcc -lpcap arpdetect.o -o arpdetect

arpdetect.o:
	gcc -c arpdetect.c

clean:
	rm -rfv *.o arpdetect
