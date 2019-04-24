all: build

build:
	gcc -Wall findmacs.c -o findmacs

clean:
	rm -f findmacs

.PHONY: build clean
