CC=gcc
CFLAGS=-Wall -Werror -Wextra
IPATH=/home/dremdor/openssl/include
LPATH=/home/dremdor/openssl/lib64
OUT=fiutil
OBJ=*.o
SRC_FILES=src/*.c
LIB_LINKS=-lssl -lcrypto -static

all: fiutil

fiutil: build.o
	$(CC) $(CFLAGS) -I$(IPATH) -L$(LPATH) -o $(OUT) $(OBJ) $(LIB_LINKS)
	rm -rf $(OBJ)

build.o:
	$(CC) -c $(CFLAGS) $(SRC_FILES) 

test: clean $(OUT)
	./$(OUT) 
	sha256sum test/1.txt > test2.txt
	diff -s test.txt test2.txt

clean:
	rm -rf $(OUT) $(OBJ) test*.txt

