CC=gcc
CFLAGS=-Wall -Werror -Wextra 
LPATH=/home/dremdor/openssl/lib64
OUT=fiutil
OBJ=*.o
SRC_FILES=src/*.c
LIB_LINKS=-lssl -lcrypto -static

all: clean fiutil

fiutil: build.o
	$(CC) $(CFLAGS) -L$(LPATH) -o $(OUT) $(OBJ) $(LIB_LINKS)
	rm -rf $(OBJ)

build.o:
	$(CC) -c $(CFLAGS) $(SRC_FILES) 

test: clean $(OUT)
	./$(OUT) 
	sha256sum test/1.txt > test2.txt
	diff -s test.txt test2.txt

clean:
	rm -rf $(OUT) $(OBJ) *.txt

