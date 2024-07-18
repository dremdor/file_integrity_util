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
	echo "hello" > test/1.txt
	echo "world" > test/2.txt
	echo "!" > test/3.txt
	./$(OUT) set test/ log.txt 
	rm test/3.txt
	echo "modified" >> test/2.txt
	echo "new file" > test/4.txt
	./$(OUT) check test/ log.txt 
	grep "fiutil" /var/log/syslog | tail

clean:
	rm -rf $(OUT) $(OBJ) *.txt

