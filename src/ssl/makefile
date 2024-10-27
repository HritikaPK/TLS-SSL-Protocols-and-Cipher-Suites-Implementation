CC = g++
CFLAGS = -c -Wall -g -I../tcp -I../cryptopp
LDFLAGS = 

SRC = ssl_server.cc ssl_client.cc ssl.cc crypto_adaptor.cc
OBJ = $(SRC:.cc=.o)
TARGET = libmyssl.a

.PHONY: init lib clean

all: init lib

init: 
	# set -e
	(cd ../cryptopp && make)
	(cd ../tcp && make lib)
	# cp ../tcp/tcp.h ../tcp/utils.h ../tcp/logger.h .
	cp ../tcp/libmytcp.a $(TARGET)
	# (cd ../tcp && make clean)

lib: $(OBJ)
	ar -rv $(TARGET) $^

ls:
	ar -t $(TARGET)

clean:
	rm -f *.o *.d $(TARGET)

%.o: %.cc
	$(CC) $(CFLAGS) $< -o $@
