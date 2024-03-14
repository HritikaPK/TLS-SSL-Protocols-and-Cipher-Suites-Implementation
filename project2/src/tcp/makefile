CC = g++
CFLAGS = -c -Wall -g
LDFLAGS = 

SRC = tcp.cc logger.cc utils.cc tcp_client.cc tcp_server.cc
OBJ = $(SRC:.cc=.o)
TARGET = libmytcp.a

.PHONY: lib clean

all: lib

lib: $(OBJ)
	ar -rv $(TARGET) $^

ls:
	ar -t $(TARGET)

clean:
	rm -f *.o *.d $(TARGET)

%.o: %.cc
	$(CC) $(CFLAGS) $< -o $@
