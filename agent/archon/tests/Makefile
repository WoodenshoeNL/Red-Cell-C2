CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -O2 -g
TARGET  = test_crypto
SRC     = test_crypto.c

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
