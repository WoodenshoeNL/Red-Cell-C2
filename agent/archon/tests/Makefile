CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -O2 -g
TARGETS = test_crypto test_synth_stack

.PHONY: all run clean

all: $(TARGETS)

test_crypto: test_crypto.c
	$(CC) $(CFLAGS) -o $@ $<

test_synth_stack: test_synth_stack.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGETS)
	./test_crypto
	./test_synth_stack

clean:
	rm -f $(TARGETS)
