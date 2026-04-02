CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -O2 -g
TARGETS = test_crypto test_synth_stack test_heap_enc test_pe_header_erase

.PHONY: all run clean

all: $(TARGETS)

test_crypto: test_crypto.c
	$(CC) $(CFLAGS) -o $@ $<

test_synth_stack: test_synth_stack.c
	$(CC) $(CFLAGS) -o $@ $<

test_heap_enc: test_heap_enc.c
	$(CC) $(CFLAGS) -o $@ $<

test_pe_header_erase: test_pe_header_erase.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGETS)
	./test_crypto
	./test_synth_stack
	./test_heap_enc
	./test_pe_header_erase

clean:
	rm -f $(TARGETS)
