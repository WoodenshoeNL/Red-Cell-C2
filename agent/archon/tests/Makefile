CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -O2 -g
TARGETS = test_crypto test_synth_stack test_heap_enc test_pe_header_erase \
          test_tp_callback test_doh_transport test_amsi_etw test_cronos \
          test_module_stomp test_ja3 test_ecdh_init test_transport_http_helpers \
          archon_replay_harness

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

test_tp_callback: test_tp_callback.c
	$(CC) $(CFLAGS) -o $@ $<

test_doh_transport: test_doh_transport.c
	$(CC) $(CFLAGS) -o $@ $<

test_amsi_etw: test_amsi_etw.c
	$(CC) $(CFLAGS) -o $@ $<

test_cronos: test_cronos.c
	$(CC) $(CFLAGS) -o $@ $<

test_module_stomp: test_module_stomp.c
	$(CC) $(CFLAGS) -o $@ $<

test_ja3: test_ja3.c
	$(CC) $(CFLAGS) -o $@ $<

test_ecdh_init: test_ecdh_init.c
	$(CC) $(CFLAGS) -I../include -o $@ $<

test_transport_http_helpers: test_transport_http_helpers.c ../src/core/TransportHttpHelpers.inc.h
	$(CC) $(CFLAGS) -o $@ test_transport_http_helpers.c

archon_replay_harness: replay_harness.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGETS)
	./test_crypto
	./test_synth_stack
	./test_heap_enc
	./test_pe_header_erase
	./test_tp_callback
	./test_doh_transport
	./test_amsi_etw
	./test_cronos
	./test_module_stomp
	./test_ja3
	./test_ecdh_init
	./test_transport_http_helpers
	./archon_replay_harness ../../../tests/wire-corpus/demon/checkin

clean:
	rm -f $(TARGETS)
