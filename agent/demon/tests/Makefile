CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -O2 -g

TARGETS = demon_replay_harness

.PHONY: all run clean

all: $(TARGETS)

demon_replay_harness: replay_harness.c
	$(CC) $(CFLAGS) -o $@ $<

run: demon_replay_harness
	./demon_replay_harness ../../../tests/wire-corpus/demon/checkin

clean:
	rm -f $(TARGETS)
