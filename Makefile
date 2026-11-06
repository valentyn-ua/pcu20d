CC?=cc
CFLAGS?=-O2 -g
CFLAGS+=-std=c11 -Wall -Wextra -Werror -fstack-protector-strong -fPIE
LDFLAGS+=-pie -Wl,-z,relro,-z,now
LDLIBS+=-lm

all: pcu20d

pcu20d: src/pcu20d.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ src/pcu20d.c $(LDLIBS)

clean:
	rm -f pcu20d
