CLANG     ?= clang
MULTIARCH := $(shell uname -m)-linux-gnu
INCLUDES  ?= -I/usr/include/$(MULTIARCH)

.RECIPEPREFIX = >

all: fortress_xdp.o

fortress_xdp.o: fortress_xdp.c
> $(CLANG) -O2 -g -Wall -target bpf $(INCLUDES) -c $< -o $@

clean:
> rm -f fortress_xdp.o

.PHONY: all clean
