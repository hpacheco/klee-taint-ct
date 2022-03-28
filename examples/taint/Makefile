# Get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# very hacky but oh well
KLEE_DIR=$(shell dirname $$(which klee))/../..

SUFFIX=.cpp

ifeq ($(IS_C),1)
# clang++ -> clang no matter the version
OLD_CC:=$(CC)
CC=$(subst ++,,$(OLD_CC))
SUFFIX=.c
endif

CFLAGS+=-emit-llvm -O0 -DDIRECT -fno-exceptions -c
INCLUDE_DIRS+=-I . -I $(SELF_DIR)/../../include/ -I $(SELF_DIR)/openssl/build/include/ -isystem $(SELF_DIR)/sec16almeida

KLEE_LIB_ARGS?=--libc=uclibc --posix-runtime -link-llvm-lib=$(SELF_DIR)/openssl/build/crypto/libcrypto.bc

KLEE_COMMAND=/usr/bin/time -v klee -allocate-determ -allocate-determ-start-address=0x00040000000 -allocate-determ-size=1000 \
							--disable-verify -write-sym-paths -dump-call-traces -dump-call-trace-tree -dump-constraint-tree \
							-taint=direct $(KLEE_LIB_ARGS) \
							-solver-backend=z3 -exit-on-error -max-memory=750000 -search=dfs -condone-undeclared-havocs \
                                                        -dump-call-trace-instructions -call-trace-instr-startfn=main -call-trace-instr-endfn=main \
#                                                        -const-array-opt=true -optimize-array=all

clean:
	rm -Rf klee-*
	rm -f *.bc

verify:
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) $(SSL_TARGET)$(SUFFIX) -o $(SSL_TARGET).bc
	$(KLEE_COMMAND) $(SSL_TARGET).bc

SHELL=/bin/bash
contract:
#	cd $(KLEE_DIR)/../bolt/perf-contracts && make clean && make LLVM=TRUE KLEE_INCLUDE=$(KLEE_DIR)/include
#	cd klee-last && $(KLEE_DIR)/scripts/process-traces.sh . verify-dpdk llvm Num_bucket_traversals 1 Num_hash_collisions 0  expired_flows 0
#	export KLEE_INCLUDE=$(KLEE_DIR)/include ; $(KLEE_DIR)/scripts/tree-gen/build_trees.sh -m 1000 -n 0 -e llvm
	$(KLEE_DIR)/scripts/stateless_perf.sh klee-last combined_perf.txt main llvm
	cp klee-last/combined_perf.txt klee-last/perf-formula.txt
	export KLEE_INCLUDE=$(KLEE_DIR)/include ; $(KLEE_DIR)/scripts/tree-gen/build_trees.sh -m 1000 -n 0
