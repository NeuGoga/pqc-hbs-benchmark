CXX ?= g++
CXXFLAGS ?= -std=c++17 -O3 -Wall -fopenmp -march=native
HBS_INC = -I libs/hbs/include -I libs/hbs/src
HBS_SRC = \
	libs/hbs/src/crypto/keccak.cpp \
	libs/hbs/src/crypto/shake.cpp \
	libs/hbs/src/crypto/rng.cpp \
	libs/hbs/src/crypto/utils.cpp \
	libs/hbs/src/sphincs/address.cpp \
	libs/hbs/src/sphincs/params.cpp \
	libs/hbs/src/sphincs/hash.cpp \
	libs/hbs/src/sphincs/wots.cpp \
	libs/hbs/src/sphincs/fors.cpp \
	libs/hbs/src/sphincs/sphincs.cpp \
	libs/hbs/src/merkle/merkle.cpp \
	libs/hbs/src/registry.cpp

.PHONY: all worker test clean

all: worker

worker: benchmark

benchmark: src/benchmark.cpp $(HBS_SRC)
	$(CXX) $(CXXFLAGS) $(HBS_INC) -DPQC_HAS_CUSTOM_SPHINCS=1 -o $@ src/benchmark.cpp $(HBS_SRC)

tester: src/tester.cpp
	$(CXX) $(CXXFLAGS) -o $@ src/tester.cpp

test: tests/test_hbs.cpp $(HBS_SRC)
	$(CXX) $(CXXFLAGS) $(HBS_INC) -o test_hbs tests/test_hbs.cpp $(HBS_SRC)
	./test_hbs

clean:
	rm -f benchmark tester test_hbs
