# Open Commissioning Model --- reference build
#
#   make          build the library (build/libocm.a)
#   make demo     build and run the narrated end-to-end flow
#   make test     build and run the test suite
#   make clean

CC      ?= cc
CSTD    ?= -std=c11
WARN    ?= -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
CFLAGS  ?= -O2 -g
CFLAGS  += $(CSTD) $(WARN) -Iinclude $(shell pkg-config --cflags libsodium)
LDLIBS  += $(shell pkg-config --libs libsodium)

BUILD   := build
LIB_SRC := $(wildcard src/*.c)
LIB_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRC))
LIB     := $(BUILD)/libocm.a

SIM_SRC := sim/storage_mock.c
SIM_OBJ := $(BUILD)/storage_mock.o

.PHONY: all demo test clean

all: $(LIB)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/storage_mock.o: sim/storage_mock.c sim/storage_mock.h | $(BUILD)
	$(CC) $(CFLAGS) -Isim -c $< -o $@

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/flow_demo: sim/flow_demo.c $(LIB) $(SIM_OBJ)
	$(CC) $(CFLAGS) -Isim $< $(SIM_OBJ) $(LIB) $(LDLIBS) -o $@

$(BUILD)/test_ocm: tests/test_ocm.c $(LIB) $(SIM_OBJ)
	$(CC) $(CFLAGS) -Isim -Itests $< $(SIM_OBJ) $(LIB) $(LDLIBS) -o $@

$(BUILD)/fleet_sim: sim/fleet_sim.c $(LIB) $(SIM_OBJ)
	$(CC) $(CFLAGS) -Isim $< $(SIM_OBJ) $(LIB) $(LDLIBS) -o $@

demo: $(BUILD)/flow_demo
	./$(BUILD)/flow_demo

test: $(BUILD)/test_ocm
	./$(BUILD)/test_ocm

fleet: $(BUILD)/fleet_sim
	./$(BUILD)/fleet_sim $(N)

clean:
	rm -rf $(BUILD)
