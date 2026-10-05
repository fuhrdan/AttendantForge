CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
BUILD_DIR := build
SRC := src/main.c src/attendantforge.c
TEST_SRC := tests/test_main.c src/attendantforge.c

.PHONY: all clean test

all: $(BUILD_DIR)/attendantforge

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/attendantforge: $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $@

$(BUILD_DIR)/test_attendantforge: $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_SRC) -o $@

test: $(BUILD_DIR)/test_attendantforge
	./$(BUILD_DIR)/test_attendantforge

clean:
	rm -rf $(BUILD_DIR)
