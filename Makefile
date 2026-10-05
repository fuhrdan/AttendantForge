CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -Iinclude -Isrc
BUILD := build-make

CORE := src/attendantforge.c src/zip_analyzer.c src/pdf_analyzer.c src/policy.c src/probe.c src/format_analyzer.c

.PHONY: all test clean

all: $(BUILD)/attendantforge

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/attendantforge: $(CORE) src/main.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CORE) src/main.c -o $@

$(BUILD)/attendantforge_tests: $(CORE) tests/test_main.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CORE) tests/test_main.c -o $@

test: $(BUILD)/attendantforge_tests
	./$(BUILD)/attendantforge_tests

clean:
	rm -rf $(BUILD) build
