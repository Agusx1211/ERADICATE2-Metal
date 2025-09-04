CC=clang++
CDEFINES=
SOURCES=eradicate2_metal.mm hexadecimal.cpp ModeFactory.cpp Speed.cpp sha3.cpp

# Output directories
BUILD_DIR?=build
OBJ_DIR?=$(BUILD_DIR)/obj
BIN_DIR?=$(BUILD_DIR)

# Build object list explicitly per extension to avoid missed substitutions
CPP_SRCS=$(filter %.cpp,$(SOURCES))
MM_SRCS=$(filter %.mm,$(SOURCES))
OBJECTS=$(addprefix $(OBJ_DIR)/,$(patsubst %.cpp,%.o,$(CPP_SRCS)) $(patsubst %.mm,%.o,$(MM_SRCS)))
EXECUTABLE=$(BIN_DIR)/ERADICATE2

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS=-framework Metal -framework Foundation
    CFLAGS=-c -std=c++17 -Wall -O2 -fobjc-arc
else
    $(error Metal build only supported on macOS)
endif

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(CDEFINES) -c $< -o $@

$(OBJ_DIR)/%.o: %.mm | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(CDEFINES) -c $< -o $@

# Explicit rule to ensure ObjC++ main compiles on all make variants
$(OBJ_DIR)/eradicate2_metal.o: eradicate2_metal.mm | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(CDEFINES) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
