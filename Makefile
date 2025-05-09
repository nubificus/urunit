# Copyright (c) 2023-2025, Nubificus LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

# Path variables
#
# Use absolute paths just for sanity
#? BUILD_DIR Directory to place produced binaries (default: ${CWD}/dist)
BUILD_DIR ?= ${CURDIR}/dist
#? PREFIX Directory to install urunit (default: /usr/local/bin)
PREFIX    ?= /usr/local/bin

# Binary variables
URUNIT_BIN_DYNAMIC:= $(BUILD_DIR)/urunit_dynamic
URUNIT_BIN_STATIC := $(BUILD_DIR)/urunit_static

# Compiler variables
#? CC the compiler to use (default: gcc)
CC     ?= gcc
CFLAGS := -Werror -Wextra -Wall -pedantic-errors -Wformat
CFLAGS += -std=gnu99 -O2 -fstack-protector --param=ssp-buffer-size=4

# Linking FLAGS
LDFLAGS        := -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-s
STATIC_LDFLAGS := -Wl,--no-export-dynamic -static

# Source files variables
URUNIT_SRC := main.c

# Install dependencies variables
#
# If we have already built either static or dynamic version of urunit
# we do not have to rebuild it, but instead we can install whichever
# version is available. However, the dynamic version
# has always a preference.
INSTALL_DEPS   =  $(shell test -e $(URUNIT_BIN_STATIC) \
                          && echo $(URUNIT_BIN_STATIC) && exit \
                          || test -e $(URUNIT_BIN_DYNAMIC) \
                             && echo $(URUNIT_BIN_DYNAMIC) \
                             || echo $(URUNIT_BIN_STATIC))

# Main Building rules
#
# By default we opt to build static binaries targeting the host archiotecture.

## default Build urunit statically for host arch.(default).
.PHONY: default
default: $(URUNIT_BIN_STATIC)

## all Build urunit statically and dynamically for host arch.
.PHONY: all
all: $(URUNIT_BIN_STATIC) $(URUNIT_BIN_DYNAMIC)

# Just an alias for $(BUILD_DIR) for easier invocation
## prepare alias for creating the build directory.
prepare: $(BUILD_DIR)

## static Build urunit statically-linked for host arch.
.PHONY: static
static: $(URUNIT_BIN_STATIC)

## dynamic Build urunit dynamically-linked for host arch.
.PHONY: dynamic
dynamic: $(URUNIT_BIN_DYNAMIC)

$(BUILD_DIR):
	mkdir -p $@

$(URUNIT_BIN_DYNAMIC): $(URUNIT_SRC) | prepare
	$(CC) $(CFLAGS) $(URUNIT_SRC) $(LDFLAGS) -o $@

$(URUNIT_BIN_STATIC): $(URUNIT_SRC) | prepare
	$(CC) $(CFLAGS) $(URUNIT_SRC) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@

## install Install urunit in PREFIX
.PHONY: install
install: $(INSTALL_DEPS)
	install -m 0755 $^ $(PREFIX)/urunit

clean:
	rm -f $(BIN) $(BIN_STATIC)
	rm -rf $(BUILD_DIR)

## help Show this help message
help:
	@echo 'Usage: make <target> <flags>'
	@echo 'Targets:'
	@grep -w "^##" $(MAKEFILE_LIST) | sed -n 's/^## /\t/p' | sed -n 's/ /\@/p' | column -s '\@' -t
	@echo 'Flags:'
	@grep -w "^#?" $(MAKEFILE_LIST) | sed -n 's/^#? /\t/p' | sed -n 's/ /\@/p' | column -s '\@' -t
