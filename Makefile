.PHONY: build_dir all build clean detach attach dump_maps iface-inspect

CC := clang
CFLAGS = -O2 -g -target bpf
LDFLAGS =
MAP = udp_rate_limit
SOURCES = $(wildcard src/*.c)
BUILD_DIR = build
OBJECTS = $(addprefix $(BUILD_DIR)/, $(notdir $(SOURCES:.c=.o)))
TARGET = ddos_protection
IFACE ?= eth0  # Default to eth0 if not provided

all: build

build: build_dir $(OBJECTS)

$(BUILD_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

build_dir:
	@mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)/*

attach:
	sudo ip link set dev $(IFACE) xdp obj $(OBJECTS) sec xdp

detach:
	sudo ip link set dev $(IFACE) xdp off

iface-inspect:
	sudo ip link show $(IFACE)

dump_maps:
	sudo bpftool map dump name $(MAP) -g &> /dev/null
