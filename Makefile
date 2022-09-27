all: build-ebpf build install

build-ebpf: build-ebpf-programs generate

SUBARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
				  -e s/sun4u/sparc64/ \
				  -e s/arm.*/arm/ -e s/sa110/arm/ \
				  -e s/s390x/s390/ -e s/parisc64/parisc/ \
				  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
				  -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ )

build-ebpf-programs:
	mkdir -p ebpf/assets/bin
	clang-14 \
		-D__TARGET_ARCH_$(SUBARCH) \
		-D__BPF_TRACING__ \
		-DKBUILD_MODNAME=\"tcprobe\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o ebpf/assets/bin/probe.o

generate:
	go generate ./...

build:
	mkdir -p bin/
	go build -o bin/ ./cmd/...

install:
	sudo cp ./bin/* /usr/bin/
	sudo chmod aog+x /usr/bin/tcprobe
