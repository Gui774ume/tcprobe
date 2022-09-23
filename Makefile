all: build-ebpf build install

build-ebpf: build-ebpf-programs generate

build-ebpf-programs:
	mkdir -p ebpf/assets/bin
	clang-14 -D__KERNEL__ -DCONFIG_64BIT -D__ASM_SYSREG_H -D__x86_64__ -D__BPF_TRACING__ -DKBUILD_MODNAME=\"tcprobe\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
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
