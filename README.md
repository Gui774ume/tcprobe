## TCProbe

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

TCProbe is an eBPF powered that traces the Traffic Control of the Linux Kernel.

TCProbe has been developed using [CO-RE (Compile Once - Run Everywhere)](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) so that it is compatible with a large range of kernel versions. If your kernel doesn't export its BTF debug information, TCProbe will try to download it automatically from [BTFHub](https://github.com/aquasecurity/btfhub). If your kernel isn't available on BTFHub, but you have been able to manually generate your kernel's BTF data, you can provide it in the configuration file (see below).

### System requirements

This project was developed on Ubuntu Focal 20.04 (Linux Kernel 5.15).

- golang 1.18+
- (optional) Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- (optional) clang & llvm 14.0.6+

Optional fields are required to recompile the eBPF programs.

### Build

1) Since TCProbe was built using CORE, you shouldn't need to rebuild the eBPF programs. That said, if you want still want to rebuild the eBPF programs, you can use the following command:

```shell script
# ~ make build-ebpf
```

2) To build TCProbe, run:

```shell script
# ~ make build
```

3) To install TCProbe (copy to /usr/bin/tcprobe) run:
```shell script
# ~ make install
```

### Getting started

TCProbe needs to run as root. Run `sudo tcprobe -h` to get help.

```shell script
# ~ tcprobe -h
Usage:
  tcprobe [flags]

Flags:
      --config string   TCProbe config file (default "./cmd/tcprobe/run/config/default_config.yaml")
  -h, --help            help for tcprobe
```

### Configuration

```yaml
## Log level, options are: panic, fatal, error, warn, info, debug or trace
log_level: debug

## JSON output file, leave empty to disable JSON output.
output: "/tmp/tcprobe.json"

## BTF information for the current kernel in .tar.xz format (required only if TCProbe isn't able to locate it by itself)
vmlinux: ""

## URL to the local datadog logs agent
datadog_logs_url: "127.0.0.1:10518"
```

## License

- The golang code is under Apache 2.0 License.
- The eBPF programs are under the GPL v2 License.