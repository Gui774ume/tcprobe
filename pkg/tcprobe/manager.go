/*
Copyright © 2022 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tcprobe

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/tcprobe/ebpf/assets"
	"github.com/Gui774ume/tcprobe/pkg/kernel"
	"github.com/Gui774ume/tcprobe/pkg/tcprobe/events"
)

func (tp *TCProbe) startManager() error {
	// setup a default manager
	tp.prepareManager()

	// load vmlinux
	if err := tp.loadVMLinux(); err != nil {
		return fmt.Errorf("couldn't load kernel BTF specs, please try to provide one in the configuration: %w", err)
	}

	// initialize the manager
	if err := tp.manager.InitWithOptions(bytes.NewReader(assets.Probe), tp.managerOptions); err != nil {
		return fmt.Errorf("couldn't init manager: %w", err)
	}

	// select kernel space maps
	if err := tp.selectMaps(); err != nil {
		return err
	}

	// load filters
	if err := tp.loadFilters(); err != nil {
		return err
	}

	logrus.Infoln("TCProbe is now running (Ctrl + C to stop)\n")

	// start the manager
	if err := tp.manager.Start(); err != nil {
		return fmt.Errorf("couldn't start manager: %w", err)
	}

	tp.startTime = time.Now()
	return nil
}

func (tp *TCProbe) prepareManager() {
	tp.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},

		ConstantEditors: []manager.ConstantEditor{},
	}
	tp.manager = &manager.Manager{
		Probes: events.AllProbes(),
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "events"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8192 * os.Getpagesize(),
					DataHandler: func(CPU int, data []byte, perfMap *manager.PerfMap, manager *manager.Manager) {
						if err := tp.handleEvent(data); err != nil {
							logrus.Errorf("couldn't handle event: %v", err)
						}
					},
				},
			},
		},
	}
}

func (tp *TCProbe) loadVMLinux() error {
	var btfSpec *btf.Spec
	var err error

	if len(tp.options.VMLinux) > 0 {
		f, err := createBTFReaderFromTarball(tp.options.VMLinux)
		if err != nil {
			return err
		}

		// if a vmlinux file was provided, open it now
		btfSpec, err = btf.LoadSpecFromReader(f)
		if err != nil {
			return fmt.Errorf("couldn't load %s: %w", tp.options.VMLinux, err)
		}
	} else {
		// try to open vmlinux from the default locations
		btfSpec, err = btf.LoadKernelSpec()
		if err != nil {
			// fetch the BTF spec from btfhub
			btfSpec, err = tp.loadSpecFromBTFHub()
			if err != nil {
				return fmt.Errorf("couldn't load kernel BTF specs from BTFHub: %w", err)
			}
		}
	}
	tp.managerOptions.VerifierOptions.Programs.KernelTypes = btfSpec
	return nil
}

const (
	// BTFHubURL is the URL to BTFHub github repository
	BTFHubURL = "https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/x86_64/%s.btf.tar.xz"
)

func (tp *TCProbe) loadSpecFromBTFHub() (*btf.Spec, error) {
	h, err := kernel.NewHost()
	if err != nil {
		return nil, err
	}

	// check the local TCProbe cache first
	file := fmt.Sprintf("/tmp/%s.tar.xz", h.UnameRelease)
	if _, err = os.Stat(file); err != nil {
		// download the file now
		url := fmt.Sprintf(BTFHubURL, h.OsRelease["ID"], h.OsRelease["VERSION_ID"], h.UnameRelease)
		logrus.Infof("Downloading BTF specs from %s ...", url)

		// Get the data
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("couldn't download BTF specs from BTFHub: %w", err)
		}
		defer resp.Body.Close()

		// Create the file
		out, err := os.Create(file)
		if err != nil {
			return nil, fmt.Errorf("couldn't create local BTFHub cache at %s: %w", file, err)
		}
		defer out.Close()

		// Write the body to file
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return nil, fmt.Errorf("couldn't create local BTFHub cache at %s: %w", file, err)
		}
	}

	f, err := createBTFReaderFromTarball(file)
	if err != nil {
		return nil, err
	}

	// if a vmlinux file was provided, open it now
	btfSpec, err := btf.LoadSpecFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("couldn't load %s: %w", tp.options.VMLinux, err)
	}

	return btfSpec, nil
}

func (tp *TCProbe) selectMaps() error {
	return nil
}

func (tp *TCProbe) loadFilters() error {
	return nil
}
