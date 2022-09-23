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

package run

import (
	"fmt"
	"os"

	"github.com/Gui774ume/tcprobe/pkg/tcprobe"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	Config         string
	TCProbeOptions *tcprobe.Options
}

// TCProbeOptionsSanitizer is a generic options sanitizer for TCProbe
type TCProbeOptionsSanitizer struct {
	field   string
	options *CLIOptions
}

// NewTCProbeOptionsSanitizer creates a new instance of TCProbeOptionsSanitizer
func NewTCProbeOptionsSanitizer(options *CLIOptions, field string) *TCProbeOptionsSanitizer {
	options.Config = "./cmd/tcprobe/run/config/default_config.yaml"

	return &TCProbeOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (tpos *TCProbeOptionsSanitizer) String() string {
	switch tpos.field {
	case "config":
		return tpos.options.Config
	default:
		return ""
	}
}

func (tpos *TCProbeOptionsSanitizer) Set(val string) error {
	switch tpos.field {
	case "config":
		_, err := os.Stat(val)
		if err != nil {
			return fmt.Errorf("couldn't find config file %s: %w", val, err)
		}
		tpos.options.Config = val
		return nil
	default:
		return nil
	}
}

func (tpos *TCProbeOptionsSanitizer) Type() string {
	switch tpos.field {
	case "config":
		return "string"
	default:
		return ""
	}
}
