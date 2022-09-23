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
	"fmt"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Options contains the parameters of TCProbe
type Options struct {
	// from config file
	LogLevel       LogLevel `yaml:"log_level"`
	Output         string   `yaml:"output"`
	VMLinux        string   `yaml:"vmlinux"`
	DatadogLogsURL string   `yaml:"datadog_logs_url"`

	EventHandler func(data []byte) error `yaml:"-"`
}

func (o Options) IsValid() error {
	return nil
}

// NewOptions returns a default set of options
func NewOptions() *Options {
	return &Options{}
}

// LogLevel is a wrapper around logrus.Level to unmarshal a log level from yaml
type LogLevel logrus.Level

// UnmarshalYAML parses a string representation of a logrus log level
func (kll *LogLevel) UnmarshalYAML(value *yaml.Node) error {
	var level string
	err := value.Decode(&level)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}

	var sanitized logrus.Level
	if len(level) > 0 {
		sanitized, err = logrus.ParseLevel(level)
		if err != nil {
			return err
		}
	} else {
		sanitized = logrus.DebugLevel
	}
	*kll = LogLevel(sanitized)
	return nil
}
