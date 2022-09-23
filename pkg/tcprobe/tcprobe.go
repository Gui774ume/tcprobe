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
	"os"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/tcprobe/pkg/tcprobe/events"
)

// TCProbe is the main TCProbe structure
type TCProbe struct {
	event        *events.Event
	handleEvent  func(data []byte) error
	timeResolver *events.TimeResolver
	outputFile   *os.File

	options        *Options
	manager        *manager.Manager
	managerOptions manager.Options

	startTime     time.Time
	logsForwarder *DatadogLogs
}

// NewTCProbe creates a new TCProbe instance
func NewTCProbe(options *Options) (*TCProbe, error) {
	var err error

	if err = options.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	e := &TCProbe{
		event:       events.NewEvent(),
		options:     options,
		handleEvent: options.EventHandler,
	}
	if e.handleEvent == nil {
		e.handleEvent = e.defaultEventHandler
	}

	if len(options.DatadogLogsURL) > 0 {
		e.logsForwarder = &DatadogLogs{}
		if err = e.logsForwarder.Start(options.DatadogLogsURL); err != nil {
			return nil, fmt.Errorf("couldn't start the Datadog logs forwarder: %w", err)
		}
	}

	e.timeResolver, err = events.NewTimeResolver()
	if err != nil {
		return nil, err
	}

	if len(options.Output) > 0 {
		e.outputFile, err = os.Create(options.Output)
		if err != nil {
			return nil, fmt.Errorf("couldn't create output file: %w", err)
		}

		_ = os.Chmod(options.Output, 0644)
	}
	return e, nil
}

// Start hooks on the requested symbols and begins tracing
func (tp *TCProbe) Start() error {
	if err := tp.startManager(); err != nil {
		return err
	}
	return nil
}

// Stop shuts down TCProbe
func (tp *TCProbe) Stop() error {
	if tp.manager == nil {
		// nothing to stop, return
		return nil
	}

	if err := tp.manager.Stop(manager.CleanAll); err != nil {
		logrus.Errorf("couldn't stop manager: %v", err)
	}

	if tp.outputFile != nil {
		if err := tp.outputFile.Close(); err != nil {
			logrus.Errorf("couldn't close output file: %v", err)
		}
	}
	return nil
}

func (tp *TCProbe) pushFilters() error {
	return nil
}

var eventZero events.Event

func (tp *TCProbe) zeroEvent() *events.Event {
	*tp.event = eventZero
	return tp.event
}

func (tp *TCProbe) defaultEventHandler(data []byte) error {
	event := tp.zeroEvent()

	// unmarshall kernel event
	cursor, err := event.Kernel.UnmarshalBinary(data, tp.timeResolver)
	if err != nil {
		return err
	}

	// unmarshall process context
	read, err := event.Process.UnmarshalBinary(data[cursor:])
	if err != nil {
		return err
	}
	cursor += read

	switch event.Kernel.Type {
	case events.QDiscEventType:
		if read, err = event.QDiscEvent.UnmarshallBinary(data[cursor:]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown event type: %s", event.Kernel.Type)
	}
	cursor += read

	// write to output file
	if tp.outputFile != nil {
		var jsonData []byte
		jsonData, err = event.MarshalJSON()
		if err != nil {
			return fmt.Errorf("couldn't marshall event: %w", err)
		}
		jsonData = append(jsonData, "\n"...)
		if _, err = tp.outputFile.Write(jsonData); err != nil {
			return fmt.Errorf("couldn't write event to output: %w", err)
		}
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.Debugf("%s", event.String())
	}

	if tp.logsForwarder != nil {
		tp.logsForwarder.EventChan <- event
	}
	return nil
}
