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

//go:generate go run github.com/mailru/easyjson/easyjson -no_std_marshalers $GOFILE

package events

import (
	"fmt"
	"strings"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/mailru/easyjson/jwriter"
	"gopkg.in/yaml.v3"
)

const (
	// TCProbeUID is the UID used to uniquely identify kernel space programs
	TCProbeUID = "tcprobe"
)

// AllProbes returns all the probes
func AllProbes() []*manager.Probe {
	all := append([]*manager.Probe{}, allQDiscProbes()...)
	all = append(all, allFilterProbes()...)
	return all
}

// EventType describes the type of an event sent from the kernel
type EventType uint32

const (
	// UnknownEventType unknow event
	UnknownEventType EventType = iota
	// QDiscEventType is used to report qdisc events
	QDiscEventType
	// FilterEventType is used to report filter events
	FilterEventType
	// MaxEventType is used internally to get the maximum number of events.
	MaxEventType
)

func (t EventType) String() string {
	switch t {
	case QDiscEventType:
		return "qdisc"
	case FilterEventType:
		return "filter"
	default:
		return fmt.Sprintf("EventType(%d)", t)
	}
}

func (t EventType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", t.String())), nil
}

var eventTypeStrings = map[string]EventType{}

func init() {
	for i := EventType(0); i < MaxEventType; i++ {
		eventTypeStrings[i.String()] = i
	}
}

// ParseEventType returns an event type from its string representation
func ParseEventType(input string) EventType {
	return eventTypeStrings[input]
}

// EventTypeList is a list of EventType
type EventTypeList []EventType

func (etl EventTypeList) String() string {
	switch len(etl) {
	case 0:
		return ""
	case 1:
		return etl[0].String()
	}
	n := len(etl) - 1
	for i := 0; i < len(etl); i++ {
		n += len(etl[i].String())
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(etl[0].String())
	for _, s := range etl[1:] {
		b.WriteString(", ")
		b.WriteString(s.String())
	}
	return b.String()
}

// Insert inserts an event type in a list of event type
func (etl *EventTypeList) Insert(et EventType) {
	for _, elem := range *etl {
		if et == elem {
			return
		}
	}
	*etl = append(*etl, et)
}

// Contains return true if the list of event types is empty or if it contains the provided event type
func (etl *EventTypeList) Contains(et EventType) bool {
	if len(*etl) == 0 {
		return true
	}

	for _, elem := range *etl {
		if elem == et {
			return true
		}
	}
	return false
}

// UnmarshalYAML parses a string representation of a list of event types
func (etl *EventTypeList) UnmarshalYAML(value *yaml.Node) error {
	var eventTypes []string
	err := value.Decode(&eventTypes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal the list of event types: %w", err)
	}

	for _, et := range eventTypes {
		// check if the provided event type exists
		newEventType := ParseEventType(et)
		if newEventType == UnknownEventType {
			return fmt.Errorf("unknown event type: %s", et)
		}
		etl.Insert(newEventType)
	}
	return nil
}

// Event is used to parse the events sent from kernel space
type Event struct {
	Kernel           KernelEvent
	Process          ProcessContext
	NetworkInterface NetworkInterface
	NetlinkMessage   NetlinkMessage

	QDisc  QDisc
	Chain  Chain
	Block  Block
	Filter Filter
}

// NewEvent returns a new Event instance
func NewEvent() *Event {
	return &Event{}
}

func (e *Event) MarshalJSON() ([]byte, error) {
	s := NewEventSerializer(e)
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	s.MarshalEasyJSON(w)
	return w.BuildBytes()
}

func (e Event) String() string {
	data, err := e.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("failed to marshall event: %v", err)
	}
	return string(data)
}

// EventSerializer is used to serialize Event
// easyjson:json
type EventSerializer struct {
	Service string `json:"service,omitempty"`

	*KernelEventSerializer      `json:"event,omitempty"`
	*ProcessContextSerializer   `json:"process,omitempty"`
	*NetworkInterfaceSerializer `json:"network_interface,omitempty"`
	*NetlinkMessageSerializer   `json:"netlink_message,omitempty"`

	*QDiscSerializer  `json:"qdisc,omitempty"`
	*ChainSerializer  `json:"chain,omitempty"`
	*BlockSerializer  `json:"block,omitempty"`
	*FilterSerializer `json:"filter,omitempty"`
}

// NewEventSerializer returns a new EventSerializer instance for the provided Event
func NewEventSerializer(event *Event) *EventSerializer {
	serializer := &EventSerializer{
		Service:                    "tcprobe",
		KernelEventSerializer:      NewKernelEventSerializer(&event.Kernel),
		ProcessContextSerializer:   NewProcessContextSerializer(&event.Process),
		NetworkInterfaceSerializer: NewNetworkInterfaceSerializer(&event.NetworkInterface),
		NetlinkMessageSerializer:   NewNetlinkMessageSerializer(&event.NetlinkMessage),
	}

	switch event.Kernel.Type {
	case QDiscEventType:
		serializer.QDiscSerializer = NewQDiscSerializer(&event.QDisc)
	case FilterEventType:
		serializer.QDiscSerializer = NewQDiscSerializer(&event.QDisc)
		serializer.ChainSerializer = NewChainSerializer(&event.Chain)
		serializer.BlockSerializer = NewBlockSerializer(&event.Block)
		serializer.FilterSerializer = NewFilterSerializer(&event.Filter)
	}
	return serializer
}
