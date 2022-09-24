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
	"encoding/binary"
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
)

// allFilterProbes returns the probes used to track filters
func allFilterProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_new_tfilter",
				EBPFFuncName: "kprobe_tc_new_tfilter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/dev_get_by_index_rcu",
				EBPFFuncName: "kretprobe_dev_get_by_index_rcu",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/qdisc_lookup_rcu",
				EBPFFuncName: "kretprobe_qdisc_lookup_rcu",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/__tcf_block_find",
				EBPFFuncName: "kretprobe___tcf_block_find",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tcf_chain_tp_find",
				EBPFFuncName: "kprobe_tcf_chain_tp_find",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tcf_chain_tp_find",
				EBPFFuncName: "kretprobe_tcf_chain_tp_find",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tfilter_notify",
				EBPFFuncName: "kprobe_tfilter_notify",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_setup_cb_add",
				EBPFFuncName: "kprobe_tc_setup_cb_add",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_setup_cb_replace",
				EBPFFuncName: "kprobe_tc_setup_cb_replace",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_setup_cb_destroy",
				EBPFFuncName: "kprobe_tc_setup_cb_destroy",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tc_new_tfilter",
				EBPFFuncName: "kretprobe_tc_new_tfilter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_del_tfilter",
				EBPFFuncName: "kprobe_tc_del_tfilter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tc_del_tfilter",
				EBPFFuncName: "kretprobe_tc_del_tfilter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_get_tfilter",
				EBPFFuncName: "kprobe_tc_get_tfilter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tc_get_tfilter",
				EBPFFuncName: "kretprobe_tc_get_tfilter",
			},
		},
	}
}

type BPFProgram struct {
	Type       BPFProgramType `json:"type"`
	AttachType BPFAttachType  `json:"attach_type,omitempty"`
	ID         uint32         `json:"id"`
	Name       string         `json:"name"`
	Tag        string         `json:"tag"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *BPFProgram) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 16+BPFObjNameLen+BPFTagSize {
		return 0, ErrNotEnoughData
	}

	e.Type = BPFProgramType(ByteOrder.Uint32(data[0:4]))
	e.AttachType = BPFAttachType(ByteOrder.Uint32(data[4:8]))
	e.ID = ByteOrder.Uint32(data[8:12])
	// Padding 4 bytes
	e.Name = NullTerminatedString(data[16 : 16+BPFObjNameLen])

	for _, b := range data[16+BPFObjNameLen : 16+BPFObjNameLen+BPFTagSize] {
		e.Tag += fmt.Sprintf("%x", b)
	}

	return 16 + BPFObjNameLen + BPFTagSize, nil
}

type BPFClassifier struct {
	Name       string     `json:"name"`
	Program    BPFProgram `json:"-"`
	OldProgram BPFProgram `json:"-"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *BPFClassifier) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < CLSBPFNameLenMax {
		return 0, ErrNotEnoughData
	}

	cursor := 0
	e.Name = NullTerminatedString(data[cursor : cursor+CLSBPFNameLenMax])
	cursor += CLSBPFNameLenMax

	read, err := e.Program.UnmarshallBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	read, err = e.OldProgram.UnmarshallBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	return cursor, nil
}

// BPFClassifierSerializer is used to serialize BPFClassifier
// easyjson:json
type BPFClassifierSerializer struct {
	*BPFClassifier
	Program    *BPFProgram `json:"program,omitempty"`
	OldProgram *BPFProgram `json:"old_program,omitempty"`
}

// NewBPFClassifierSerializer returns a new instance of BPFClassifierSerializer
func NewBPFClassifierSerializer(e *BPFClassifier) *BPFClassifierSerializer {
	serializer := &BPFClassifierSerializer{
		BPFClassifier: e,
	}

	if e.Program.ID > 0 {
		serializer.Program = &e.Program
	}
	if e.OldProgram.ID > 0 {
		serializer.OldProgram = &e.OldProgram
	}

	return serializer
}

// Filter represents a Filter event
type Filter struct {
	Priority    uint32      `json:"priority"`
	Protocol    L3Protocol  `json:"protocol"`
	Kind        string      `json:"kind,omitempty"`
	TCSetupType TCSetupType `json:"tc_setup_type"`
	Handle      Handle      `json:"handle"`

	BPFClassifier BPFClassifier `json:"-"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *Filter) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 16+IfNameLen {
		return 0, ErrNotEnoughData
	}

	e.Priority = ByteOrder.Uint32(data[0:4])
	e.Protocol = L3Protocol(binary.BigEndian.Uint16(data[4:6]))
	// padding 2 bytes
	e.TCSetupType = TCSetupType(ByteOrder.Uint32(data[8:12]))
	e.Handle = Handle(ByteOrder.Uint32(data[12:16]))
	e.Kind = NullTerminatedString(data[16 : 16+IfNameLen])
	cursor := 16 + IfNameLen

	if len(e.Kind) == 0 {
		e.TCSetupType = 0xffffffff
	}

	read, err := e.BPFClassifier.UnmarshallBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	return cursor, nil
}

// FilterSerializer is used to serialize Filter
// easyjson:json
type FilterSerializer struct {
	*Filter
	*BPFClassifierSerializer `json:"bpf_classifier,omitempty"`
}

// NewFilterSerializer returns a new instance of FilterSerializer
func NewFilterSerializer(e *Filter) *FilterSerializer {
	serializer := &FilterSerializer{
		Filter: e,
	}

	if e.Kind == "bpf" {
		serializer.BPFClassifierSerializer = NewBPFClassifierSerializer(&e.BPFClassifier)
	}

	return serializer
}
