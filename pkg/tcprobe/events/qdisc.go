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
	manager "github.com/DataDog/ebpf-manager"
)

// allQDiscProbes returns the probes used to track qdiscs
func allQDiscProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_modify_qdisc",
				EBPFFuncName: "kprobe_tc_modify_qdisc",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tc_modify_qdisc",
				EBPFFuncName: "kretprobe_tc_modify_qdisc",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/tc_get_qdisc",
				EBPFFuncName: "kprobe_tc_get_qdisc",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/tc_get_qdisc",
				EBPFFuncName: "kretprobe_tc_get_qdisc",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/__dev_get_by_index",
				EBPFFuncName: "kretprobe___dev_get_by_index",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/qdisc_create",
				EBPFFuncName: "kretprobe_qdisc_create",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kprobe/qdisc_destroy",
				EBPFFuncName: "kprobe_qdisc_destroy",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/qdisc_leaf",
				EBPFFuncName: "kretprobe_qdisc_leaf",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/qdisc_lookup",
				EBPFFuncName: "kretprobe_qdisc_lookup",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          TCProbeUID,
				EBPFSection:  "kretprobe/dev_ingress_queue_create",
				EBPFFuncName: "kretprobe_dev_ingress_queue_create",
			},
		},
	}
}

// QDisc represents a QDisc
type QDisc struct {
	Handle  Handle `json:"handle"`
	Parent  Handle `json:"parent"`
	QDiscID string `json:"qdisc_id"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *QDisc) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8+IfNameLen {
		return 0, ErrNotEnoughData
	}
	e.Handle = Handle(ByteOrder.Uint32(data[0:4]))
	e.Parent = Handle(ByteOrder.Uint32(data[4:8]))
	e.QDiscID = NullTerminatedString(data[8 : 8+IfNameLen])
	return 8 + IfNameLen, nil
}

// QDiscSerializer is used to serialize BPFEvent
// easyjson:json
type QDiscSerializer struct {
	*QDisc
}

// NewQDiscSerializer returns a new instance of QDiscEventSerializer
func NewQDiscSerializer(e *QDisc) *QDiscSerializer {
	serializer := &QDiscSerializer{
		QDisc: e,
	}

	return serializer
}
