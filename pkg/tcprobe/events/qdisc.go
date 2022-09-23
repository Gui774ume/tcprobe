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

// QDiscEvent represents a QDisc event
type QDiscEvent struct {
	Netns               uint32             `json:"netns"`
	IfIndex             uint32             `json:"ifindex"`
	IfName              string             `json:"ifname"`
	Handle              Handle             `json:"handle"`
	Parent              Handle             `json:"parent"`
	QDiscID             string             `json:"qdisc_id"`
	NetlinkMessageType  RoutingMessageType `json:"netlink_message_type"`
	NetlinkErrorMessage string             `json:"netlink_error_message,omitempty"`
	netlinkMessageFlags uint16
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *QDiscEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 56 {
		return 0, ErrNotEnoughData
	}
	e.Netns = ByteOrder.Uint32(data[0:4])
	e.IfIndex = ByteOrder.Uint32(data[4:8])
	e.IfName = NullTerminatedString(data[8 : 8+IfNameLen])
	e.Handle = Handle(ByteOrder.Uint32(data[8+IfNameLen : 12+IfNameLen]))
	e.Parent = Handle(ByteOrder.Uint32(data[12+IfNameLen : 16+IfNameLen]))
	e.QDiscID = NullTerminatedString(data[16+IfNameLen : 16+2*IfNameLen])
	e.NetlinkMessageType = RoutingMessageType(ByteOrder.Uint16(data[16+2*IfNameLen : 18+2*IfNameLen]))
	e.netlinkMessageFlags = ByteOrder.Uint16(data[18+2*IfNameLen : 20+2*IfNameLen])
	// padding 4 bytes
	e.NetlinkErrorMessage = NullTerminatedString(data[24+2*IfNameLen:])
	return 0, nil
}

// QDiscEventSerializer is used to serialize BPFEvent
// easyjson:json
type QDiscEventSerializer struct {
	*QDiscEvent
	NetlinkMessageFlags string `json:"netlink_message_flags"`
}

// NewQDiscEventSerializer returns a new instance of QDiscEventSerializer
func NewQDiscEventSerializer(e *QDiscEvent) *QDiscEventSerializer {
	serializer := &QDiscEventSerializer{
		QDiscEvent: e,
	}

	switch e.NetlinkMessageType {
	case 36, 40, 44, 48: // RTM_NEWQDISC, RTM_NEWTCLASS, RTM_NEWTFILTER, RTM_NEWACTION
		serializer.NetlinkMessageFlags = bitmaskU16ToString(e.netlinkMessageFlags, netlinkMessageNewFlagStrings)
	case 37, 41, 45, 49: // RTM_DELQDISC, RTM_DELTCLASS, RTM_DELTFILTER, RTM_DELACTION
		serializer.NetlinkMessageFlags = bitmaskU16ToString(e.netlinkMessageFlags, netlinkMessageDeleteFlagStrings)
	case 38, 42, 46, 50: // RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER, RTM_GETACTION
		serializer.NetlinkMessageFlags = bitmaskU16ToString(e.netlinkMessageFlags, netlinkMessageGetFlagStrings)
	}

	return serializer
}
