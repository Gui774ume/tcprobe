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

// NetlinkMessage represents the network interface context of an event
type NetlinkMessage struct {
	Type  RoutingMessageType `json:"type"`
	Error string             `json:"error,omitempty"`
	flags uint16
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *NetlinkMessage) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8+NetlinkMessageErrLen {
		return 0, ErrNotEnoughData
	}

	e.Type = RoutingMessageType(ByteOrder.Uint16(data[0:2]))
	e.flags = ByteOrder.Uint16(data[2:4])
	// padding 4 bytes
	e.Error = NullTerminatedString(data[8 : 8+NetlinkMessageErrLen])
	return 8 + NetlinkMessageErrLen, nil
}

// NetlinkMessageSerializer is used to serialize a NetlinkMessage
// easyjson:json
type NetlinkMessageSerializer struct {
	*NetlinkMessage
	Flags string `json:"flags"`
}

// NewNetlinkMessageSerializer returns a new instance of NetlinkMessageSerializer
func NewNetlinkMessageSerializer(e *NetlinkMessage) *NetlinkMessageSerializer {
	serializer := &NetlinkMessageSerializer{
		NetlinkMessage: e,
	}

	switch e.Type {
	case 36, 40, 44, 48: // RTM_NEWQDISC, RTM_NEWTCLASS, RTM_NEWTFILTER, RTM_NEWACTION
		serializer.Flags = bitmaskU16ToString(e.flags, netlinkMessageNewFlagStrings)
	case 37, 41, 45, 49: // RTM_DELQDISC, RTM_DELTCLASS, RTM_DELTFILTER, RTM_DELACTION
		serializer.Flags = bitmaskU16ToString(e.flags, netlinkMessageDeleteFlagStrings)
	case 38, 42, 46, 50: // RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER, RTM_GETACTION
		serializer.Flags = bitmaskU16ToString(e.flags, netlinkMessageGetFlagStrings)
	}

	return serializer
}
