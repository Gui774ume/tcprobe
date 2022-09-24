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

// NetworkInterface represents the network interface context of an event
type NetworkInterface struct {
	Netns   uint32 `json:"netns"`
	IfIndex uint32 `json:"ifindex"`
	IfName  string `json:"ifname"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *NetworkInterface) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8+IfNameLen {
		return 0, ErrNotEnoughData
	}
	e.Netns = ByteOrder.Uint32(data[0:4])
	e.IfIndex = ByteOrder.Uint32(data[4:8])
	e.IfName = NullTerminatedString(data[8 : 8+IfNameLen])
	return 8 + IfNameLen, nil
}

// NetworkInterfaceSerializer is used to serialize a NetworkInterface
// easyjson:json
type NetworkInterfaceSerializer struct {
	*NetworkInterface
}

// NewNetworkInterfaceSerializer returns a new instance of NetworkInterfaceSerializer
func NewNetworkInterfaceSerializer(e *NetworkInterface) *NetworkInterfaceSerializer {
	serializer := &NetworkInterfaceSerializer{
		NetworkInterface: e,
	}

	return serializer
}
