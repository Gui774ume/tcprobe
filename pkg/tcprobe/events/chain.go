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

// Chain represents a Chain
type Chain struct {
	Index uint32 `json:"index"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *Chain) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, ErrNotEnoughData
	}

	e.Index = ByteOrder.Uint32(data[0:4])
	// padding 8 bytes

	return 8, nil
}

// ChainSerializer is used to serialize Chain
// easyjson:json
type ChainSerializer struct {
	*Chain
}

// NewChainSerializer returns a new instance of ChainSerializer
func NewChainSerializer(e *Chain) *ChainSerializer {
	serializer := &ChainSerializer{
		Chain: e,
	}

	return serializer
}
