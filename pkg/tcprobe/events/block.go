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

// Block represents a Block
type Block struct {
	Index   uint32 `json:"index"`
	Classid Handle `json:"classid"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *Block) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, ErrNotEnoughData
	}

	e.Index = ByteOrder.Uint32(data[0:4])
	e.Classid = Handle(ByteOrder.Uint32(data[4:8]))

	return 8, nil
}

// BlockSerializer is used to serialize Block
// easyjson:json
type BlockSerializer struct {
	*Block
}

// NewBlockSerializer returns a new instance of BlockSerializer
func NewBlockSerializer(e *Block) *BlockSerializer {
	serializer := &BlockSerializer{
		Block: e,
	}

	return serializer
}
