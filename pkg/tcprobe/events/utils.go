package events

import "bytes"

// NullTerminatedString returns a string from its binary representation
func NullTerminatedString(d []byte) string {
	idx := bytes.IndexByte(d, 0)
	if idx == -1 {
		return string(d)
	}
	return string(d[:idx])
}
