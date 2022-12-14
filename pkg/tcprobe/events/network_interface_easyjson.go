// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package events

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonB5866df4DecodeGithubComGui774umeTcprobePkgTcprobeEvents(in *jlexer.Lexer, out *NetworkInterfaceSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.NetworkInterface = new(NetworkInterface)
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "netns":
			out.Netns = uint32(in.Uint32())
		case "ifindex":
			out.IfIndex = uint32(in.Uint32())
		case "ifname":
			out.IfName = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonB5866df4EncodeGithubComGui774umeTcprobePkgTcprobeEvents(out *jwriter.Writer, in NetworkInterfaceSerializer) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"netns\":"
		out.RawString(prefix[1:])
		out.Uint32(uint32(in.Netns))
	}
	{
		const prefix string = ",\"ifindex\":"
		out.RawString(prefix)
		out.Uint32(uint32(in.IfIndex))
	}
	{
		const prefix string = ",\"ifname\":"
		out.RawString(prefix)
		out.String(string(in.IfName))
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v NetworkInterfaceSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonB5866df4EncodeGithubComGui774umeTcprobePkgTcprobeEvents(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *NetworkInterfaceSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonB5866df4DecodeGithubComGui774umeTcprobePkgTcprobeEvents(l, v)
}
