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

func easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents(in *jlexer.Lexer, out *FilterSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.Filter = new(Filter)
	out.BPFClassifierSerializer = new(BPFClassifierSerializer)
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
		case "bpf_classifier":
			if in.IsNull() {
				in.Skip()
				out.BPFClassifierSerializer = nil
			} else {
				if out.BPFClassifierSerializer == nil {
					out.BPFClassifierSerializer = new(BPFClassifierSerializer)
				}
				(*out.BPFClassifierSerializer).UnmarshalEasyJSON(in)
			}
		case "priority":
			out.Priority = uint32(in.Uint32())
		case "protocol":
			out.Protocol = L3Protocol(in.Uint16())
		case "kind":
			out.Kind = string(in.String())
		case "tc_setup_type":
			out.TCSetupType = TCSetupType(in.Uint32())
		case "handle":
			out.Handle = Handle(in.Uint32())
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
func easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents(out *jwriter.Writer, in FilterSerializer) {
	out.RawByte('{')
	first := true
	_ = first
	if in.BPFClassifierSerializer != nil {
		const prefix string = ",\"bpf_classifier\":"
		first = false
		out.RawString(prefix[1:])
		(*in.BPFClassifierSerializer).MarshalEasyJSON(out)
	}
	{
		const prefix string = ",\"priority\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint32(uint32(in.Priority))
	}
	{
		const prefix string = ",\"protocol\":"
		out.RawString(prefix)
		out.Raw((in.Protocol).MarshalJSON())
	}
	if in.Kind != "" {
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		out.String(string(in.Kind))
	}
	{
		const prefix string = ",\"tc_setup_type\":"
		out.RawString(prefix)
		out.Raw((in.TCSetupType).MarshalJSON())
	}
	{
		const prefix string = ",\"handle\":"
		out.RawString(prefix)
		out.Raw((in.Handle).MarshalJSON())
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v FilterSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *FilterSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents(l, v)
}
func easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents1(in *jlexer.Lexer, out *BPFClassifierSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.BPFClassifier = new(BPFClassifier)
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
		case "program":
			if in.IsNull() {
				in.Skip()
				out.Program = nil
			} else {
				if out.Program == nil {
					out.Program = new(BPFProgram)
				}
				easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents2(in, out.Program)
			}
		case "old_program":
			if in.IsNull() {
				in.Skip()
				out.OldProgram = nil
			} else {
				if out.OldProgram == nil {
					out.OldProgram = new(BPFProgram)
				}
				easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents2(in, out.OldProgram)
			}
		case "name":
			out.Name = string(in.String())
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
func easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents1(out *jwriter.Writer, in BPFClassifierSerializer) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Program != nil {
		const prefix string = ",\"program\":"
		first = false
		out.RawString(prefix[1:])
		easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents2(out, *in.Program)
	}
	if in.OldProgram != nil {
		const prefix string = ",\"old_program\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents2(out, *in.OldProgram)
	}
	{
		const prefix string = ",\"name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Name))
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v BPFClassifierSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents1(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *BPFClassifierSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents1(l, v)
}
func easyjson4d398eaaDecodeGithubComGui774umeTcprobePkgTcprobeEvents2(in *jlexer.Lexer, out *BPFProgram) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
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
		case "type":
			out.Type = BPFProgramType(in.Uint32())
		case "attach_type":
			out.AttachType = BPFAttachType(in.Uint32())
		case "id":
			out.ID = uint32(in.Uint32())
		case "name":
			out.Name = string(in.String())
		case "tag":
			out.Tag = string(in.String())
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
func easyjson4d398eaaEncodeGithubComGui774umeTcprobePkgTcprobeEvents2(out *jwriter.Writer, in BPFProgram) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"type\":"
		out.RawString(prefix[1:])
		out.Raw((in.Type).MarshalJSON())
	}
	if in.AttachType != 0 {
		const prefix string = ",\"attach_type\":"
		out.RawString(prefix)
		out.Raw((in.AttachType).MarshalJSON())
	}
	{
		const prefix string = ",\"id\":"
		out.RawString(prefix)
		out.Uint32(uint32(in.ID))
	}
	{
		const prefix string = ",\"name\":"
		out.RawString(prefix)
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"tag\":"
		out.RawString(prefix)
		out.String(string(in.Tag))
	}
	out.RawByte('}')
}
