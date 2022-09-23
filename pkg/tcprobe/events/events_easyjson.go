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

func easyjson692db02bDecodeGithubComGui774umeTcprobePkgTcprobeEvents(in *jlexer.Lexer, out *EventSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.KernelEventSerializer = new(KernelEventSerializer)
	out.ProcessContextSerializer = new(ProcessContextSerializer)
	out.QDiscEventSerializer = new(QDiscEventSerializer)
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
		case "event":
			if in.IsNull() {
				in.Skip()
				out.KernelEventSerializer = nil
			} else {
				if out.KernelEventSerializer == nil {
					out.KernelEventSerializer = new(KernelEventSerializer)
				}
				(*out.KernelEventSerializer).UnmarshalEasyJSON(in)
			}
		case "process":
			if in.IsNull() {
				in.Skip()
				out.ProcessContextSerializer = nil
			} else {
				if out.ProcessContextSerializer == nil {
					out.ProcessContextSerializer = new(ProcessContextSerializer)
				}
				(*out.ProcessContextSerializer).UnmarshalEasyJSON(in)
			}
		case "qdisc":
			if in.IsNull() {
				in.Skip()
				out.QDiscEventSerializer = nil
			} else {
				if out.QDiscEventSerializer == nil {
					out.QDiscEventSerializer = new(QDiscEventSerializer)
				}
				(*out.QDiscEventSerializer).UnmarshalEasyJSON(in)
			}
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
func easyjson692db02bEncodeGithubComGui774umeTcprobePkgTcprobeEvents(out *jwriter.Writer, in EventSerializer) {
	out.RawByte('{')
	first := true
	_ = first
	if in.KernelEventSerializer != nil {
		const prefix string = ",\"event\":"
		first = false
		out.RawString(prefix[1:])
		(*in.KernelEventSerializer).MarshalEasyJSON(out)
	}
	if in.ProcessContextSerializer != nil {
		const prefix string = ",\"process\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		(*in.ProcessContextSerializer).MarshalEasyJSON(out)
	}
	if in.QDiscEventSerializer != nil {
		const prefix string = ",\"qdisc\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		(*in.QDiscEventSerializer).MarshalEasyJSON(out)
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v EventSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson692db02bEncodeGithubComGui774umeTcprobePkgTcprobeEvents(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *EventSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson692db02bDecodeGithubComGui774umeTcprobePkgTcprobeEvents(l, v)
}