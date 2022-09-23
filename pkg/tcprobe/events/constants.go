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

package events

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
)

const (
	// IfNameLen is the maximum length of an interface name
	IfNameLen = 16
)

// CgroupSubsystemID is used to parse a cgroup subsystem ID
type CgroupSubsystemID uint32

const (
	CgroupSubsystemCPUSet CgroupSubsystemID = iota
	CgroupSubsystemCPU
	CgroupSubsystemCPUAcct
	CgroupSubsystemIO
	CgroupSubsystemMemory
	CgroupSubsystemDevices
	CgroupSubsystemFreezer
	CgroupSubsystemNetCLS
	CgroupSubsystemPerfEvent
	CgroupSubsystemNetPrio
	CgroupSubsystemHugeTLB
	CgroupSubsystemPIDs
	CgroupSubsystemRDMA
	CgroupSubsystemMisc
	CgroupSubsystemMax
)

func (id CgroupSubsystemID) String() string {
	switch id {
	case CgroupSubsystemCPUSet:
		return "cpuset"
	case CgroupSubsystemCPU:
		return "cpu"
	case CgroupSubsystemCPUAcct:
		return "cpuacct"
	case CgroupSubsystemIO:
		return "io"
	case CgroupSubsystemMemory:
		return "memory"
	case CgroupSubsystemDevices:
		return "devices"
	case CgroupSubsystemFreezer:
		return "freezer"
	case CgroupSubsystemNetCLS:
		return "net_cls"
	case CgroupSubsystemPerfEvent:
		return "perf_event"
	case CgroupSubsystemNetPrio:
		return "net_prio"
	case CgroupSubsystemHugeTLB:
		return "hugetlb"
	case CgroupSubsystemPIDs:
		return "pids"
	case CgroupSubsystemRDMA:
		return "rdma"
	case CgroupSubsystemMisc:
		return "misc"
	default:
		return fmt.Sprintf("CgroupSubsystem(%d)", id)
	}
}

func (id CgroupSubsystemID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", id.String())), nil
}

var (
	RoutingMessageTypeConstants = map[string]RoutingMessageType{
		"RTM_NEWQDISC":   36,
		"RTM_DELQDISC":   37,
		"RTM_GETQDISC":   38,
		"RTM_NEWTCLASS":  40,
		"RTM_DELTCLASS":  41,
		"RTM_GETTCLASS":  42,
		"RTM_NEWTFILTER": 44,
		"RTM_DELTFILTER": 45,
		"RTM_GETTFILTER": 46,
		"RTM_NEWACTION":  48,
		"RTM_DELACTION":  49,
		"RTM_GETACTION":  50,
	}

	NetlinkMessageGetFlagContants = map[string]uint16{
		"NLM_F_REQUEST":       0x01,  /* It is request message. 	*/
		"NLM_F_MULTI":         0x02,  /* Multipart message, terminated by NLMSG_DONE */
		"NLM_F_ACK":           0x04,  /* Reply with ack, with zero or error code */
		"NLM_F_ECHO":          0x08,  /* Echo this request 		*/
		"NLM_F_DUMP_INTR":     0x10,  /* Dump was inconsistent due to sequence change */
		"NLM_F_DUMP_FILTERED": 0x20,  /* Dump was filtered as requested */
		"NLM_F_ROOT":          0x100, /* specify tree	root	*/
		"NLM_F_MATCH":         0x200, /* return all matching	*/
		"NLM_F_ATOMIC":        0x400, /* atomic GET		*/
		"NLM_F_DUMP":          0x100 | 0x200,
	}

	NetlinkMessageNewFlagContants = map[string]uint16{
		"NLM_F_REQUEST":       0x01,  /* It is request message. 	*/
		"NLM_F_MULTI":         0x02,  /* Multipart message, terminated by NLMSG_DONE */
		"NLM_F_ACK":           0x04,  /* Reply with ack, with zero or error code */
		"NLM_F_ECHO":          0x08,  /* Echo this request 		*/
		"NLM_F_DUMP_INTR":     0x10,  /* Dump was inconsistent due to sequence change */
		"NLM_F_DUMP_FILTERED": 0x20,  /* Dump was filtered as requested */
		"NLM_F_REPLACE":       0x100, /* Override existing		*/
		"NLM_F_EXCL":          0x200, /* Do not touch, if it exists	*/
		"NLM_F_CREATE":        0x400, /* Create, if it does not exist	*/
		"NLM_F_APPEND":        0x800, /* Add to end of list		*/
	}

	NetlinkMessageDeleteFlagContants = map[string]uint16{
		"NLM_F_REQUEST":       0x01,  /* It is request message. 	*/
		"NLM_F_MULTI":         0x02,  /* Multipart message, terminated by NLMSG_DONE */
		"NLM_F_ACK":           0x04,  /* Reply with ack, with zero or error code */
		"NLM_F_ECHO":          0x08,  /* Echo this request 		*/
		"NLM_F_DUMP_INTR":     0x10,  /* Dump was inconsistent due to sequence change */
		"NLM_F_DUMP_FILTERED": 0x20,  /* Dump was filtered as requested */
		"NLM_F_NONREC":        0x100, /* Do not delete recursively	*/
		"NLM_F_BULK":          0x200, /* Delete multiple objects	*/
	}

	ErrorConstants = map[string]KernelError{
		"OK":              0,
		"E2BIG":           -KernelError(syscall.E2BIG),
		"EACCES":          -KernelError(syscall.EACCES),
		"EADDRINUSE":      -KernelError(syscall.EADDRINUSE),
		"EADDRNOTAVAIL":   -KernelError(syscall.EADDRNOTAVAIL),
		"EADV":            -KernelError(syscall.EADV),
		"EAFNOSUPPORT":    -KernelError(syscall.EAFNOSUPPORT),
		"EAGAIN":          -KernelError(syscall.EAGAIN),
		"EALREADY":        -KernelError(syscall.EALREADY),
		"EBADE":           -KernelError(syscall.EBADE),
		"EBADF":           -KernelError(syscall.EBADF),
		"EBADFD":          -KernelError(syscall.EBADFD),
		"EBADMSG":         -KernelError(syscall.EBADMSG),
		"EBADR":           -KernelError(syscall.EBADR),
		"EBADRQC":         -KernelError(syscall.EBADRQC),
		"EBADSLT":         -KernelError(syscall.EBADSLT),
		"EBFONT":          -KernelError(syscall.EBFONT),
		"EBUSY":           -KernelError(syscall.EBUSY),
		"ECANCELED":       -KernelError(syscall.ECANCELED),
		"ECHILD":          -KernelError(syscall.ECHILD),
		"ECHRNG":          -KernelError(syscall.ECHRNG),
		"ECOMM":           -KernelError(syscall.ECOMM),
		"ECONNABORTED":    -KernelError(syscall.ECONNABORTED),
		"ECONNREFUSED":    -KernelError(syscall.ECONNREFUSED),
		"ECONNRESET":      -KernelError(syscall.ECONNRESET),
		"EDEADLK":         -KernelError(syscall.EDEADLK),
		"EDEADLOCK":       -KernelError(syscall.EDEADLOCK),
		"EDESTADDRREQ":    -KernelError(syscall.EDESTADDRREQ),
		"EDOM":            -KernelError(syscall.EDOM),
		"EDOTDOT":         -KernelError(syscall.EDOTDOT),
		"EDQUOT":          -KernelError(syscall.EDQUOT),
		"EEXIST":          -KernelError(syscall.EEXIST),
		"EFAULT":          -KernelError(syscall.EFAULT),
		"EFBIG":           -KernelError(syscall.EFBIG),
		"EHOSTDOWN":       -KernelError(syscall.EHOSTDOWN),
		"EHOSTUNREACH":    -KernelError(syscall.EHOSTUNREACH),
		"EIDRM":           -KernelError(syscall.EIDRM),
		"EILSEQ":          -KernelError(syscall.EIDRM),
		"EINPROGRESS":     -KernelError(syscall.EINPROGRESS),
		"EINTR":           -KernelError(syscall.EINTR),
		"EINVAL":          -KernelError(syscall.EINVAL),
		"EIO":             -KernelError(syscall.EIO),
		"EISCONN":         -KernelError(syscall.EISCONN),
		"EISDIR":          -KernelError(syscall.EISDIR),
		"EISNAM":          -KernelError(syscall.EISNAM),
		"EKEYEXPIRED":     -KernelError(syscall.EKEYEXPIRED),
		"EKEYREJECTED":    -KernelError(syscall.EKEYREJECTED),
		"EKEYREVOKED":     -KernelError(syscall.EKEYREVOKED),
		"EL2HLT":          -KernelError(syscall.EL2HLT),
		"EL2NSYNC":        -KernelError(syscall.EL2NSYNC),
		"EL3HLT":          -KernelError(syscall.EL3HLT),
		"EL3RST":          -KernelError(syscall.EL3RST),
		"ELIBACC":         -KernelError(syscall.ELIBACC),
		"ELIBBAD":         -KernelError(syscall.ELIBBAD),
		"ELIBEXEC":        -KernelError(syscall.ELIBEXEC),
		"ELIBMAX":         -KernelError(syscall.ELIBMAX),
		"ELIBSCN":         -KernelError(syscall.ELIBSCN),
		"ELNRNG":          -KernelError(syscall.ELNRNG),
		"ELOOP":           -KernelError(syscall.ELOOP),
		"EMEDIUMTYPE":     -KernelError(syscall.EMEDIUMTYPE),
		"EMFILE":          -KernelError(syscall.EMFILE),
		"EMLINK":          -KernelError(syscall.EMLINK),
		"EMSGSIZE":        -KernelError(syscall.EMSGSIZE),
		"EMULTIHOP":       -KernelError(syscall.EMULTIHOP),
		"ENAMETOOLONG":    -KernelError(syscall.ENAMETOOLONG),
		"ENAVAIL":         -KernelError(syscall.ENAVAIL),
		"ENETDOWN":        -KernelError(syscall.ENETDOWN),
		"ENETRESET":       -KernelError(syscall.ENETRESET),
		"ENETUNREACH":     -KernelError(syscall.ENETUNREACH),
		"ENFILE":          -KernelError(syscall.ENFILE),
		"ENOANO":          -KernelError(syscall.ENOANO),
		"ENOBUFS":         -KernelError(syscall.ENOBUFS),
		"ENOCSI":          -KernelError(syscall.ENOCSI),
		"ENODATA":         -KernelError(syscall.ENODATA),
		"ENODEV":          -KernelError(syscall.ENODEV),
		"ENOENT":          -KernelError(syscall.ENOENT),
		"ENOEXEC":         -KernelError(syscall.ENOEXEC),
		"ENOKEY":          -KernelError(syscall.ENOKEY),
		"ENOLCK":          -KernelError(syscall.ENOLCK),
		"ENOLINK":         -KernelError(syscall.ENOLINK),
		"ENOMEDIUM":       -KernelError(syscall.ENOMEDIUM),
		"ENOMEM":          -KernelError(syscall.ENOMEM),
		"ENOMSG":          -KernelError(syscall.ENOMSG),
		"ENONET":          -KernelError(syscall.ENONET),
		"ENOPKG":          -KernelError(syscall.ENOPKG),
		"ENOPROTOOPT":     -KernelError(syscall.ENOPROTOOPT),
		"ENOSPC":          -KernelError(syscall.ENOSPC),
		"ENOSR":           -KernelError(syscall.ENOSR),
		"ENOSTR":          -KernelError(syscall.ENOSTR),
		"ENOSYS":          -KernelError(syscall.ENOSYS),
		"ENOTBLK":         -KernelError(syscall.ENOTBLK),
		"ENOTCONN":        -KernelError(syscall.ENOTCONN),
		"ENOTDIR":         -KernelError(syscall.ENOTDIR),
		"ENOTEMPTY":       -KernelError(syscall.ENOTEMPTY),
		"ENOTNAM":         -KernelError(syscall.ENOTNAM),
		"ENOTRECOVERABLE": -KernelError(syscall.ENOTRECOVERABLE),
		"ENOTSOCK":        -KernelError(syscall.ENOTSOCK),
		"ENOTSUP":         -KernelError(syscall.ENOTSUP),
		"ENOTTY":          -KernelError(syscall.ENOTTY),
		"ENOTUNIQ":        -KernelError(syscall.ENOTUNIQ),
		"ENXIO":           -KernelError(syscall.ENXIO),
		"EOPNOTSUPP":      -KernelError(syscall.EOPNOTSUPP),
		"EOVERFLOW":       -KernelError(syscall.EOVERFLOW),
		"EOWNERDEAD":      -KernelError(syscall.EOWNERDEAD),
		"EPERM":           -KernelError(syscall.EPERM),
		"EPFNOSUPPORT":    -KernelError(syscall.EPFNOSUPPORT),
		"EPIPE":           -KernelError(syscall.EPIPE),
		"EPROTO":          -KernelError(syscall.EPROTO),
		"EPROTONOSUPPORT": -KernelError(syscall.EPROTONOSUPPORT),
		"EPROTOTYPE":      -KernelError(syscall.EPROTOTYPE),
		"ERANGE":          -KernelError(syscall.ERANGE),
		"EREMCHG":         -KernelError(syscall.EREMCHG),
		"EREMOTE":         -KernelError(syscall.EREMOTE),
		"EREMOTEIO":       -KernelError(syscall.EREMOTEIO),
		"ERESTART":        -KernelError(syscall.ERESTART),
		"ERFKILL":         -KernelError(syscall.ERFKILL),
		"EROFS":           -KernelError(syscall.EROFS),
		"ESHUTDOWN":       -KernelError(syscall.ESHUTDOWN),
		"ESOCKTNOSUPPORT": -KernelError(syscall.ESOCKTNOSUPPORT),
		"ESPIPE":          -KernelError(syscall.ESPIPE),
		"ESRCH":           -KernelError(syscall.ESRCH),
		"ESRMNT":          -KernelError(syscall.ESRMNT),
		"ESTALE":          -KernelError(syscall.ESTALE),
		"ESTRPIPE":        -KernelError(syscall.ESTRPIPE),
		"ETIME":           -KernelError(syscall.ETIME),
		"ETIMEDOUT":       -KernelError(syscall.ETIMEDOUT),
		"ETOOMANYREFS":    -KernelError(syscall.ETOOMANYREFS),
		"ETXTBSY":         -KernelError(syscall.ETXTBSY),
		"EUCLEAN":         -KernelError(syscall.EUCLEAN),
		"EUNATCH":         -KernelError(syscall.EUNATCH),
		"EUSERS":          -KernelError(syscall.EUSERS),
		"EWOULDBLOCK":     -KernelError(syscall.EWOULDBLOCK),
		"EXDEV":           -KernelError(syscall.EXDEV),
		"EXFULL":          -KernelError(syscall.EXFULL),
	}
)

var (
	routingMessageTypeStrings       = map[RoutingMessageType]string{}
	netlinkMessageGetFlagStrings    = map[uint16]string{}
	netlinkMessageNewFlagStrings    = map[uint16]string{}
	netlinkMessageDeleteFlagStrings = map[uint16]string{}
	errorStrings                    = map[KernelError]string{}
)

func initConstants() {
	for k, v := range RoutingMessageTypeConstants {
		routingMessageTypeStrings[v] = k
	}
	for k, v := range NetlinkMessageGetFlagContants {
		netlinkMessageGetFlagStrings[v] = k
	}
	for k, v := range NetlinkMessageNewFlagContants {
		netlinkMessageNewFlagStrings[v] = k
	}
	for k, v := range NetlinkMessageDeleteFlagContants {
		netlinkMessageDeleteFlagStrings[v] = k
	}
	for k, v := range ErrorConstants {
		errorStrings[v] = k
	}
}

func init() {
	initConstants()
}

func bitmaskToStringArray(bitmask int, intToStrMap map[int]string) []string {
	var strs []string
	var result int

	for v, s := range intToStrMap {
		if v == 0 {
			continue
		}

		if bitmask&v == v {
			strs = append(strs, s)
			result |= v
		}
	}

	if result != bitmask {
		strs = append(strs, fmt.Sprintf("%d", bitmask&^result))
	}

	sort.Strings(strs)
	return strs
}

func bitmaskToString(bitmask int, intToStrMap map[int]string) string {
	return strings.Join(bitmaskToStringArray(bitmask, intToStrMap), " | ")
}

func bitmaskU64ToStringArray(bitmask uint64, intToStrMap map[uint64]string) []string {
	var strs []string
	var result uint64

	for v, s := range intToStrMap {
		if v == 0 {
			continue
		}

		if bitmask&v == v {
			strs = append(strs, s)
			result |= v
		}
	}

	if result != bitmask {
		strs = append(strs, fmt.Sprintf("%d", bitmask&^result))
	}

	sort.Strings(strs)
	return strs
}

func bitmaskU64ToString(bitmask uint64, intToStrMap map[uint64]string) string {
	return strings.Join(bitmaskU64ToStringArray(bitmask, intToStrMap), " | ")
}

func bitmaskU16ToStringArray(bitmask uint16, intToStrMap map[uint16]string) []string {
	var strs []string
	var result uint16

	for v, s := range intToStrMap {
		if v == 0 {
			continue
		}

		if bitmask&v == v {
			strs = append(strs, s)
			result |= v
		}
	}

	if result != bitmask {
		strs = append(strs, fmt.Sprintf("%d", bitmask&^result))
	}

	sort.Strings(strs)
	return strs
}

func bitmaskU16ToString(bitmask uint16, intToStrMap map[uint16]string) string {
	return strings.Join(bitmaskU16ToStringArray(bitmask, intToStrMap), " | ")
}

// RoutingMessageType routing message type
type RoutingMessageType uint16

func (rtmt RoutingMessageType) String() string {
	return routingMessageTypeStrings[rtmt]
}

func (rtmt RoutingMessageType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", rtmt.String())), nil
}

// Handle is used to serialize a TC handle
type Handle uint32

func (h Handle) String() string {
	return fmt.Sprintf("%x:%x", uint16(h&0xFFFF0000>>16), uint16(h&0x0000FFFF))
}

func (h Handle) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", h.String())), nil
}

// KernelError represents a kernel error
type KernelError int

func (ke KernelError) String() string {
	return errorStrings[ke]
}

func (ke KernelError) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", ke.String())), nil
}
