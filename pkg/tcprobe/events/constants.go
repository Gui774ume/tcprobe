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
	// NetlinkMessageErrLen is the maximum length of a netlink message error
	NetlinkMessageErrLen = 64
	// BPFObjNameLen is the maximum length of the name of a bpf object
	BPFObjNameLen = 16
	// BPFTagSize is the size of the tag of a BPF program
	BPFTagSize = 8
	// CLSBPFNameLenMax is the maximum len of a cls_bpf filter (should be 256 but reduced to 128 to save space)
	CLSBPFNameLenMax = 128
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
	CgroupSubsystemDebug
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
	case CgroupSubsystemDebug:
		return "debug"
	default:
		return fmt.Sprintf("CgroupSubsystem(%d)", id)
	}
}

func (id CgroupSubsystemID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", id.String())), nil
}

var (
	TCSetupTypeConstants = map[string]TCSetupType{
		"NONE":                  0xffffffff,
		"TC_SETUP_QDISC_MQPRIO": 0,
		"TC_SETUP_CLSU32":       1,
		"TC_SETUP_CLSFLOWER":    2,
		"TC_SETUP_CLSMATCHALL":  3,
		"TC_SETUP_CLSBPF":       4,
		"TC_SETUP_BLOCK":        5,
		"TC_SETUP_QDISC_CBS":    6,
		"TC_SETUP_QDISC_RED":    7,
		"TC_SETUP_QDISC_PRIO":   8,
		"TC_SETUP_QDISC_MQ":     9,
		"TC_SETUP_QDISC_ETF":    10,
		"TC_SETUP_ROOT_QDISC":   11,
		"TC_SETUP_QDISC_GRED":   12,
		"TC_SETUP_QDISC_TAPRIO": 13,
		"TC_SETUP_FT":           14,
		"TC_SETUP_QDISC_ETS":    15,
		"TC_SETUP_QDISC_TBF":    16,
		"TC_SETUP_QDISC_FIFO":   17,
		"TC_SETUP_QDISC_HTB":    18,
		"TC_SETUP_ACT":          19,
	}

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

	// BPFProgramTypeConstants is the list of BPF program type constants
	BPFProgramTypeConstants = map[string]BPFProgramType{
		"BPF_PROG_TYPE_UNSPEC":                  BpfProgTypeUnspec,
		"BPF_PROG_TYPE_SOCKET_FILTER":           BpfProgTypeSocketFilter,
		"BPF_PROG_TYPE_KPROBE":                  BpfProgTypeKprobe,
		"BPF_PROG_TYPE_SCHED_CLS":               BpfProgTypeSchedCls,
		"BPF_PROG_TYPE_SCHED_ACT":               BpfProgTypeSchedAct,
		"BPF_PROG_TYPE_TRACEPOINT":              BpfProgTypeTracepoint,
		"BPF_PROG_TYPE_XDP":                     BpfProgTypeXdp,
		"BPF_PROG_TYPE_PERF_EVENT":              BpfProgTypePerfEvent,
		"BPF_PROG_TYPE_CGROUP_SKB":              BpfProgTypeCgroupSkb,
		"BPF_PROG_TYPE_CGROUP_SOCK":             BpfProgTypeCgroupSock,
		"BPF_PROG_TYPE_LWT_IN":                  BpfProgTypeLwtIn,
		"BPF_PROG_TYPE_LWT_OUT":                 BpfProgTypeLwtOut,
		"BPF_PROG_TYPE_LWT_XMIT":                BpfProgTypeLwtXmit,
		"BPF_PROG_TYPE_SOCK_OPS":                BpfProgTypeSockOps,
		"BPF_PROG_TYPE_SK_SKB":                  BpfProgTypeSkSkb,
		"BPF_PROG_TYPE_CGROUP_DEVICE":           BpfProgTypeCgroupDevice,
		"BPF_PROG_TYPE_SK_MSG":                  BpfProgTypeSkMsg,
		"BPF_PROG_TYPE_RAW_TRACEPOINT":          BpfProgTypeRawTracepoint,
		"BPF_PROG_TYPE_CGROUP_SOCK_ADDR":        BpfProgTypeCgroupSockAddr,
		"BPF_PROG_TYPE_LWT_SEG6LOCAL":           BpfProgTypeLwtSeg6local,
		"BPF_PROG_TYPE_LIRC_MODE2":              BpfProgTypeLircMode2,
		"BPF_PROG_TYPE_SK_REUSEPORT":            BpfProgTypeSkReuseport,
		"BPF_PROG_TYPE_FLOW_DISSECTOR":          BpfProgTypeFlowDissector,
		"BPF_PROG_TYPE_CGROUP_SYSCTL":           BpfProgTypeCgroupSysctl,
		"BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE": BpfProgTypeRawTracepointWritable,
		"BPF_PROG_TYPE_CGROUP_SOCKOPT":          BpfProgTypeCgroupSockopt,
		"BPF_PROG_TYPE_TRACING":                 BpfProgTypeTracing,
		"BPF_PROG_TYPE_STRUCT_OPS":              BpfProgTypeStructOps,
		"BPF_PROG_TYPE_EXT":                     BpfProgTypeExt,
		"BPF_PROG_TYPE_LSM":                     BpfProgTypeLsm,
		"BPF_PROG_TYPE_SK_LOOKUP":               BpfProgTypeSkLookup,
	}

	// BPFAttachTypeConstants is the list of BPF attach type constants
	BPFAttachTypeConstants = map[string]BPFAttachType{
		"BPF_CGROUP_INET_INGRESS":      BpfCgroupInetIngress,
		"BPF_CGROUP_INET_EGRESS":       BpfCgroupInetEgress,
		"BPF_CGROUP_INET_SOCK_CREATE":  BpfCgroupInetSockCreate,
		"BPF_CGROUP_SOCK_OPS":          BpfCgroupSockOps,
		"BPF_SK_SKB_STREAM_PARSER":     BpfSkSkbStreamParser,
		"BPF_SK_SKB_STREAM_VERDICT":    BpfSkSkbStreamVerdict,
		"BPF_CGROUP_DEVICE":            BpfCgroupDevice,
		"BPF_SK_MSG_VERDICT":           BpfSkMsgVerdict,
		"BPF_CGROUP_INET4_BIND":        BpfCgroupInet4Bind,
		"BPF_CGROUP_INET6_BIND":        BpfCgroupInet6Bind,
		"BPF_CGROUP_INET4_CONNECT":     BpfCgroupInet4Connect,
		"BPF_CGROUP_INET6_CONNECT":     BpfCgroupInet6Connect,
		"BPF_CGROUP_INET4_POST_BIND":   BpfCgroupInet4PostBind,
		"BPF_CGROUP_INET6_POST_BIND":   BpfCgroupInet6PostBind,
		"BPF_CGROUP_UDP4_SENDMSG":      BpfCgroupUDP4Sendmsg,
		"BPF_CGROUP_UDP6_SENDMSG":      BpfCgroupUDP6Sendmsg,
		"BPF_LIRC_MODE2":               BpfLircMode2,
		"BPF_FLOW_DISSECTOR":           BpfFlowDissector,
		"BPF_CGROUP_SYSCTL":            BpfCgroupSysctl,
		"BPF_CGROUP_UDP4_RECVMSG":      BpfCgroupUDP4Recvmsg,
		"BPF_CGROUP_UDP6_RECVMSG":      BpfCgroupUDP6Recvmsg,
		"BPF_CGROUP_GETSOCKOPT":        BpfCgroupGetsockopt,
		"BPF_CGROUP_SETSOCKOPT":        BpfCgroupSetsockopt,
		"BPF_TRACE_RAW_TP":             BpfTraceRawTp,
		"BPF_TRACE_FENTRY":             BpfTraceFentry,
		"BPF_TRACE_FEXIT":              BpfTraceFexit,
		"BPF_MODIFY_RETURN":            BpfModifyReturn,
		"BPF_LSM_MAC":                  BpfLsmMac,
		"BPF_TRACE_ITER":               BpfTraceIter,
		"BPF_CGROUP_INET4_GETPEERNAME": BpfCgroupInet4Getpeername,
		"BPF_CGROUP_INET6_GETPEERNAME": BpfCgroupInet6Getpeername,
		"BPF_CGROUP_INET4_GETSOCKNAME": BpfCgroupInet4Getsockname,
		"BPF_CGROUP_INET6_GETSOCKNAME": BpfCgroupInet6Getsockname,
		"BPF_XDP_DEVMAP":               BpfXdpDevmap,
		"BPF_CGROUP_INET_SOCK_RELEASE": BpfCgroupInetSockRelease,
		"BPF_XDP_CPUMAP":               BpfXdpCPUmap,
		"BPF_SK_LOOKUP":                BpfSkLookup,
		"BPF_XDP":                      BpfXdp,
		"BPF_SK_SKB_VERDICT":           BpfSkSkbVerdict,
	}

	// L3ProtocolConstants is the list of supported L3 protocols
	// generate_constants:L3 protocols,L3 protocols are the supported Layer 3 protocols.
	L3ProtocolConstants = map[string]L3Protocol{
		"ETH_P_LOOP":            EthPLOOP,
		"ETH_P_PUP":             EthPPUP,
		"ETH_P_PUPAT":           EthPPUPAT,
		"ETH_P_TSN":             EthPTSN,
		"ETH_P_IP":              EthPIP,
		"ETH_P_X25":             EthPX25,
		"ETH_P_ARP":             EthPARP,
		"ETH_P_BPQ":             EthPBPQ,
		"ETH_P_IEEEPUP":         EthPIEEEPUP,
		"ETH_P_IEEEPUPAT":       EthPIEEEPUPAT,
		"ETH_P_BATMAN":          EthPBATMAN,
		"ETH_P_DEC":             EthPDEC,
		"ETH_P_DNADL":           EthPDNADL,
		"ETH_P_DNARC":           EthPDNARC,
		"ETH_P_DNART":           EthPDNART,
		"ETH_P_LAT":             EthPLAT,
		"ETH_P_DIAG":            EthPDIAG,
		"ETH_P_CUST":            EthPCUST,
		"ETH_P_SCA":             EthPSCA,
		"ETH_P_TEB":             EthPTEB,
		"ETH_P_RARP":            EthPRARP,
		"ETH_P_ATALK":           EthPATALK,
		"ETH_P_AARP":            EthPAARP,
		"ETH_P_8021_Q":          EthP8021Q,
		"ETH_P_ERSPAN":          EthPERSPAN,
		"ETH_P_IPX":             EthPIPX,
		"ETH_P_IPV6":            EthPIPV6,
		"ETH_P_PAUSE":           EthPPAUSE,
		"ETH_P_SLOW":            EthPSLOW,
		"ETH_P_WCCP":            EthPWCCP,
		"ETH_P_MPLSUC":          EthPMPLSUC,
		"ETH_P_MPLSMC":          EthPMPLSMC,
		"ETH_P_ATMMPOA":         EthPATMMPOA,
		"ETH_P_PPPDISC":         EthPPPPDISC,
		"ETH_P_PPPSES":          EthPPPPSES,
		"ETH_P__LINK_CTL":       EthPLinkCTL,
		"ETH_P_ATMFATE":         EthPATMFATE,
		"ETH_P_PAE":             EthPPAE,
		"ETH_P_AOE":             EthPAOE,
		"ETH_P_8021_AD":         EthP8021AD,
		"ETH_P_802_EX1":         EthP802EX1,
		"ETH_P_TIPC":            EthPTIPC,
		"ETH_P_MACSEC":          EthPMACSEC,
		"ETH_P_8021_AH":         EthP8021AH,
		"ETH_P_MVRP":            EthPMVRP,
		"ETH_P_1588":            EthP1588,
		"ETH_P_NCSI":            EthPNCSI,
		"ETH_P_PRP":             EthPPRP,
		"ETH_P_FCOE":            EthPFCOE,
		"ETH_P_IBOE":            EthPIBOE,
		"ETH_P_TDLS":            EthPTDLS,
		"ETH_P_FIP":             EthPFIP,
		"ETH_P_80221":           EthP80221,
		"ETH_P_HSR":             EthPHSR,
		"ETH_P_NSH":             EthPNSH,
		"ETH_P_LOOPBACK":        EthPLOOPBACK,
		"ETH_P_QINQ1":           EthPQINQ1,
		"ETH_P_QINQ2":           EthPQINQ2,
		"ETH_P_QINQ3":           EthPQINQ3,
		"ETH_P_EDSA":            EthPEDSA,
		"ETH_P_IFE":             EthPIFE,
		"ETH_P_AFIUCV":          EthPAFIUCV,
		"ETH_P_8023_MIN":        EthP8023MIN,
		"ETH_P_IPV6_HOP_BY_HOP": EthPIPV6HopByHop,
		"ETH_P_8023":            EthP8023,
		"ETH_P_AX25":            EthPAX25,
		"ETH_P_ALL":             EthPALL,
		"ETH_P_8022":            EthP8022,
		"ETH_P_SNAP":            EthPSNAP,
		"ETH_P_DDCMP":           EthPDDCMP,
		"ETH_P_WANPPP":          EthPWANPPP,
		"ETH_P_PPPMP":           EthPPPPMP,
		"ETH_P_LOCALTALK":       EthPLOCALTALK,
		"ETH_P_CAN":             EthPCAN,
		"ETH_P_CANFD":           EthPCANFD,
		"ETH_P_PPPTALK":         EthPPPPTALK,
		"ETH_P_TR8022":          EthPTR8022,
		"ETH_P_MOBITEX":         EthPMOBITEX,
		"ETH_P_CONTROL":         EthPCONTROL,
		"ETH_P_IRDA":            EthPIRDA,
		"ETH_P_ECONET":          EthPECONET,
		"ETH_P_HDLC":            EthPHDLC,
		"ETH_P_ARCNET":          EthPARCNET,
		"ETH_P_DSA":             EthPDSA,
		"ETH_P_TRAILER":         EthPTRAILER,
		"ETH_P_PHONET":          EthPPHONET,
		"ETH_P_IEEE802154":      EthPIEEE802154,
		"ETH_P_CAIF":            EthPCAIF,
		"ETH_P_XDSA":            EthPXDSA,
		"ETH_P_MAP":             EthPMAP,
	}
)

var (
	routingMessageTypeStrings       = map[RoutingMessageType]string{}
	netlinkMessageGetFlagStrings    = map[uint16]string{}
	netlinkMessageNewFlagStrings    = map[uint16]string{}
	netlinkMessageDeleteFlagStrings = map[uint16]string{}
	errorStrings                    = map[KernelError]string{}
	bpfProgramTypeStrings           = map[BPFProgramType]string{}
	bpfAttachTypeStrings            = map[BPFAttachType]string{}
	tcSetupTypeStrings              = map[TCSetupType]string{}
	l3ProtocolStrings               = map[L3Protocol]string{}
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
	for k, v := range BPFProgramTypeConstants {
		bpfProgramTypeStrings[v] = k
	}
	for k, v := range BPFAttachTypeConstants {
		bpfAttachTypeStrings[v] = k
	}
	for k, v := range TCSetupTypeConstants {
		tcSetupTypeStrings[v] = k
	}
	for k, v := range L3ProtocolConstants {
		l3ProtocolStrings[v] = k
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

// TCSetupType is used to define the TC setup type
type TCSetupType uint32

func (t TCSetupType) String() string {
	return tcSetupTypeStrings[t]
}

func (t TCSetupType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", t.String())), nil
}

// BPFProgramType is used to define program type constants
type BPFProgramType uint32

func (t BPFProgramType) String() string {
	return bpfProgramTypeStrings[t]
}

func (t BPFProgramType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", t.String())), nil
}

const (
	// BpfProgTypeUnspec program type
	BpfProgTypeUnspec BPFProgramType = iota
	// BpfProgTypeSocketFilter program type
	BpfProgTypeSocketFilter
	// BpfProgTypeKprobe program type
	BpfProgTypeKprobe
	// BpfProgTypeSchedCls program type
	BpfProgTypeSchedCls
	// BpfProgTypeSchedAct program type
	BpfProgTypeSchedAct
	// BpfProgTypeTracepoint program type
	BpfProgTypeTracepoint
	// BpfProgTypeXdp program type
	BpfProgTypeXdp
	// BpfProgTypePerfEvent program type
	BpfProgTypePerfEvent
	// BpfProgTypeCgroupSkb program type
	BpfProgTypeCgroupSkb
	// BpfProgTypeCgroupSock program type
	BpfProgTypeCgroupSock
	// BpfProgTypeLwtIn program type
	BpfProgTypeLwtIn
	// BpfProgTypeLwtOut program type
	BpfProgTypeLwtOut
	// BpfProgTypeLwtXmit program type
	BpfProgTypeLwtXmit
	// BpfProgTypeSockOps program type
	BpfProgTypeSockOps
	// BpfProgTypeSkSkb program type
	BpfProgTypeSkSkb
	// BpfProgTypeCgroupDevice program type
	BpfProgTypeCgroupDevice
	// BpfProgTypeSkMsg program type
	BpfProgTypeSkMsg
	// BpfProgTypeRawTracepoint program type
	BpfProgTypeRawTracepoint
	// BpfProgTypeCgroupSockAddr program type
	BpfProgTypeCgroupSockAddr
	// BpfProgTypeLwtSeg6local program type
	BpfProgTypeLwtSeg6local
	// BpfProgTypeLircMode2 program type
	BpfProgTypeLircMode2
	// BpfProgTypeSkReuseport program type
	BpfProgTypeSkReuseport
	// BpfProgTypeFlowDissector program type
	BpfProgTypeFlowDissector
	// BpfProgTypeCgroupSysctl program type
	BpfProgTypeCgroupSysctl
	// BpfProgTypeRawTracepointWritable program type
	BpfProgTypeRawTracepointWritable
	// BpfProgTypeCgroupSockopt program type
	BpfProgTypeCgroupSockopt
	// BpfProgTypeTracing program type
	BpfProgTypeTracing
	// BpfProgTypeStructOps program type
	BpfProgTypeStructOps
	// BpfProgTypeExt program type
	BpfProgTypeExt
	// BpfProgTypeLsm program type
	BpfProgTypeLsm
	// BpfProgTypeSkLookup program type
	BpfProgTypeSkLookup
)

// BPFAttachType is used to define attach type constants
type BPFAttachType uint32

func (t BPFAttachType) String() string {
	return bpfAttachTypeStrings[t]
}

func (t BPFAttachType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", t.String())), nil
}

const (
	// BpfCgroupInetIngress attach type
	BpfCgroupInetIngress BPFAttachType = iota + 1
	// BpfCgroupInetEgress attach type
	BpfCgroupInetEgress
	// BpfCgroupInetSockCreate attach type
	BpfCgroupInetSockCreate
	// BpfCgroupSockOps attach type
	BpfCgroupSockOps
	// BpfSkSkbStreamParser attach type
	BpfSkSkbStreamParser
	// BpfSkSkbStreamVerdict attach type
	BpfSkSkbStreamVerdict
	// BpfCgroupDevice attach type
	BpfCgroupDevice
	// BpfSkMsgVerdict attach type
	BpfSkMsgVerdict
	// BpfCgroupInet4Bind attach type
	BpfCgroupInet4Bind
	// BpfCgroupInet6Bind attach type
	BpfCgroupInet6Bind
	// BpfCgroupInet4Connect attach type
	BpfCgroupInet4Connect
	// BpfCgroupInet6Connect attach type
	BpfCgroupInet6Connect
	// BpfCgroupInet4PostBind attach type
	BpfCgroupInet4PostBind
	// BpfCgroupInet6PostBind attach type
	BpfCgroupInet6PostBind
	// BpfCgroupUDP4Sendmsg attach type
	BpfCgroupUDP4Sendmsg
	// BpfCgroupUDP6Sendmsg attach type
	BpfCgroupUDP6Sendmsg
	// BpfLircMode2 attach type
	BpfLircMode2
	// BpfFlowDissector attach type
	BpfFlowDissector
	// BpfCgroupSysctl attach type
	BpfCgroupSysctl
	// BpfCgroupUDP4Recvmsg attach type
	BpfCgroupUDP4Recvmsg
	// BpfCgroupUDP6Recvmsg attach type
	BpfCgroupUDP6Recvmsg
	// BpfCgroupGetsockopt attach type
	BpfCgroupGetsockopt
	// BpfCgroupSetsockopt attach type
	BpfCgroupSetsockopt
	// BpfTraceRawTp attach type
	BpfTraceRawTp
	// BpfTraceFentry attach type
	BpfTraceFentry
	// BpfTraceFexit attach type
	BpfTraceFexit
	// BpfModifyReturn attach type
	BpfModifyReturn
	// BpfLsmMac attach type
	BpfLsmMac
	// BpfTraceIter attach type
	BpfTraceIter
	// BpfCgroupInet4Getpeername attach type
	BpfCgroupInet4Getpeername
	// BpfCgroupInet6Getpeername attach type
	BpfCgroupInet6Getpeername
	// BpfCgroupInet4Getsockname attach type
	BpfCgroupInet4Getsockname
	// BpfCgroupInet6Getsockname attach type
	BpfCgroupInet6Getsockname
	// BpfXdpDevmap attach type
	BpfXdpDevmap
	// BpfCgroupInetSockRelease attach type
	BpfCgroupInetSockRelease
	// BpfXdpCPUmap attach type
	BpfXdpCPUmap
	// BpfSkLookup attach type
	BpfSkLookup
	// BpfXdp attach type
	BpfXdp
	// BpfSkSkbVerdict attach type
	BpfSkSkbVerdict
)

// L3Protocol Network protocols
type L3Protocol uint16

func (proto L3Protocol) String() string {
	return l3ProtocolStrings[proto]
}

func (proto L3Protocol) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", proto.String())), nil
}

const (
	// EthPLOOP Ethernet Loopback packet
	EthPLOOP L3Protocol = 0x0060
	// EthPPUP Xerox PUP packet
	EthPPUP L3Protocol = 0x0200
	// EthPPUPAT Xerox PUP Addr Trans packet
	EthPPUPAT L3Protocol = 0x0201
	// EthPTSN TSN (IEEE 1722) packet
	EthPTSN L3Protocol = 0x22F0
	// EthPIP Internet Protocol packet
	EthPIP L3Protocol = 0x0800
	// EthPX25 CCITT X.25
	EthPX25 L3Protocol = 0x0805
	// EthPARP Address Resolution packet
	EthPARP L3Protocol = 0x0806
	// EthPBPQ G8BPQ AX.25 Ethernet Packet    [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPBPQ L3Protocol = 0x08FF
	// EthPIEEEPUP Xerox IEEE802.3 PUP packet
	EthPIEEEPUP L3Protocol = 0x0a00
	// EthPIEEEPUPAT Xerox IEEE802.3 PUP Addr Trans packet
	EthPIEEEPUPAT L3Protocol = 0x0a01
	// EthPBATMAN B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPBATMAN L3Protocol = 0x4305
	// EthPDEC DEC Assigned proto
	EthPDEC L3Protocol = 0x6000
	// EthPDNADL DEC DNA Dump/Load
	EthPDNADL L3Protocol = 0x6001
	// EthPDNARC DEC DNA Remote Console
	EthPDNARC L3Protocol = 0x6002
	// EthPDNART DEC DNA Routing
	EthPDNART L3Protocol = 0x6003
	// EthPLAT DEC LAT
	EthPLAT L3Protocol = 0x6004
	// EthPDIAG DEC Diagnostics
	EthPDIAG L3Protocol = 0x6005
	// EthPCUST DEC Customer use
	EthPCUST L3Protocol = 0x6006
	// EthPSCA DEC Systems Comms Arch
	EthPSCA L3Protocol = 0x6007
	// EthPTEB Trans Ether Bridging
	EthPTEB L3Protocol = 0x6558
	// EthPRARP Reverse Addr Res packet
	EthPRARP L3Protocol = 0x8035
	// EthPATALK Appletalk DDP
	EthPATALK L3Protocol = 0x809B
	// EthPAARP Appletalk AARP
	EthPAARP L3Protocol = 0x80F3
	// EthP8021Q 802.1Q VLAN Extended Header
	EthP8021Q L3Protocol = 0x8100
	// EthPERSPAN ERSPAN type II
	EthPERSPAN L3Protocol = 0x88BE
	// EthPIPX IPX over DIX
	EthPIPX L3Protocol = 0x8137
	// EthPIPV6 IPv6 over bluebook
	EthPIPV6 L3Protocol = 0x86DD
	// EthPPAUSE IEEE Pause frames. See 802.3 31B
	EthPPAUSE L3Protocol = 0x8808
	// EthPSLOW Slow Protocol. See 802.3ad 43B
	EthPSLOW L3Protocol = 0x8809
	// EthPWCCP Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
	EthPWCCP L3Protocol = 0x883E
	// EthPMPLSUC MPLS Unicast traffic
	EthPMPLSUC L3Protocol = 0x8847
	// EthPMPLSMC MPLS Multicast traffic
	EthPMPLSMC L3Protocol = 0x8848
	// EthPATMMPOA MultiProtocol Over ATM
	EthPATMMPOA L3Protocol = 0x884c
	// EthPPPPDISC PPPoE discovery messages
	EthPPPPDISC L3Protocol = 0x8863
	// EthPPPPSES PPPoE session messages
	EthPPPPSES L3Protocol = 0x8864
	// EthPLinkCTL HPNA, wlan link local tunnel
	EthPLinkCTL L3Protocol = 0x886c
	// EthPATMFATE Frame-based ATM Transport over Ethernet
	EthPATMFATE L3Protocol = 0x8884
	// EthPPAE Port Access Entity (IEEE 802.1X)
	EthPPAE L3Protocol = 0x888E
	// EthPAOE ATA over Ethernet
	EthPAOE L3Protocol = 0x88A2
	// EthP8021AD 802.1ad Service VLAN
	EthP8021AD L3Protocol = 0x88A8
	// EthP802EX1 802.1 Local Experimental 1.
	EthP802EX1 L3Protocol = 0x88B5
	// EthPTIPC TIPC
	EthPTIPC L3Protocol = 0x88CA
	// EthPMACSEC 802.1ae MACsec
	EthPMACSEC L3Protocol = 0x88E5
	// EthP8021AH 802.1ah Backbone Service Tag
	EthP8021AH L3Protocol = 0x88E7
	// EthPMVRP 802.1Q MVRP
	EthPMVRP L3Protocol = 0x88F5
	// EthP1588 IEEE 1588 Timesync
	EthP1588 L3Protocol = 0x88F7
	// EthPNCSI NCSI protocol
	EthPNCSI L3Protocol = 0x88F8
	// EthPPRP IEC 62439-3 PRP/HSRv0
	EthPPRP L3Protocol = 0x88FB
	// EthPFCOE Fibre Channel over Ethernet
	EthPFCOE L3Protocol = 0x8906
	// EthPIBOE Infiniband over Ethernet
	EthPIBOE L3Protocol = 0x8915
	// EthPTDLS TDLS
	EthPTDLS L3Protocol = 0x890D
	// EthPFIP FCoE Initialization Protocol
	EthPFIP L3Protocol = 0x8914
	// EthP80221 IEEE 802.21 Media Independent Handover Protocol
	EthP80221 L3Protocol = 0x8917
	// EthPHSR IEC 62439-3 HSRv1
	EthPHSR L3Protocol = 0x892F
	// EthPNSH Network Service Header
	EthPNSH L3Protocol = 0x894F
	// EthPLOOPBACK Ethernet loopback packet, per IEEE 802.3
	EthPLOOPBACK L3Protocol = 0x9000
	// EthPQINQ1 deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ1 L3Protocol = 0x9100
	// EthPQINQ2 deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ2 L3Protocol = 0x9200
	// EthPQINQ3 deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPQINQ3 L3Protocol = 0x9300
	// EthPEDSA Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPEDSA L3Protocol = 0xDADA
	// EthPIFE ForCES inter-FE LFB type
	EthPIFE L3Protocol = 0xED3E
	// EthPAFIUCV IBM afiucv [ NOT AN OFFICIALLY REGISTERED ID ]
	EthPAFIUCV L3Protocol = 0xFBFB
	// EthP8023MIN If the value in the ethernet type is less than this value then the frame is Ethernet II. Else it is 802.3
	EthP8023MIN L3Protocol = 0x0600
	// EthPIPV6HopByHop IPv6 Hop by hop option
	EthPIPV6HopByHop L3Protocol = 0x000
	// EthP8023 Dummy type for 802.3 frames
	EthP8023 L3Protocol = 0x0001
	// EthPAX25 Dummy protocol id for AX.25
	EthPAX25 L3Protocol = 0x0002
	// EthPALL Every packet (be careful!!!)
	EthPALL L3Protocol = 0x0003
	// EthP8022 802.2 frames
	EthP8022 L3Protocol = 0x0004
	// EthPSNAP Internal only
	EthPSNAP L3Protocol = 0x0005
	// EthPDDCMP DEC DDCMP: Internal only
	EthPDDCMP L3Protocol = 0x0006
	// EthPWANPPP Dummy type for WAN PPP frames*/
	EthPWANPPP L3Protocol = 0x0007
	// EthPPPPMP Dummy type for PPP MP frames
	EthPPPPMP L3Protocol = 0x0008
	// EthPLOCALTALK Localtalk pseudo type
	EthPLOCALTALK L3Protocol = 0x0009
	// EthPCAN CAN: Controller Area Network
	EthPCAN L3Protocol = 0x000C
	// EthPCANFD CANFD: CAN flexible data rate*/
	EthPCANFD L3Protocol = 0x000D
	// EthPPPPTALK Dummy type for Atalk over PPP*/
	EthPPPPTALK L3Protocol = 0x0010
	// EthPTR8022 802.2 frames
	EthPTR8022 L3Protocol = 0x0011
	// EthPMOBITEX Mobitex (kaz@cafe.net)
	EthPMOBITEX L3Protocol = 0x0015
	// EthPCONTROL Card specific control frames
	EthPCONTROL L3Protocol = 0x0016
	// EthPIRDA Linux-IrDA
	EthPIRDA L3Protocol = 0x0017
	// EthPECONET Acorn Econet
	EthPECONET L3Protocol = 0x0018
	// EthPHDLC HDLC frames
	EthPHDLC L3Protocol = 0x0019
	// EthPARCNET 1A for ArcNet :-)
	EthPARCNET L3Protocol = 0x001A
	// EthPDSA Distributed Switch Arch.
	EthPDSA L3Protocol = 0x001B
	// EthPTRAILER Trailer switch tagging
	EthPTRAILER L3Protocol = 0x001C
	// EthPPHONET Nokia Phonet frames
	EthPPHONET L3Protocol = 0x00F5
	// EthPIEEE802154 IEEE802.15.4 frame
	EthPIEEE802154 L3Protocol = 0x00F6
	// EthPCAIF ST-Ericsson CAIF protocol
	EthPCAIF L3Protocol = 0x00F7
	// EthPXDSA Multiplexed DSA protocol
	EthPXDSA L3Protocol = 0x00F8
	// EthPMAP Qualcomm multiplexing and aggregation protocol
	EthPMAP L3Protocol = 0x00F9
)
