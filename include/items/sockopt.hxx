#pragma once

// C++
#include <optional>
#include <variant>

// Linux
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/net_tstamp.h>

// cosmos
#include <cosmos/net/SocketOptions.hxx>
#include <cosmos/net/unix/aux.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/items/net.hxx>
#include <clues/items/seccomp.hxx>
#include <clues/items/time.hxx>

namespace clues {

enum class SockOptType;

namespace item {

using GetSockOptLen = PointerToScalar<int>;
using SetSockOptLen = IntValue;

/**
 * @file
 * This header contains getsockopt() and setsockopt() related types. There are
 * many different specializations of these ioctl-style system calls which also
 * requires a bunch of dedicated types for the concrete `optval` parameters
 * used.
 **/

CLUES_DEFAULT_VISIBILITY_ON;

/// Specialized pointer to scalar `optval`s used in getsockopt().
template <typename T>
class GetSockOptVal :
		public item::PointerToScalar<T> {
public: // functions

	explicit GetSockOptVal(const GetSockOptLen &optlen, const ItemCfg cfg = {}) :
			clues::item::PointerToScalar<T>{cfg.applyDefaults(ItemCfg{.label = "optval"})},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void updateData(const Tracee &tracee) override {
		/*
		 * the system call does not error out in all cases when a lack
		 * of option value space is encountered, so verify we actually
		 * have data to interpret.
		 */
		if (!this->callSuccessful() || m_optlen.value() < sizeof(T)) {
			this->m_val.reset();
			return;
		}

		return PointerToScalar<T>::updateData(tracee);
	}

protected: // data

	const GetSockOptLen &m_optlen;
};

/// Specialized pointer to scalar `optval`s used in setsockopt().
template <typename T>
class SetSockOptVal :
		public item::PointerToScalar<T> {
public: // functions

	explicit SetSockOptVal(const SetSockOptLen &optlen, const ItemCfg cfg = {}) :
			clues::item::PointerToScalar<T>{cfg.applyDefaults(ItemCfg{.label = "optval"})},
			m_optlen{optlen} {
	}

protected: // data

	const SetSockOptLen &m_optlen;
};

/// Specialized PointerInValue to handle `struct` types in setsockopt() context.
template <class STRUCT>
class SetSockOptStruct :
		public item::PointerInValue {
public: // types

	using StructType = STRUCT;

public: // functions

	explicit SetSockOptStruct(const SetSockOptLen &optlen,
			const ItemCfg &cfg) :
			item::PointerInValue{cfg.applyDefaults(
				ItemCfg{.label = "optval"})},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

	const std::optional<STRUCT>& data() const {
		return m_struct;
	}

	std::string str() const override = 0;

protected: // functions

	void processData(const Tracee &proc) override;

protected: // data

	const SetSockOptLen &m_optlen;
	std::optional<STRUCT> m_struct;
};

/// Specialized PointerOutValue to handle `struct` types in getsockopt() context.
template <typename STRUCT>
class GetSockOptStruct :
		public item::PointerOutValue {
public: // data

	using StructType = STRUCT;

public: // functions

	explicit GetSockOptStruct(const GetSockOptLen &optlen,
			const ItemCfg &cfg) :
			item::PointerOutValue{cfg.applyDefaults(ItemCfg{
				.label = "optval"
			})},
			m_optlen{optlen} {
	}

	const std::optional<STRUCT>& data() const {
		return m_struct;
	}

	virtual std::string str() const override = 0;

protected: // functions

	void processData(const Tracee &) override {
		m_struct.reset();
	}

	void updateData(const Tracee &proc) override;

protected: // data

	const GetSockOptLen &m_optlen;
	std::optional<STRUCT> m_struct;
};

/// Socket option level selection.
class SockOptLevel :
		public ValueInParameter {
public: // types

	enum class Level : int {
		IPV6    = SOL_IPV6,
		IP      = SOL_IP,
		NETLINK = SOL_NETLINK,
		PACKET  = SOL_PACKET,
		RAW     = SOL_RAW,
		SOCKET  = SOL_SOCKET,
		TCP     = IPPROTO_TCP,
		UDP     = IPPROTO_UDP,
		INVALID = -1
	};

	using enum Level;

public: // functions

	explicit SockOptLevel() :
			ValueInParameter{ItemCfg{.label = "optlevel", .desc = "socket level selection"}} {
	}

	Level level() const {
		return m_level;
	}

	std::string str() const override;

protected: // functions

	void processData(const Tracee &) override;

protected: // data

	Level m_level = Level::INVALID;
};

/// Socket option name selection.
/**
 * The concrete type depends on the SockOptLevel sibling parameter.
 **/
class SockOptName :
		public ValueInParameter {
public: // types

	enum class IP6Option : int {

	};

	enum class IPOption : int {

	};

	enum class NetlinkOption : int {

	};

	enum class PacketOption : int {

	};

#ifndef SO_RIGHTS_NOTRUNC
	// this was only added in kernel 7.3, not yet found in most userspace
	// headers
#	define SO_RIGHTS_NOTRUNC 85 /* generic UAPI value */
#endif

	enum class SocketOption : int {
		ACCEPTCONN            = SO_ACCEPTCONN,            ///< read-only boolean option whether the socket is in listening state.
		ATTACH_FILTER         = SO_ATTACH_FILTER,         ///< set a classic BPF filter program passed in `struct fprog` argument.
		ATTACH_BPF            = SO_ATTACH_BPF,            ///< set an extended BPF filter program passed in a `bpf()` file descriptor argument.
		GET_FILTER            = SO_GET_FILTER,            ///< returns the currently installed filter program into an array of `struct sock_fprog*`. `optlen` is determines the amount of array entries on in/output.
		ATTACH_REUSEPORT_CBPF = SO_ATTACH_REUSEPORT_CBPF, ///< similar to ATTACH_FILTER, assigns program to control packet distribution in SO_REUSEPORT scenarios.
		ATTACH_REUSEPORT_EBPF = SO_ATTACH_REUSEPORT_EBPF, ///< similar to ATTACH_BPF for SO_REUSEPORT scenarios.
		BPF_EXTENSIONS        = SO_BPF_EXTENSIONS,        ///< get-only `int` option. Returns SKF_AD_MAX, the highest BPF extension value supported by the kernel.
		BINDTODEVICE          = SO_BINDTODEVICE,          ///< receive only packets from the given network interface; string option.
		BINDTOIFINDEX         = SO_BINDTOIFINDEX,         ///< receive only packets from the given network interface; interface index int option.
		BROADCAST             = SO_BROADCAST,             ///< set/get broadcast boolean option.
		BSDCOMPAT             = SO_BSDCOMPAT,             ///< no longer available boolean option for BSD bug-to-bug compatibility.
		DEBUG                 = SO_DEBUG,                 ///< set/get boolean socket debugging option.
		DETACH_BPF            = SO_DETACH_BPF,            ///< remove any active FILTER/BPF program, no option data, synonym to DETACH_FILTER.
		DETACH_REUSEPORT_BPF  = SO_DETACH_REUSEPORT_BPF,  ///< remove any active FILTER/BPF program for REUSEPORT behaviour, no option data.
		DOMAIN                = SO_DOMAIN,                ///< returns the SocketDomain::Domain the socket belongs too, read-only option.
		ERROR                 = SO_ERROR,                 ///< get and clear any pending socket error. Integer errno option.
		DONTROUTE             = SO_DONTROUTE,             ///< get/set boolean option defining whether gateways may be used, corresponding to cosmos::MessageFlag::DONTROUTE used in send().
		INCOMING_CPU          = SO_INCOMING_CPU,          ///< get/set CPU affinity for the socket. Integer CPU number option.
		INCOMING_NAPI_ID      = SO_INCOMING_NAPI_ID,      ///< returns an ID for the RX queue used to receive packets on this socket. Integer ID value, read-only.
		INQ                   = SO_INQ,                   ///< (AF_UNIX) get/set boolean option to enable the reception INQ control messages which provide the amoung of bytes remaining in the receive queue.

		KEEPALIVE             = SO_KEEPALIVE,             ///< get/set boolean keepalive option.
		LINGER                = SO_LINGER,                ///< get/set the current linger option; uses `struct linger`.
		LOCK_FILTER           = SO_LOCK_FILTER,           ///< lock any currently installed BPF programs on the socket with no way of turning the lock off again. This still takes a boolean.
		MARK                  = SO_MARK,                  ///< get/set the mark used for each packet sent through the socket. Takes a `uint32_t`.
		RCVMARK               = SO_RCVMARK,               ///< get/set boolean option controlling reception of SO_MARK ancillary messages.
		RCVPRIORITY           = SO_RCVPRIORITY,           ///< get/set boolean option controlling reception of control messages providing the receive queue priority for the message.
		NO_CHECK              = SO_NO_CHECK,              ///< don't calculate checksum for outgoing UDP packets, boolean option.
		OOBINLINE             = SO_OOBINLINE,             ///< receive out-of-band data directly in the receive data stream. Boolean get/set option.
		PASSCRED              = SO_PASSCRED,              ///< (AF_UNIX) get/set boolean whether to receive SCM_CREDENTIALS control messages.
		PASSSEC               = SO_PASSSEC,               ///< (AF_UNIX) get/set boolean whether to receive SCM_SECURITY control messages.
		PASSPIDFD             = SO_PASSPIDFD,             ///< (AF_UNIX) get/set boolean whether to receive SCM_PIDFD control messages.
		PASSRIGHTS            = SO_PASSRIGHTS,            ///< (AF_UNIX) get/set boolean whether to allow reception of SCM_RIGHTS control messages (default: yes).
		RIGHTS_NOTRUNC        = SO_RIGHTS_NOTRUNC,        ///< (AF_UNIX) get/set boolean whether to truncate SCM_RIGHTS control messages on error (default) or report an errno instead of a file descriptor. Only available since kernel 7.3.
		PEEK_OFF              = SO_PEEK_OFF,              ///< (AF_UNIX) get/set offset to be maintained in the context of MSG_PEEK `recv()` calls. `int` value.
		PEERCRED              = SO_PEERCRED,              ///< (AF_UNIX) get the `struct ucred` of the peer used during `connect()` or `socketpair()` time.
		PEERSEC               = SO_PEERSEC,               ///< (AF_UNIX) get a string describing the security context of the peer. Content depends on the LSM in effect.
		PEERPIDFD             = SO_PEERPIDFD,             ///< (AF_UNIX) obtain a PIDFD of the process which called connect() on the socket.
		PRIORITY              = SO_PRIORITY,              ///< get/set the priority used for packets sent on the socket. Integer value.
		PROTOCOL              = SO_PROTOCOL,              ///< get the socket's protocol option. Integer value. Interpretation is depending on SocketDomain.
		RCVBUF                = SO_RCVBUF,                ///< get/set the maximum receive buffer size used in the kernel. Integer value.
		RCVBUFFORCE           = SO_RCVBUFFORCE,           ///< forced RCVBUF setting with `CAP_NET_ADMIN`.
		RCVLOWAT              = SO_RCVLOWAT,              ///< get/set minimum number of bytes in receive buffer before passing data to userspace. Integer option.
		SNDLOWAT              = SO_SNDLOWAT,              ///< get minimum number of bytes in send buffer before passing on to the protocol layer. Cannot be changed on Linux. Integer option.
		RCVTIMEO_OLD          = SO_RCVTIMEO_OLD,          ///< get/set receive timeout in `struct timeval` argument.
		SNDTIMEO_OLD          = SO_SNDTIMEO_OLD,          ///< get/set send timeout in `struct timeval` argument.
		RCVTIMEO_NEW          = SO_RCVTIMEO_NEW,          ///< get/set receive timeout in `struct timespec` argument.
		SNDTIMEO_NEW          = SO_SNDTIMEO_NEW,          ///< get/set send timeout in `struct timespec` argument.
		RESERVE_MEM           = SO_RESERVE_MEM,           ///< get/set memory to reserve in kernel for socket. int argument in bytes.
		REUSEADDR             = SO_REUSEADDR,             ///< get/set reuse address boolean option.
		REUSEPORT             = SO_REUSEPORT,             ///< get/set reuse port boolean option.
		RXQ_OVFL              = SO_RXQ_OVFL,              ///< get/set boolean option whether to supply a 32-bit value ancillary message indicating the number of dropped packets.
		SELECT_ERR_QUEUE      = SO_SELECT_ERR_QUEUE,      ///< get/set select() error handling behaviour boolean option. Deprecated.
		SNDBUF                = SO_SNDBUF,                ///< get/set maximum send buffer size used in the kernel. Integer value.
		SNDBUFFORCE           = SO_SNDBUFFORCE,           ///< forced SNDBUF setting with `CAP_NET_ADMIN`.
		TIMESTAMP             = SO_TIMESTAMP,             ///< get/set reception of `SCM_TIMESTAMP` control messages. Boolean option.
		TIMESTAMPNS           = SO_TIMESTAMPNS,           ///< get/set reception of `SCM_TIMESTAMPNS` control messages. Boolean option.
		TYPE                  = SO_TYPE,                  ///< get the socket type. Integer value.
		TXREHASH              = SO_TXREHASH,              ///< get/set boolean option, whether to allow the kernel to rethink the tx queue to use in ertain situations.
		BUSY_POLL             = SO_BUSY_POLL,             ///< get/set a poll duration in microseconds for `recv()` calls on the socket. Integer option.
		PREFER_BUSY_POLL      = SO_PREFER_BUSY_POLL,      ///< declare that the application will regularly busy poll the socket, allowing the kernel to disable interrupts. Boolean option.
		BUSY_POLL_BUDGET      = SO_BUSY_POLL_BUDGET,      ///< controls the maximum number of packets a single busy poll is allowed to process. Integer option.
		BUF_LOCK              = SO_BUF_LOCK,              ///< get/set an integer bitmask controlling whether the kernel may automatically change socket buffer sizes.
		NETNS_COOKIE          = SO_NETNS_COOKIE,          ///< retrieve the network namespace ID the socket belongs to.
		WIFI_STATUS           = SO_WIFI_STATUS,           ///< get/set boolean option to enable reception of control messages indicating low level WIFI status.
		NOFCS                 = SO_NOFCS,                 ///< get/set boolean option to disable checksuming on packet socket TX frames; let the hardware to the checksumming (FCS = frame check sequence).
		ZEROCOPY              = SO_ZEROCOPY,              ///< get/set boolean option to enable zerocopy operation on a socket, allows use of MSG_ZEROCOPY flag.
		CNX_ADVICE            = SO_CNX_ADVICE,            ///< inform the kernel that the current route is bad, this is kind of a command, not a persistent option. Only supports set, acts on `optval == 1`. Other `optval`s could be supported in the future, kind of an enum, without defined constants at the moment.
		DEVMEM_DONTNEED       = SO_DEVMEM_DONTNEED,       ///< set-only "command" supplying a `struct dmabuf_token` to tell the kernel which DMA buffers are no longer needed by userspace.
		TXTIME                = SO_TXTIME,                ///< get/set a `struct sock_txtime`. Allows to send SCM_TXTIME control messages to control when to send data out.
	};

	enum class TCPOption : int {

	};

	enum class UDPOption : int {

	};

	using OptVariant = std::variant<std::monostate, IP6Option, IPOption,
	      NetlinkOption, PacketOption, SocketOption, TCPOption, UDPOption>;

public: // functions

	explicit SockOptName(const SockOptLevel &level_arg, const SockOptType opt_type) :
			ValueInParameter{
				ItemCfg{.label = "optname",
				.desc = "socket option name selection"}},
			m_level_arg{level_arg},
			m_opt_variant{std::monostate{}},
			m_opt_type{opt_type} {
	}

	OptVariant option() const {
		return m_opt_variant;
	}

	std::string str() const override;

protected: // functions

	void processData(const Tracee &) override;

protected: // data

	const SockOptLevel &m_level_arg;

	OptVariant m_opt_variant;
	const SockOptType m_opt_type;
};

/// Type for `struct sock_fprog` as used with SO_ATTACH_FILTER and others.
/**
 * This specialization of FilterProg checks that the `optlen` is sufficient to
 * process a `struct sock_fprog`. It is used with:
 *
 * - SO_ATTACH_FILTER
 * - SO_ATTACH_REUSEPORT_CBPF
 **/
class ClassicBPFSockOpt :
		public FilterProg {
public: // functions

	explicit ClassicBPFSockOpt(const SetSockOptLen &optlen) :
				FilterProg{ItemType::PARAM_IN},
				m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &) override;

protected: // data

	const SetSockOptLen &m_optlen;
};

/// Type for `struct sock_filter` as used with SO_GET_FILTER.
/**
 * `SO_GET_FILTER` is actually only the GET variant for `SO_ATTACH_FILTER`.
 * It's semantics are quite unfortunate: `optval` refers to an array of
 * `struct sock_filter`, not to a `struct sock_fprog`.
 *
 * To hide this additional complexity we're synthesizing a `struct fprog` here
 * for users of libclues based on the `FilterProg` base class.
 **/
class GetFilterSocktOpt :
		public FilterProg {
public: // functions

	explicit GetFilterSocktOpt(const GetSockOptLen &optlen) :
				FilterProg{ItemType::PARAM_OUT},
				m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &) override;

	void updateData(const Tracee &) override;

protected: // data

	const GetSockOptLen &m_optlen;
};

class LingerSockOptBase :
		public PointerValue {
public: // functions

	const std::optional<cosmos::SocketOptions::Linger>& linger() const {
		return m_linger;
	}

	std::string str() const override;

protected: // functions

	explicit LingerSockOptBase(const ItemCfg &cfg) :
			PointerValue{cfg.applyDefaults(ItemCfg{
					.label = "linger",
					.desc = "struct linger*"})} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

	void fetch(const Tracee &proc, const int len);

protected: // data

	std::optional<cosmos::SocketOptions::Linger> m_linger;
};

class GetLingerSockOpt :
		public LingerSockOptBase {
public: // functions

	explicit GetLingerSockOpt(const GetSockOptLen &optlen) :
			LingerSockOptBase{ItemCfg{ItemType::PARAM_OUT}},
			m_optlen{optlen} {
	}

protected: // functions

	void processData(const Tracee &) override {
		m_linger.reset();
	}

	void updateData(const Tracee &proc) override;


protected: // data

	const GetSockOptLen &m_optlen;
};

class SetLingerSockOpt :
		public LingerSockOptBase {
public: // functions

	explicit SetLingerSockOpt(const SetSockOptLen &optlen) :
			LingerSockOptBase{ItemCfg{ItemType::PARAM_IN}},
			m_optlen{optlen} {
	}

protected: // functions

	void processData(const Tracee &proc) override;

protected: // data

	const SetSockOptLen &m_optlen;
};

class GetPeerCredSockOpt :
		public GetSockOptStruct<cosmos::UnixCredentials> {
public: // functions

	explicit GetPeerCredSockOpt(const GetSockOptLen &optlen) :
			GetSockOptStruct{optlen, ItemCfg{
				.desc = "struct ucred*"}} {
	}

	std::string str() const override;
};

/// Contains the socket protocol for SOL_SOCKET/SO_PROTOCOL.
/**
 * This type provides the same ProtocolVariant as the SocketProtocol item
 * does. Only currently supported socket families are covered. For more exotic
 * situations you need to inspect the raw integer value returned from
 * the `value()` base class function.
 **/
class ProtocolSockOpt :
		public GetSockOptVal<int> {
public: // types

	using ProtocolVariant = clues::item::SocketProtocol::ProtocolVariant;

public: // functions

	explicit ProtocolSockOpt(const GetSockOptLen &optlen) :
		GetSockOptVal<int>{optlen},
		m_prot{std::monostate{}} {
	}

	std::string str() const override;

	ProtocolVariant prot() const {
		return m_prot;
	}

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	ProtocolVariant m_prot;
};

/// Specialization of TimeValParameter which takes `optlen` into account.
class SetTimeValSockOpt :
		public item::TimeValParameter {
public: // functions

	explicit SetTimeValSockOpt(const SetSockOptLen &optlen) :
			item::TimeValParameter{ItemCfg{
				ItemType::PARAM_IN,
				"optval",
				"struct timeval*"}},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &proc) override;

protected: // data

	const SetSockOptLen &m_optlen;
};

/// Specialization of TimeValParameter which takes `optlen` into account.
class GetTimeValSockOpt :
		public item::TimeValParameter {
public: // functions

	explicit GetTimeValSockOpt(const GetSockOptLen &optlen) :
			item::TimeValParameter{ItemCfg{
				ItemType::PARAM_OUT,
				"optval",
				"struct timeval*"}},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	const GetSockOptLen &m_optlen;
};

/// Specialization of TimeSpecParameter which takes `optlen` into account.
class SetTimeSpecSockOpt :
		public item::TimeSpecParameter {
public: // functions

	explicit SetTimeSpecSockOpt(const SetSockOptLen &optlen) :
			item::TimeSpecParameter{ItemCfg{
				ItemType::PARAM_IN,
				"optval",
				"struct timespec*"}},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &proc) override;

protected: // data

	const SetSockOptLen &m_optlen;
};

/// Specialization of TimeSpecParameter which takes `optlen` into account.
class GetTimeSpecSockOpt :
		public item::TimeSpecParameter {
public: // functions

	explicit GetTimeSpecSockOpt(const GetSockOptLen &optlen) :
			item::TimeSpecParameter{ItemCfg{
				ItemType::PARAM_OUT,
				"optval",
				"struct timespec*"}},
			m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	const GetSockOptLen &m_optlen;
};

template <class BASE, class OPT_LEN>
class BufLockSockOptT :
		public BASE {
public: // types

	enum class LockType : int {
		SNDBUF = SOCK_SNDBUF_LOCK,
		RCVBUF = SOCK_RCVBUF_LOCK
	};

	using LockMask = cosmos::BitMask<LockType>;

public: // functions

	std::optional<LockMask> mask() const {
		return m_mask;
	}

	std::string str() const override;

protected: // functions

	BufLockSockOptT(const OPT_LEN &optlen, const ItemType type) :
			BASE{optlen, ItemCfg{type, "optval", "int bitmask"}} {
	}

protected: // data

	std::optional<LockMask> m_mask;
};

class GetBufLockSockOpt :
		public BufLockSockOptT<GetSockOptVal<int>, GetSockOptLen> {
public: // functions

	GetBufLockSockOpt(const GetSockOptLen &optlen) :
			BufLockSockOptT{optlen, ItemType::PARAM_OUT} {
	}

protected: // functions

	void updateData(const Tracee &proc) override;
};

class SetBufLockSockOpt :
		public BufLockSockOptT<SetSockOptVal<int>, SetSockOptLen> {
public: // functions

	SetBufLockSockOpt(const SetSockOptLen &optlen) :
			BufLockSockOptT{optlen, ItemType::PARAM_IN} {
	}

protected: // functions

	void processData(const Tracee &proc) override;
};

/*
 * define this here on our own, since <linux/uio.h> makes the compiler
 * choke over redefinition of `struct iovec`.
 */
struct dmabuf_token {
	uint32_t token_start;
	uint32_t token_count;
};

class SetDevMemDontNeedSockOpt :
		public SetSockOptStruct<dmabuf_token> {
public: // functions

	explicit SetDevMemDontNeedSockOpt(const SetSockOptLen &optlen) :
			SetSockOptStruct{optlen, ItemCfg{.desc = "struct dmabuf_token*"}} {
	}

	std::string str() const override;
};

class TxTimeSockOptBase {
protected:
	std::string str(const sock_txtime&) const;
};

class GetTxTimeSockOpt :
		public GetSockOptStruct<sock_txtime>,
		public TxTimeSockOptBase {
public: // functions

	explicit GetTxTimeSockOpt(const GetSockOptLen &optlen) :
			GetSockOptStruct{optlen, ItemCfg{
				.desc = "struct sock_txtime*"}} {
	}

	std::string str() const override;
};

class SetTxTimeSockOpt :
		public SetSockOptStruct<sock_txtime>,
		public TxTimeSockOptBase {
public: // functions

	explicit SetTxTimeSockOpt(const SetSockOptLen &optlen) :
			SetSockOptStruct{optlen, ItemCfg{
				.desc = "struct sock_txtime*"}} {
	}

	std::string str() const override;
};

CLUES_DEFAULT_VISIBILITY_OFF;

}} // end ns * 2
