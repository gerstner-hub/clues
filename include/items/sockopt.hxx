#pragma once

// C++
#include <variant>

// Linux
#include <netinet/in.h>
#include <sys/socket.h>

// clues
#include <clues/items/items.hxx>
#include <clues/items/seccomp.hxx>

namespace clues {

enum class SockOptType;

namespace item {

/**
 * @file
 * This header contains getsockopt() and setsockopt() related types. There are
 * many different specializations of these ioctl-style system calls which also
 * requires a bunch of dedicated types for the concrete `optval` parameters
 * used.
 **/

CLUES_DEFAULT_VISIBILITY_ON;

/// Specialized pointer to `optval` in getsockopt().
template <typename T>
class GetSockOptVal :
		public item::PointerToScalar<T> {
public: // functions

	explicit GetSockOptVal(const item::PointerToScalar<int> &optlen, const ItemCfg cfg = {}) :
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
		if (!this->m_call->hasResultValue() || m_optlen.value() < sizeof(T)) {
			this->m_val.reset();
			return;
		}

		return PointerToScalar<T>::updateData(tracee);
	}

protected: // data

	const item::PointerToScalar<int> &m_optlen;
};

/// Specialized pointer to `optval` in setsockopt().
template <typename T>
class SetSockOptVal :
		public item::PointerToScalar<T> {
public: // functions

	explicit SetSockOptVal(const item::IntValue &optlen, const ItemCfg cfg = {}) :
			clues::item::PointerToScalar<T>{cfg.applyDefaults(ItemCfg{.label = "optval"})},
			m_optlen{optlen} {
	}

protected: // data

	const item::IntValue &m_optlen;
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

	enum class SocketOption : int {
		ACCEPTCONN            = SO_ACCEPTCONN,            ///< read-only boolean option whether the socket is in listening state.
		ATTACH_FILTER         = SO_ATTACH_FILTER,         ///< set a classic BPF filter program passed in `struct fprog` argument.
		ATTACH_BPF            = SO_ATTACH_BPF,            ///< set an extended BPF filter program passed in a `bpf()` file descriptor argument.
		GET_FILTER            = SO_GET_FILTER,            ///< returns the currently installed filter program into an array of `struct sock_fprog*`. `optlen` is determines the amount of array entries on in/output.
		ATTACH_REUSEPORT_CBPF = SO_ATTACH_REUSEPORT_CBPF, ///< similar to ATTACH_FILTER, assigns program to control packet distribution in SO_REUSEPORT scenarios.
		ATTACH_REUSEPORT_EBPF = SO_ATTACH_REUSEPORT_EBPF, ///< similar to ATTACH_BPF for SO_REUSEPORT scenarios.
		BINDTODEVICE          = SO_BINDTODEVICE,          ///< receive only packets from the given network interface; string option.
		BROADCAST             = SO_BROADCAST,             ///< set/get broadcast boolean option.
		BSDCOMPAT             = SO_BSDCOMPAT,             ///< no longer available boolean option for BSD bug-to-bug compatibility.
		DEBUG                 = SO_DEBUG,                 ///< set/get boolean socket debugging option.
		DETACH_BPF            = SO_DETACH_BPF,            ///< remove any active FILTER/BPF program, no option data, synonym to DETACH_FILTER.
		DOMAIN                = SO_DOMAIN,                ///< returns the SocketDomain::Domain the socket belongs too, read-only option.
		ERROR                 = SO_ERROR,                 ///< get and clear any pending socket error. Integer errno option.
		DONTROUTE             = SO_DONTROUTE,             ///< get/set boolean option defining whether gateways may be used, corresponding to cosmos::MessageFlag::DONTROUTE used in send().
		INCOMING_CPU          = SO_INCOMING_CPU,          ///< get/set CPU affinity for the socket. Integer CPU number option.
		INCOMING_NAPI_ID      = SO_INCOMING_NAPI_ID,      ///< returns an ID for the RX queue used to receive packets on this socket. Integer ID value, read-only.
		KEEPALIVE             = SO_KEEPALIVE,             ///< get/set boolean keepalive option.
		LINGER                = SO_LINGER,                ///< get/set the current linger option; uses `struct linger`.
		LOCK_FILTER           = SO_LOCK_FILTER,           ///< lock any currently installed BPF programs on the socket with no way of turning the lock off again. This still takes a boolean.
		MARK                  = SO_MARK,                  ///< get/set the mark used for each packet sent through the socket. Takes a `uint32_t`.
		OOBINLINE             = SO_OOBINLINE,             ///< receive out-of-band data directly in the receive data stream. Boolean get/set option.
		PASSCRED              = SO_PASSCRED,              ///< (AF_UNIX) get/set boolean whether to receive SCM_CREDENTIALS control messages.
		PASSSEC               = SO_PASSSEC,               ///< (AF_UNIX) get/set boolean whether to receive SCM_SECURITY control messages.
		PEEK_OFF              = SO_PEEK_OFF,              ///< (AF_UNIX) get/set offset to be maintained in the context of MSG_PEEK `recv()` calls. `int` value.
		PEERCRED              = SO_PEERCRED,              ///< (AF_UNIX) get the `struct ucred` of the peer used during `connect()` or `socketpair()` time.
		PEERSEC               = SO_PEERSEC,               ///< (AF_UNIX) get a string describing the security context of the peer. Content depends on the LSM in effect.
		PRIORITY              = SO_PRIORITY,              ///< get/set the priority used for packets sent on the socket. Integer value.
		PROTOCOL              = SO_PROTOCOL,              ///< get the socket's protocol option. Integer value. Interpretation is depending on SocketDomain.
		RCVBUF                = SO_RCVBUF,                ///< get/set the maximum receive buffer size used in the kernel. Integer value.
		RCVBUFFORCE           = SO_RCVBUFFORCE,           ///< forced RCVBUF setting with `CAP_NET_ADMIN`.
		RCVLOWAT              = SO_RCVLOWAT,              ///< get/set minimum number of bytes in receive buffer before passing data to userspace. Integer option.
		SNDLOWAT              = SO_SNDLOWAT,              ///< get minimum number of bytes in send buffer before passing on to the protocol layer. Cannot be changed on Linux. Integer option.
		RCVTIMEO              = SO_RCVTIMEO,              ///< get/set receive timeout in `struct timeval` argument.
		SNDTIMEO              = SO_SNDTIMEO,              ///< get/set send timeout in `struct timeval` argument.
		REUSEADDR             = SO_REUSEADDR,             ///< get/set reuse address boolean option.
		REUSEPORT             = SO_REUSEPORT,             ///< get/set reuse port boolean option.
		RXQ_OVFL              = SO_RXQ_OVFL,              ///< get/set boolean option whether to supply a 32-bit value ancillary message indicating the number of dropped packets.
		SELECT_ERR_QUEUE      = SO_SELECT_ERR_QUEUE,      ///< get/set select() error handling behaviour boolean option. Deprecated.
		SNDBUF                = SO_SNDBUF,                ///< get/set maximum send buffer size used in the kernel. Integer value.
		SNDBUFFORCE           = SO_SNDBUFFORCE,           ///< forced SNDBUF setting with `CAP_NET_ADMIN`.
		TIMESTAMP             = SO_TIMESTAMP,             ///< get/set reception of `SCM_TIMESTAMP` control messages. Boolean option.
		TIMESTAMPNS           = SO_TIMESTAMPNS,           ///< get/set reception of `SCM_TIMESTAMPNS` control messages. Boolean option.
		TYPE                  = SO_TYPE,                  ///< get the socket type. Integer value.
		BUSY_POLL             = SO_BUSY_POLL              ///< get/set a poll duration in microseconds for `recv()` calls on the socket. Integer option.
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

/// Type for `struct sock_fprog` as used with SO_ATTACH_FILTER.
/**
 * This specialization of FilterProg checks that the `optlen` is sufficient to
 * process a `struct sock_fprog`.
 **/
class AttachFilterSockOpt :
		public FilterProg {
public: // functions

	explicit AttachFilterSockOpt(const IntValue &optlen) :
				FilterProg{ItemType::PARAM_IN},
				m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &) override;

protected: // data

	const IntValue &m_optlen;
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

	explicit GetFilterSocktOpt(const PointerToScalar<int> &optlen) :
				FilterProg{ItemType::PARAM_OUT},
				m_optlen{optlen} {
		this->m_flags.set(SystemCallItem::Flag::DEFER_FILL);
	}

protected: // functions

	void processData(const Tracee &) override;

	void updateData(const Tracee &) override;

protected: // data

	const PointerToScalar<int> &m_optlen;
};

CLUES_DEFAULT_VISIBILITY_OFF;

}} // end ns * 2
