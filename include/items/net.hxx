#pragma once

// C++
#include <array>
#include <variant>

// Linux
#include <linux/net.h>
#include <linux/netlink.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// cosmos
#include <cosmos/net/inet/IPAddress.hxx>
#include <cosmos/net/LinkLayerAddress.hxx>
#include <cosmos/net/message_header.hxx>
#include <cosmos/net/netlink/NetlinkAddress.hxx>
#include <cosmos/net/Socket.hxx>
#include <cosmos/net/unix/UnixAddress.hxx>

// clues
#include <clues/items/fs.hxx>
#include <clues/items/io.hxx>
#include <clues/items/items.hxx>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

struct SocketFD :
		public FileDescriptor {
	explicit SocketFD() :
			FileDescriptor{make_item_cfg(
					"sockfd",
					"socket file descriptor")} {
	}
};

/// Pass-by-value address length `socklen_t` for socket-related system calls.
struct AddressLength :
		public IntValue {
	explicit AddressLength() :
			IntValue{ItemCfg{.label = "addrlen"}} {
	}
};

/// Value-result address length parameter for socket-related system calls.
/**
 * On input this points to a `socklen_t` (`int`) providing the maximum amount
 * of space in the `struct sockaddr*` which is also passed to the system call.
 * On output the actually filled-in amount of bytes in the `structk sockaddr*`
 * is reported. These two usually only differ for certain address families
 * like `AF_UNIX`, or if applications use `sockaddr_storage`.
 **/
struct AddressLengthPointer :
		public PointerToScalar<int> {
public: // functions

	explicit AddressLengthPointer() :
			clues::item::PointerToScalar<int>{
				ItemCfg{
					ItemType::PARAM_IN_OUT,
					"addrlen",
					"socklen_t*"
				}} {
	}

	std::optional<int> available() const {
		return m_available;
	}

	std::optional<int> filled() const {
		return m_filled;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override;

	void updateData(const Tracee &) override;

protected: // data

	std::optional<int> m_available;
	std::optional<int> m_filled;
};

/// The basic socket domain of a newly created socket.
class SocketDomain :
		public ValueInParameter {
public: // types

	enum class Domain : int {
		UNSPEC    = AF_UNSPEC,
		ALG       = AF_ALG,
		APPLETALK = AF_APPLETALK,
		AX25      = AF_AX25,
		BLUETOOTH = AF_BLUETOOTH,
		CAN       = AF_CAN,
		DECnet    = AF_DECnet,
		IB        = AF_IB,
		INET6     = AF_INET6,
		INET      = AF_INET,
		IPX       = AF_IPX,
		KCM       = AF_KCM,
		KEY       = AF_KEY,
		LLC       = AF_LLC,
		LOCAL     = AF_LOCAL,
		MPLS      = AF_MPLS,
		NETLINK   = AF_NETLINK,
		PACKET    = AF_PACKET,
		PPPOX     = AF_PPPOX,
		RDS       = AF_RDS,
		TIPC      = AF_TIPC,
		UNIX      = AF_UNIX,
		VSOCK     = AF_VSOCK,
		X25       = AF_X25,
		XDP       = AF_XDP,
	};

	using enum Domain;

public: // functions

	explicit SocketDomain() :
		ValueInParameter{ItemCfg{.label = "domain"}} {
	}

	std::string str() const override;

	Domain domain() const {
		return m_domain;
	}

	static std::string_view label(const Domain domain);

protected: // functions

	void processValue(const Tracee&) override {
		m_domain = Domain{valueAs<int>()};
	}

protected: // data

	Domain m_domain{};
};

/// The type of a socket in the context of a given SocketDomain for a newly created socket.
/**
 * Similar to the `flags` in open(), this type consists of a type value and
 * additional bitmask flags. Both parts are provided as separate parameters by
 * this class.
 **/
class SocketType :
		public ValueInParameter {
public: // types

	enum class Type : int {
		DGRAM     = SOCK_DGRAM,
		PACKET    = SOCK_PACKET,
		RAW       = SOCK_RAW,
		RDM       = SOCK_RDM,
		SEQPACKET = SOCK_SEQPACKET,
		STREAM    = SOCK_STREAM,
		DCCP      = SOCK_DCCP,
	};

	using enum Type;

	enum class Flag : int {
		NONBLOCK = SOCK_NONBLOCK,
		CLOEXEC  = SOCK_CLOEXEC
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit SocketType() :
			ValueInParameter{ItemCfg{.label = "type"}} {
	}

	std::string str() const override;

	Type type() const {
		return m_type;
	}

	Flags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Type m_type{};
	Flags m_flags;
};

/// The SocketDomain-specific protocol for newly created sockets.
/**
 * This value is typically zero, since most socket domains only support one
 * protocol. In case the value is required then its interpretation depends on
 * the SocketDomain e.g. for `AF_INET` this will be an entry from
 * `/etc/protocols`.
 **/
class SocketProtocol :
		public ValueInParameter {
public: // types

	///  For IP-based domains this defines the desired IP-protocol.
	/**
	 * Typically this will be specified as 0, but in some cases
	 * applications may explicitly pass the desired IP-protocol. This is
	 * only present for Domain::INET and Domain::INET6.
	 **/
	enum class IPProtocol : int {
	    IP       = IPPROTO_IP,
	    ICMP     = IPPROTO_ICMP,
	    IGMP     = IPPROTO_IGMP,
	    IPIP     = IPPROTO_IPIP,
	    TCP      = IPPROTO_TCP,
	    EGP      = IPPROTO_EGP,
	    PUP      = IPPROTO_PUP,
	    UDP      = IPPROTO_UDP,
	    IDP      = IPPROTO_IDP,
	    TP       = IPPROTO_TP,
	    DCCP     = IPPROTO_DCCP,
	    IPV6     = IPPROTO_IPV6,
	    RSVP     = IPPROTO_RSVP,
	    GRE      = IPPROTO_GRE,
	    ESP      = IPPROTO_ESP,
	    AH       = IPPROTO_AH,
	    MTP      = IPPROTO_MTP,
	    BEETPH   = IPPROTO_BEETPH,
	    ENCAP    = IPPROTO_ENCAP,
	    PIM      = IPPROTO_PIM,
	    COMP     = IPPROTO_COMP,
	    L2TP     = IPPROTO_L2TP,
	    SCTP     = IPPROTO_SCTP,
	    UDPLITE  = IPPROTO_UDPLITE,
	    MPLS     = IPPROTO_MPLS,
	    ETHERNET = IPPROTO_ETHERNET,
	    RAW      = IPPROTO_RAW,
#ifdef IPPROTO_SMC
	    SMC      = IPPROTO_SMC,
#endif
	    MPTCP    = IPPROTO_MPTCP,
	};

	/// The Ethernet protocol used with Domain::PACKET.
	enum class EthProtocol : int {
		LOOP        = ETH_P_LOOP,
		PUP         = ETH_P_PUP,
		PUPAT       = ETH_P_PUPAT,
		TSN         = ETH_P_TSN,
		ERSPAN2     = ETH_P_ERSPAN2,
		IP          = ETH_P_IP,
		X25         = ETH_P_X25,
		ARP         = ETH_P_ARP,
		BPQ         = ETH_P_BPQ,
		IEEEPUP     = ETH_P_IEEEPUP,
		IEEEPUPAT   = ETH_P_IEEEPUPAT,
		BATMAN      = ETH_P_BATMAN,
		DEC         = ETH_P_DEC,
		DNA_DL      = ETH_P_DNA_DL,
		DNA_RC      = ETH_P_DNA_RC,
		DNA_RT      = ETH_P_DNA_RT,
		LAT         = ETH_P_LAT,
		DIAG        = ETH_P_DIAG,
		CUST        = ETH_P_CUST,
		SCA         = ETH_P_SCA,
		TEB         = ETH_P_TEB,
		RARP        = ETH_P_RARP,
		ATALK       = ETH_P_ATALK,
		AARP        = ETH_P_AARP,
		VLAN_8021Q  = ETH_P_8021Q,
		ERSPAN      = ETH_P_ERSPAN,
		IPX         = ETH_P_IPX,
		IPV6        = ETH_P_IPV6,
		PAUSE       = ETH_P_PAUSE,
		SLOW        = ETH_P_SLOW,
		WCCP        = ETH_P_WCCP,
		MPLS_UC     = ETH_P_MPLS_UC,
		MPLS_MC     = ETH_P_MPLS_MC,
		ATMMPOA     = ETH_P_ATMMPOA,
		PPP_DISC    = ETH_P_PPP_DISC,
		PPP_SES     = ETH_P_PPP_SES,
		LINK_CTL    = ETH_P_LINK_CTL,
		ATMFATE     = ETH_P_ATMFATE,
		PAE         = ETH_P_PAE,
#ifdef ETH_P_PROFINET
		PROFINET    = ETH_P_PROFINET,
#endif
#ifdef ETH_P_REALTEK
		REALTEK     = ETH_P_REALTEK,
#endif
		AOE         = ETH_P_AOE,
#ifdef ETH_P_ETHERCAT
		ETHERCAT    = ETH_P_ETHERCAT,
#endif
		VLAN_8021AD = ETH_P_8021AD,
		EX1_802     = ETH_P_802_EX1,
		PREAUTH     = ETH_P_PREAUTH,
		TIPC        = ETH_P_TIPC,
		LLDP        = ETH_P_LLDP,
		MRP         = ETH_P_MRP,
		MACSEC      = ETH_P_MACSEC,
		BACK_8021AH = ETH_P_8021AH,
		MVRP        = ETH_P_MVRP,
		TS_1588     = ETH_P_1588,
		NCSI        = ETH_P_NCSI,
		PRP         = ETH_P_PRP,
		CFM         = ETH_P_CFM,
		FCOE        = ETH_P_FCOE,
		IBOE        = ETH_P_IBOE,
		TDLS        = ETH_P_TDLS,
		FIP         = ETH_P_FIP,
		HO_80221    = ETH_P_80221,
		HSR         = ETH_P_HSR,
		NSH         = ETH_P_NSH,
		LOOPBACK    = ETH_P_LOOPBACK,
		QINQ1       = ETH_P_QINQ1,
		QINQ2       = ETH_P_QINQ2,
		QINQ3       = ETH_P_QINQ3,
		EDSA        = ETH_P_EDSA,
		DSA_8021Q   = ETH_P_DSA_8021Q,
#ifdef ETH_PDSA_A5PSW
		DSA_A5PSW   = ETH_P_DSA_A5PSW,
#endif
		IFE         = ETH_P_IFE,
		IUCV        = ETH_P_AF_IUCV,
		ALL         = ETH_P_ALL
	};

	/// The specific Netlink protocol used with Domain::NETLINK.
	enum class NetlinkProtocol : int {
		ROUTE          = NETLINK_ROUTE,
		UNUSED         = NETLINK_UNUSED,
		USERSOCK       = NETLINK_USERSOCK,
		FIREWALL       = NETLINK_FIREWALL,
		SOCK_DIAG      = NETLINK_SOCK_DIAG,
		NFLOG          = NETLINK_NFLOG,
		XFRM           = NETLINK_XFRM,
		SELINUX        = NETLINK_SELINUX,
		ISCSI          = NETLINK_ISCSI,
		AUDIT          = NETLINK_AUDIT,
		FIB_LOOKUP     = NETLINK_FIB_LOOKUP,
		CONNECTOR      = NETLINK_CONNECTOR,
		NETFILTER      = NETLINK_NETFILTER,
		IP6_FW         = NETLINK_IP6_FW,
		DNRTMSG        = NETLINK_DNRTMSG,
		KOBJECT_UEVENT = NETLINK_KOBJECT_UEVENT,
		GENERIC        = NETLINK_GENERIC,
		SCSITRANSPORT  = NETLINK_SCSITRANSPORT,
		ECRYPTFS       = NETLINK_ECRYPTFS,
		RDMA           = NETLINK_RDMA,
		CRYPTO         = NETLINK_CRYPTO,
		SMC            = NETLINK_SMC,
	};

	using ProtocolVariant = std::variant<IPProtocol,EthProtocol,NetlinkProtocol,std::monostate>;

public: // functions

	explicit SocketProtocol(const SocketDomain &domain) :
			ValueInParameter{make_item_cfg("prot", "protocol")},
			m_domain{domain} {
	}

	std::string str() const override;

	ProtocolVariant prot() const {
		return m_prot;
	}

	int raw() const {
		return m_raw;
	}

	std::string_view label(const NetlinkProtocol prot) const;

	std::string_view label(const IPProtocol prot) const;

	std::string_view label(const EthProtocol prot) const;

protected: // functions

	void processValue(const Tracee&) override;

	std::string label(const std::monostate) const;

protected: // data

	int m_raw{};
	ProtocolVariant m_prot;
	const SocketDomain &m_domain;
};

/// `socketcall()` sub-system call enum.
class SocketCallType :
		public ValueInParameter {
public: // types

	enum class Call : int {
		INVALID     = 0,
		ACCEPT4     = SYS_ACCEPT4,
		ACCEPT      = SYS_ACCEPT,
		BIND        = SYS_BIND,
		CONNECT     = SYS_CONNECT,
		GETPEERNAME = SYS_GETPEERNAME,
		GETSOCKNAME = SYS_GETSOCKNAME,
		GETSOCKOPT  = SYS_GETSOCKOPT,
		LISTEN      = SYS_LISTEN,
		RECVFROM    = SYS_RECVFROM,
		RECVMMSG    = SYS_RECVMMSG,
		RECVMSG     = SYS_RECVMSG,
		RECV        = SYS_RECV,
		SENDMMSG    = SYS_SENDMMSG,
		SENDMSG     = SYS_SENDMSG,
		SEND        = SYS_SEND,
		SENDTO      = SYS_SENDTO,
		SETSOCKOPT  = SYS_SETSOCKOPT,
		SHUTDOWN    = SYS_SHUTDOWN,
		SOCKETPAIR  = SYS_SOCKETPAIR,
		SOCKET      = SYS_SOCKET,
	};

	using enum Call;

public: // functions

	SocketCallType() :
			ValueInParameter{make_item_cfg("call", "socket sub-system call")} {
	}

	std::string str() const override;

	Call call() const {
		return m_call;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_call = Call{valueAs<int>()};
	}

protected: // data

	Call m_call{};
};

/// Array of `unsigned long` containing context-dependent parameters for `socketcall()`.
/**
 * The multiplexed `socketcall()` system call passes the actual system call
 * parameters in an array of `unsigned long`. These values need to be casted
 * to the proper context-dependent type (can also be pointers).
 *
 * The helper class `SocketCallBase` and its specializations interpret the
 * individual `unsigned long` values as needed. The `str()` override will
 * format the parameters of the base class `SocketCallBase`.
 **/
class SocketCallArgs :
		public PointerValue {
public: // functions

	explicit SocketCallArgs(const SocketCallType &type) :
			PointerValue{ItemCfg(ItemType::PARAM_IN_OUT, "args", "socketcall argument block")},
       			m_type{type} {
	}

	std::string str() const override;

	bool valid() const {
		// all sub-calls use > 0 arguments
		return !m_args.empty();
	}

	const std::vector<unsigned long>& args() const {
		return m_args;
	}

	static std::vector<unsigned long> fetchArgs(const Tracee &,
			const ABI abi,
			const SocketCallType::Call call,
			const ForeignPtr arg_ptr);

protected: // functions

	void processValue(const Tracee&) override;

	void updateData(const Tracee&) override {
		/*
		 * This is sometimes an IN/OUT type parameter, but we cover
		 * that indirectly via the update of the base class items that
		 * are not registered as actual parameters of the system call.
		 * This update is done in SocketCallBase::postSystemCall().
		 *
		 * This stills needs to be marked as PARAM_IN_OUT to maintain
		 * the proper semantics (e.g. don't call str() on this type
		 * before system call exit happened).
		 */
	}

protected: // data

	const SocketCallType &m_type;
	std::vector<unsigned long> m_args;
};

class SocketPair :
		public PointerOutValue {
public: // functions

	explicit SocketPair() :
			PointerOutValue{make_item_cfg("sv", "int[2] output pointer")} {
	}

	std::string str() const override;

	const std::array<cosmos::FileNum, 2> pair() const {
		return m_pair;
	}

protected: // functions

	void processValue(const Tracee&) override;

	void updateData(const Tracee&) override;

protected: // data

	bool m_valid = false;
	std::array<cosmos::FileNum, 2> m_pair;
};

/// `struct sockaddr*` type parameters for the socket family of syscalls.
class SocketAddress :
		public PointerValue {
public: // types

	using AddressVariant = std::variant<
	      cosmos::IP4Address,
	      cosmos::IP6Address,
	      cosmos::UnixAddress,
	      cosmos::NetlinkAddress,
	      cosmos::LinkLayerAddress>;

public: // functions

	explicit SocketAddress(
		const ItemCfg &cfg,
		std::variant<const IntValue*, const PointerToScalar<int>*> len);

	std::string str() const override;

	/// Provides a specialized type with detailed address information.
	/**
	 * Only more the more common address families are currently modeled.
	 * If std::nullopt is returned then there is currently no support for
	 * the address family in effect (or no valid address is stored).
	 **/
	std::optional<AddressVariant> addr() const;

	SocketDomain::Domain domain() const {
		if (!valid())
			return SocketDomain::UNSPEC;

		return SocketDomain::Domain{m_addr->ss_family};
	}

	bool valid() const {
		return m_addr != std::nullopt;
	}

protected: // functions

	void processValue(const Tracee &) override;

	int addrLen() const;

protected: // data

	std::optional<sockaddr_storage> m_addr;
	const IntValue *m_len{};
	const PointerToScalar<int> *m_lenp{};
};

/// Flags used with accept4() style system calls.
class AcceptFlags :
		public ValueInParameter {
public: // types

	using Flag = SocketType::Flag;
	using enum Flag;
	using Flags = SocketType::Flags;

public: // functions

	explicit AcceptFlags() :
			ValueInParameter{ItemCfg{
				.label = "flags",
				.desc = "initial socket flags"}} {
	}

	std::string str() const override;

	Flags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_flags = Flags{valueAs<int>()};
	}

protected: // data

	Flags m_flags{};
};

/// Enum type used with ShutdownSystemCall.
class ShutdownType :
		public ValueInParameter {
public: // types

	using Direction = cosmos::Socket::Direction;

	using enum cosmos::Socket::Direction;

public: // functions

	explicit ShutdownType() :
			ValueInParameter{ItemCfg{
				.label = "how",
				.desc = "direction to shutdown"}} {
	}

	std::string str() const override;

	Direction direction() const {
		return m_dir;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_dir = Direction{valueAs<int>()};
	}

protected: // data

	Direction m_dir{};
};

/// Flags used with the recv() and send() family of functions.
/**
 * This type reuses cosmos::MessageFlag, which combines the options for
 * send/receive, since they don't overlap.
 **/
class SendRecvFlags :
		public ValueInParameter {
public: // types

	using MessageFlag = cosmos::MessageFlag;
	using MessageFlags = cosmos::MessageFlags;

	using enum MessageFlag;

public: // functions

	explicit SendRecvFlags() :
			ValueInParameter{ItemCfg{
				.label = "flags",
				.desc = "send/receive options"}} {
	}

	std::string str() const override;

	MessageFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_flags = MessageFlags{valueAs<int>()};
	}

protected: // data

	MessageFlags m_flags{};
};

/// Base class for SendMessageHeader and ReceiveMessageHeader.
/**
 * This type keeps common logic which is shared between the two system calls,
 * most notably dealing with control data and ABI conversion.
 **/
class MessageHeaderBase :
		public PointerValue {
protected: // functions

	explicit MessageHeaderBase(const ItemCfg &cfg) :
			PointerValue{cfg.applyDefaults(ItemCfg{.label = "msg"})},
			m_msg_control{m_msg_controllen, ItemCfg{
				cfg.type == ItemType::PARAM_IN ? ItemType::PARAM_IN : ItemType::PARAM_OUT,
				"msg_control"}, /*is_binary=*/true},
			m_msg_controllen{ItemCfg{
				cfg.type == ItemType::PARAM_IN ? ItemType::PARAM_IN : ItemType::PARAM_IN_OUT,
				"msg_controllen"}} {
	}

	bool fetchMsgHdr32(const Tracee &proc, std::optional<struct msghdr> &out);

	std::vector<std::byte> convertControlHeader32() const;

	/// Returns a description of contained control messages.
	std::string controlStr(const std::optional<cosmos::ReceiveMessageHeader> &hdr) const;

protected: // data

	BufferPointer m_msg_control;
	IntValue m_msg_controllen;
};

class RecvMessageHeader :
		public MessageHeaderBase {
public: // functions

	explicit RecvMessageHeader(const SystemCallItem &obtained_bytes) :
			MessageHeaderBase{ItemCfg{ItemType::PARAM_IN_OUT}},
			m_msg_name{ItemCfg{ItemType::PARAM_OUT}, &m_msg_namelen},
			m_msg_iov{m_msg_iovlen, obtained_bytes},
			m_msg_iovlen{ItemCfg{.label = "num_iovs"}} {
	}

	std::string str() const override;

	/// Provides access to message control data and flags.
	/**
	 * This is only valid after system call exit, else std::nullopt
	 * will be returned. The returned object will contain a copy of the
	 * control data as well as a copy of the receive flags observed in the
	 * tracee. You can use the ControlMessage iterators to inspect
	 * individual messages.
	 *
	 * \warning when 32-bit cross ABI tracing is in effect then accessing
	 * control data is a very messy endeavour. This is because the binary
	 * data in the control data can also be subject to ABI differences.
	 * This function will return a control data structure converted from
	 * 32-bit to 64-bit representation such that the 64-bit tracer can
	 * safely iterate over individual control messages.
	 *
	 * Regarding control message payload libclues currently only considers
	 * UNIX domain socket ancillary messages for this scenario.
	 **/
	std::optional<cosmos::ReceiveMessageHeader> header() const;

	/// Provides access to the raw payload data which was received.
	/*
	 * This is only valid after system call exit. The buffer contents will
	 * be truncated if buffer fetch limits are in effect.
	 */
	const ReadVector::BufferVector& ioVector() const {
		return m_msg_iov.buffers();
	}

	/// Provides access to the raw control data which was received.
	/**
	 * This is only valid after system call exit. This type will always
	 * fetch the complete control data regardless of buffer fetch limits
	 * in effect.
	 **/
	const std::vector<std::byte>& controlData() const {
		return m_msg_control.data();
	}

protected: // functions

	void processValue(const Tracee &) override;

	void updateData(const Tracee &) override;

	void resetSubItems(const Tracee &proc);

	void fillSubItems(const Tracee &);

	void updateSubItems(const Tracee &);

protected: // data

	/* let's reuse items as sub-items for this complex structure */
	SocketAddress m_msg_name;
	AddressLength m_msg_namelen;
	ReadVector m_msg_iov;
	SizeValue m_msg_iovlen;
	SendRecvFlags m_msg_flags;

	///! Header as observed during system call entry.
	std::optional<struct msghdr> m_in_header;
	///! Header as observed during system call exit.
	std::optional<struct msghdr> m_out_header;
};

/// Extended variant of `struct msghdr` used with RecvMessageHeaderVector for `recvmmsg()`.
/**
 * This structure basically carries an additional `unsigned int` to
 * communicate back the individual amount of received bytes.
 **/
class RecvMultiMessageHeader :
		public RecvMessageHeader {

	// allow to set protected members
	friend class RecvMessageHeaderVector;
	// allow to fill sub-items
	template <typename HDR_ITEM>
	friend class MessageHeaderVectorBase;

public: // functions

	/// Create a new header based on `hdr` for the input header part.
	/**
	 * The given `hdr` will be assigned to the input header part of
	 * RecvMessageHeader.
	 **/
	explicit RecvMultiMessageHeader(const SystemCall *call,
			const struct msghdr &hdr);

	/// Number of bytes received.
	/**
	 * Upon system call exit of recvmmsg() this contains the number of
	 * bytes received into the msghdr. In other states or when a tracing
	 * error occurred, std::nullopt is returned.
	 **/
	std::optional<unsigned long> bytesReceived() const {
		if (!m_have_bytes_received)
			return {};

		return m_bytes_received.value();
	}

protected: // functions

	using RecvMessageHeader::fillSubItems;
	using RecvMessageHeader::updateSubItems;

	void setBytesReceived(const unsigned int received, const Tracee &proc) {
		m_bytes_received.fill(proc, Word{received});
		m_have_bytes_received = true;
	}

	/// Apply the output header information as found in `hdr`.
	/**
	 * This will also trigger a call to updateSubItems() to reflect the
	 * changes.
	 **/
	void setOutHeader(const struct msghdr &hdr, const Tracee &);

protected: // data

	// contrary to SendMultiMessageHeader we need a fully-fledged
	// SystemCallItem here, because the RecvMessageHeader base class
	// expects a reference to one to determine the amount of received
	// bytes.

	bool m_have_bytes_received = false;
	UintValue m_bytes_received;
};

class SendMessageHeader :
		public MessageHeaderBase {
public: // functions

	explicit SendMessageHeader() :
			MessageHeaderBase{ItemCfg{ItemType::PARAM_IN}},
			m_msg_name{ItemCfg{ItemType::PARAM_IN}, &m_msg_namelen},
			m_msg_iov{m_msg_iovlen},
			m_msg_iovlen{ItemCfg{.label = "num_iovs"}} {
	}

	std::string str() const override;

	/// Provides access to message control data and flags.
	/**
	 * The returned object will contain a copy of the control data as well
	 * as a copy of the receive flags observed in the tracee. You can use
	 * the ControlMessage iterators to inspect individual messages. This
	 * uses cosmos::ReceiveMessageHeader instead of
	 * cosmos::SendMessageHeader, because the latter is intended for
	 * constructing a new outgoing message, while we are dealing with an
	 * already assembled messages used by the tracee.
	 *
	 * \warning See RecvMessageHeader::header() for limitations of
	 * cross-ABI tracing.
	 **/
	std::optional<cosmos::ReceiveMessageHeader> header() const;

	/// Provides access to the raw payload data which is to be sent out.
	/*
	 * The buffer contents will be truncated if buffer fetch limits are in
	 * effect.
	 */
	const WriteVector::BufferVector& ioVector() const {
		return m_msg_iov.buffers();
	}

	/// Provides access to the raw control data which is to be sent out.
	/**
	 * This type will always fetch the complete control data regardless of
	 * buffer fetch limits in effect.
	 **/
	const std::vector<std::byte>& controlData() const {
		return m_msg_control.data();
	}

protected: // functions

	void processValue(const Tracee &) override;

	void resetSubItems(const Tracee &proc);

	void fillSubItems(const Tracee &);

protected: // data

	/* let's reuse items as sub-items for this complex structure */
	SocketAddress m_msg_name;
	AddressLength m_msg_namelen;
	WriteVector m_msg_iov;
	SizeValue m_msg_iovlen;
	SendRecvFlags m_msg_flags;

	std::optional<struct msghdr> m_header;
};

/// Extended variant of `struct msghdr` used with SendMessageHeaderVector for `sendmmsg()`.
/**
 * This structure basically carries an additional `unsigned int` to
 * communicate back the individual amount of sent bytes.
 **/
class SendMultiMessageHeader :
		public SendMessageHeader {

	// allow to set bytes set
	friend class SendMessageHeaderVector;

	// allow to fill sub-items
	template <typename HDR_ITEM>
	friend class MessageHeaderVectorBase;

public: // functions

	/// Assign the given `hdr` to the SendMessageHeader part of the object.
	explicit SendMultiMessageHeader(const SystemCall *call,
			const struct msghdr &hdr);

	/// Number of bytes sent out.
	/**
	 * Upon system call exit of sendmmsg() this contains the number of
	 * bytes actually sent out. In other states or when tracing errors
	 * occurred then std::nullopt is returned.
	 **/
	std::optional<unsigned long> bytesSent() const {
		return m_bytes_sent;
	}

protected: // functions

	using SendMessageHeader::fillSubItems;

	void setBytesSent(const unsigned int sent) {
		m_bytes_sent = sent;
	}

protected: // data

	std::optional<unsigned int> m_bytes_sent;
};

/// Base class for vectors of `struct mmsghdr` in `recvmmsg()` and `sendmmsg()`.
/**
 * The `struct mmsghdr` is the same for both `recvmmsg()` and `sendmmsg()`,
 * but we need somewhat different logic due to the different update logic in
 * the calls. This base class covers the shared logic, while the
 * specializations take care of the send/recv-specific logic.
 *
 * `HDR_ITEM` is either RecvMultiMessageHeader or SendMultiMessageHeader.
 *
 * This type holds two vectors: one for the raw `struct mmsghdr` and one
 * containing the corresponding `HDR_ITEM` instances. This is because we want
 * to reuse the logic from RecvMessageHeader and SendMessageHeaderVector for
 * the nearly identical `struct mmsghdr`. This is not ideal for performance,
 * but these system calls are rather rare and a lot of redundant code for this
 * would be bad.
 **/
template <typename HDR_ITEM>
class MessageHeaderVectorBase :
		public PointerValue {
public: // functions

	/// Create a new MessageHeaderVector based on `num_msgs`.
	/**
	 * `num_msgs` must refer to the accompanying system call argument
	 * which defines the number of `struct mmsghdr` found in the array
	 * this parameter points to.
	 **/
	explicit MessageHeaderVectorBase(const SystemCallItem &num_msgs) :
			PointerValue{ItemCfg{ItemType::PARAM_IN_OUT,
				"msgvec", "struct mmsghdr[]"}},
			m_num_msgs{num_msgs} {
		/* the `num_msgs` argument generally comes after the `msgvec` */
		m_flags.set(Flag::DEFER_FILL);
	}

	std::string str() const override;

protected: // functions

	/// Fetch the raw `struct mmsghdr` from the tracee and store them in `m_raw_headers`.
	/**
	 * This can only be called when a valid value is stored in
	 * `m_num_msgs`.
	 *
	 * The return value indicates whether reading the data from the Tracee
	 * succeeded, otherwise `m_raw_headers` will be empty.
	 **/
	bool fetchRawHeaders(const Tracee &);

	void processValue(const Tracee &) override;

	/// Returns a string description of the `msg_len` parameter.
	/**
	 * This needs to be implemented by the specialization of this type,
	 * because RecvMultiMessageHeader and SendMultiMessageHeader use
	 * different types for storing this information.
	 **/
	virtual std::string getMsgLenStr(const HDR_ITEM &item) const = 0;

protected: // data

	const SystemCallItem &m_num_msgs;
	std::vector<struct mmsghdr> m_raw_headers;
	std::vector<HDR_ITEM> m_headers;
};

class RecvMessageHeaderVector :
		public MessageHeaderVectorBase<RecvMultiMessageHeader> {
public: // functions

	explicit RecvMessageHeaderVector(const SystemCallItem &num_msgs) :
			MessageHeaderVectorBase{num_msgs} {
	}

	const std::vector<RecvMultiMessageHeader>& headers() const {
		return m_headers;
	}

protected: // functions

	void updateData(const Tracee &) override;

	std::string getMsgLenStr(const RecvMultiMessageHeader &item) const override;
};

class SendMessageHeaderVector :
		public MessageHeaderVectorBase<SendMultiMessageHeader> {
public: // functions

	explicit SendMessageHeaderVector(const SystemCallItem &num_msgs) :
			MessageHeaderVectorBase{num_msgs} {
	}

	const std::vector<SendMultiMessageHeader>& headers() const {
		return m_headers;
	}

protected: // functions

	void updateData(const Tracee &) override;

	std::string getMsgLenStr(const SendMultiMessageHeader &item) const override;
};

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

	void processValue(const Tracee &) override;

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

	explicit SockOptName(const SockOptLevel &level_arg) :
			ValueInParameter{
				ItemCfg{.label = "optname",
				.desc = "socket option name selection"}},
			m_level_arg{level_arg},
			m_opt_variant{std::monostate{}}	{
	}

	OptVariant option() const {
		return m_opt_variant;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override;

protected: // data

	const SockOptLevel &m_level_arg;

	OptVariant m_opt_variant;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
