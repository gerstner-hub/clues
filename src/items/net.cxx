// C++
#include <algorithm>

// cosmos
#include <cosmos/net/unix/aux.hxx>
#include <cosmos/net/inet/aux.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/net.hxx>
#include <clues/logger.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/msghdr.hxx>
#include <clues/private/utils.hxx>
#include <clues/syscalls/net.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string SocketDomain::str() const {
	return std::string{label(m_domain)};
}

std::string_view SocketDomain::label(const Domain domain) {
	switch (cosmos::to_integral(domain)) {
		CASE_ENUM_TO_STR(AF_ALG);
		CASE_ENUM_TO_STR(AF_APPLETALK);
		CASE_ENUM_TO_STR(AF_AX25);
		CASE_ENUM_TO_STR(AF_BLUETOOTH);
		CASE_ENUM_TO_STR(AF_CAN);
		CASE_ENUM_TO_STR(AF_DECnet);
		CASE_ENUM_TO_STR(AF_IB);
		CASE_ENUM_TO_STR(AF_INET6);
		CASE_ENUM_TO_STR(AF_INET);
		CASE_ENUM_TO_STR(AF_IPX);
		CASE_ENUM_TO_STR(AF_KCM);
		CASE_ENUM_TO_STR(AF_KEY);
		CASE_ENUM_TO_STR(AF_LLC);
		CASE_ENUM_TO_STR(AF_MPLS);
		CASE_ENUM_TO_STR(AF_NETLINK);
		CASE_ENUM_TO_STR(AF_PACKET);
		CASE_ENUM_TO_STR(AF_PPPOX);
		CASE_ENUM_TO_STR(AF_RDS);
		CASE_ENUM_TO_STR(AF_TIPC);
		CASE_ENUM_TO_STR(AF_UNIX); // synonym to AF_LOCAL
		CASE_ENUM_TO_STR(AF_VSOCK);
		CASE_ENUM_TO_STR(AF_X25);
		CASE_ENUM_TO_STR(AF_XDP);
		default: return "AF_???";
	}
}

void SocketType::processValue(const Tracee &) {
	/* this is only found in the kernel's linux/net.h */
	constexpr int SOCK_TYPE_MASK  = 0xf;

	const auto raw = valueAs<int>();
	m_type = Type{raw & SOCK_TYPE_MASK};
	m_flags = Flags{raw & ~SOCK_TYPE_MASK};
}

static std::string_view type_label(const SocketType::Type type) {
	switch (cosmos::to_integral(type)) {
		default: return "SOCK_???";
		CASE_ENUM_TO_STR(SOCK_DGRAM);
		CASE_ENUM_TO_STR(SOCK_PACKET);
		CASE_ENUM_TO_STR(SOCK_RAW);
		CASE_ENUM_TO_STR(SOCK_RDM);
		CASE_ENUM_TO_STR(SOCK_SEQPACKET);
		CASE_ENUM_TO_STR(SOCK_STREAM);
		CASE_ENUM_TO_STR(SOCK_DCCP);
	}
}

std::string SocketType::str() const {
	BITFLAGS_FORMAT_START_COMBINED(m_flags, valueAs<int>());
	BITFLAGS_STREAM() << type_label(m_type);

	BITFLAGS_STREAM() << '|';
	BITFLAGS_ADD(SOCK_NONBLOCK);
	BITFLAGS_ADD(SOCK_CLOEXEC);

	return BITFLAGS_STR();
}

void SocketProtocol::processValue(const Tracee&) {
	m_raw = valueAs<int>();
	m_prot = std::monostate{};

	using Domain = SocketDomain::Domain;

	switch (m_domain.domain()) {
		case Domain::INET: [[ fallthrough ]];
		case Domain::INET6:
			if (m_raw != 0) {
				m_prot = IPProtocol{m_raw};
			}
			break;
		case Domain::PACKET:
			if (m_raw != 0) {
				m_prot = EthProtocol{m_raw};
			}
			break;
		case Domain::NETLINK:
			m_prot = NetlinkProtocol{m_raw};
			break;
		default: break;
	}
}

std::string_view SocketProtocol::label(const NetlinkProtocol prot) const {
	switch (cosmos::to_integral(prot)) {
		CASE_ENUM_TO_STR(NETLINK_ROUTE);
		CASE_ENUM_TO_STR(NETLINK_UNUSED);
		CASE_ENUM_TO_STR(NETLINK_USERSOCK);
		CASE_ENUM_TO_STR(NETLINK_FIREWALL);
		CASE_ENUM_TO_STR(NETLINK_SOCK_DIAG);
		CASE_ENUM_TO_STR(NETLINK_NFLOG);
		CASE_ENUM_TO_STR(NETLINK_XFRM);
		CASE_ENUM_TO_STR(NETLINK_SELINUX);
		CASE_ENUM_TO_STR(NETLINK_ISCSI);
		CASE_ENUM_TO_STR(NETLINK_AUDIT);
		CASE_ENUM_TO_STR(NETLINK_FIB_LOOKUP);
		CASE_ENUM_TO_STR(NETLINK_CONNECTOR);
		CASE_ENUM_TO_STR(NETLINK_NETFILTER);
		CASE_ENUM_TO_STR(NETLINK_IP6_FW);
		CASE_ENUM_TO_STR(NETLINK_DNRTMSG);
		CASE_ENUM_TO_STR(NETLINK_KOBJECT_UEVENT);
		CASE_ENUM_TO_STR(NETLINK_GENERIC);
		CASE_ENUM_TO_STR(NETLINK_SCSITRANSPORT);
		CASE_ENUM_TO_STR(NETLINK_ECRYPTFS);
		CASE_ENUM_TO_STR(NETLINK_RDMA);
		CASE_ENUM_TO_STR(NETLINK_CRYPTO);
		CASE_ENUM_TO_STR(NETLINK_SMC);
		default: return "NETLINK_???";
	}
}

std::string_view SocketProtocol::label(const IPProtocol prot) const {
	switch (cosmos::to_integral(prot)) {
		CASE_ENUM_TO_STR(IPPROTO_IP);
		CASE_ENUM_TO_STR(IPPROTO_ICMP);
		CASE_ENUM_TO_STR(IPPROTO_IGMP);
		CASE_ENUM_TO_STR(IPPROTO_IPIP);
		CASE_ENUM_TO_STR(IPPROTO_TCP);
		CASE_ENUM_TO_STR(IPPROTO_EGP);
		CASE_ENUM_TO_STR(IPPROTO_PUP);
		CASE_ENUM_TO_STR(IPPROTO_UDP);
		CASE_ENUM_TO_STR(IPPROTO_IDP);
		CASE_ENUM_TO_STR(IPPROTO_TP);
		CASE_ENUM_TO_STR(IPPROTO_DCCP);
		CASE_ENUM_TO_STR(IPPROTO_IPV6);
		CASE_ENUM_TO_STR(IPPROTO_RSVP);
		CASE_ENUM_TO_STR(IPPROTO_GRE);
		CASE_ENUM_TO_STR(IPPROTO_ESP);
		CASE_ENUM_TO_STR(IPPROTO_AH);
		CASE_ENUM_TO_STR(IPPROTO_MTP);
		CASE_ENUM_TO_STR(IPPROTO_BEETPH);
		CASE_ENUM_TO_STR(IPPROTO_ENCAP);
		CASE_ENUM_TO_STR(IPPROTO_PIM);
		CASE_ENUM_TO_STR(IPPROTO_COMP);
		CASE_ENUM_TO_STR(IPPROTO_L2TP);
		CASE_ENUM_TO_STR(IPPROTO_SCTP);
		CASE_ENUM_TO_STR(IPPROTO_UDPLITE);
		CASE_ENUM_TO_STR(IPPROTO_MPLS);
		CASE_ENUM_TO_STR(IPPROTO_ETHERNET);
		CASE_ENUM_TO_STR(IPPROTO_RAW);
#ifdef IPPROTO_SMC
		CASE_ENUM_TO_STR(IPPROTO_SMC);
#endif
		CASE_ENUM_TO_STR(IPPROTO_MPTCP);
		default: return "IPPROTO_???";
	}
}

std::string_view SocketProtocol::label(const EthProtocol prot) const {
	switch (cosmos::to_integral(prot)) {
		CASE_ENUM_TO_STR(ETH_P_LOOP);
		CASE_ENUM_TO_STR(ETH_P_PUP);
		CASE_ENUM_TO_STR(ETH_P_PUPAT);
		CASE_ENUM_TO_STR(ETH_P_TSN);
		CASE_ENUM_TO_STR(ETH_P_ERSPAN2);
		CASE_ENUM_TO_STR(ETH_P_IP);
		CASE_ENUM_TO_STR(ETH_P_X25);
		CASE_ENUM_TO_STR(ETH_P_ARP);
		CASE_ENUM_TO_STR(ETH_P_BPQ);
		CASE_ENUM_TO_STR(ETH_P_IEEEPUP);
		CASE_ENUM_TO_STR(ETH_P_IEEEPUPAT);
		CASE_ENUM_TO_STR(ETH_P_BATMAN);
		CASE_ENUM_TO_STR(ETH_P_DEC);
		CASE_ENUM_TO_STR(ETH_P_DNA_DL);
		CASE_ENUM_TO_STR(ETH_P_DNA_RC);
		CASE_ENUM_TO_STR(ETH_P_DNA_RT);
		CASE_ENUM_TO_STR(ETH_P_LAT);
		CASE_ENUM_TO_STR(ETH_P_DIAG);
		CASE_ENUM_TO_STR(ETH_P_CUST);
		CASE_ENUM_TO_STR(ETH_P_SCA);
		CASE_ENUM_TO_STR(ETH_P_TEB);
		CASE_ENUM_TO_STR(ETH_P_RARP);
		CASE_ENUM_TO_STR(ETH_P_ATALK);
		CASE_ENUM_TO_STR(ETH_P_AARP);
		CASE_ENUM_TO_STR(ETH_P_8021Q);
		CASE_ENUM_TO_STR(ETH_P_ERSPAN);
		CASE_ENUM_TO_STR(ETH_P_IPX);
		CASE_ENUM_TO_STR(ETH_P_IPV6);
		CASE_ENUM_TO_STR(ETH_P_PAUSE);
		CASE_ENUM_TO_STR(ETH_P_SLOW);
		CASE_ENUM_TO_STR(ETH_P_WCCP);
		CASE_ENUM_TO_STR(ETH_P_MPLS_UC);
		CASE_ENUM_TO_STR(ETH_P_MPLS_MC);
		CASE_ENUM_TO_STR(ETH_P_ATMMPOA);
		CASE_ENUM_TO_STR(ETH_P_PPP_DISC);
		CASE_ENUM_TO_STR(ETH_P_PPP_SES);
		CASE_ENUM_TO_STR(ETH_P_LINK_CTL);
		CASE_ENUM_TO_STR(ETH_P_ATMFATE);
		CASE_ENUM_TO_STR(ETH_P_PAE);
#ifdef ETH_P_PROFINET
		CASE_ENUM_TO_STR(ETH_P_PROFINET);
#endif
#ifdef ETH_P_REALTEK
		CASE_ENUM_TO_STR(ETH_P_REALTEK);
#endif
		CASE_ENUM_TO_STR(ETH_P_AOE);
#ifdef ETH_P_ETHERCAT
		CASE_ENUM_TO_STR(ETH_P_ETHERCAT);
#endif
		CASE_ENUM_TO_STR(ETH_P_8021AD);
		CASE_ENUM_TO_STR(ETH_P_802_EX1);
		CASE_ENUM_TO_STR(ETH_P_PREAUTH);
		CASE_ENUM_TO_STR(ETH_P_TIPC);
		CASE_ENUM_TO_STR(ETH_P_LLDP);
		CASE_ENUM_TO_STR(ETH_P_MRP);
		CASE_ENUM_TO_STR(ETH_P_MACSEC);
		CASE_ENUM_TO_STR(ETH_P_8021AH);
		CASE_ENUM_TO_STR(ETH_P_MVRP);
		CASE_ENUM_TO_STR(ETH_P_1588);
		CASE_ENUM_TO_STR(ETH_P_NCSI);
		CASE_ENUM_TO_STR(ETH_P_PRP);
		CASE_ENUM_TO_STR(ETH_P_CFM);
		CASE_ENUM_TO_STR(ETH_P_FCOE);
		CASE_ENUM_TO_STR(ETH_P_IBOE);
		CASE_ENUM_TO_STR(ETH_P_TDLS);
		CASE_ENUM_TO_STR(ETH_P_FIP);
		CASE_ENUM_TO_STR(ETH_P_80221);
		CASE_ENUM_TO_STR(ETH_P_HSR);
		CASE_ENUM_TO_STR(ETH_P_NSH);
		CASE_ENUM_TO_STR(ETH_P_LOOPBACK);
		CASE_ENUM_TO_STR(ETH_P_QINQ1);
		CASE_ENUM_TO_STR(ETH_P_QINQ2);
		CASE_ENUM_TO_STR(ETH_P_QINQ3);
		CASE_ENUM_TO_STR(ETH_P_EDSA);
		CASE_ENUM_TO_STR(ETH_P_DSA_8021Q);
#ifdef ETH_PDSA_A5PSW
		CASE_ENUM_TO_STR(ETH_P_DSA_A5PSW);
#endif
		CASE_ENUM_TO_STR(ETH_P_IFE);
		CASE_ENUM_TO_STR(ETH_P_AF_IUCV);
		CASE_ENUM_TO_STR(ETH_P_ALL);
		default: return "ETH_P_???";
	}
}

std::string SocketProtocol::label(const std::monostate) const {
	return std::to_string(m_raw);
}

std::string SocketProtocol::str() const {
	return std::visit([this](const auto prot) -> std::string {
		const auto ret = label(prot);

		if constexpr (std::is_same_v<decltype(ret), const std::string_view>) {
			return std::string{ret};
		}
		if constexpr (std::is_same_v<decltype(ret), const std::string>) {
			return ret;
		}

		return "???";
	}, m_prot);
}

std::string SocketCallType::str() const {
	switch (cosmos::to_integral(m_call)) {
		CASE_ENUM_TO_STR(SYS_SOCKET);
		CASE_ENUM_TO_STR(SYS_BIND);
		CASE_ENUM_TO_STR(SYS_CONNECT);
		CASE_ENUM_TO_STR(SYS_LISTEN);
		CASE_ENUM_TO_STR(SYS_ACCEPT);
		CASE_ENUM_TO_STR(SYS_GETSOCKNAME);
		CASE_ENUM_TO_STR(SYS_GETPEERNAME);
		CASE_ENUM_TO_STR(SYS_SOCKETPAIR);
		CASE_ENUM_TO_STR(SYS_SEND);
		CASE_ENUM_TO_STR(SYS_RECV);
		CASE_ENUM_TO_STR(SYS_SENDTO);
		CASE_ENUM_TO_STR(SYS_RECVFROM);
		CASE_ENUM_TO_STR(SYS_SHUTDOWN);
		CASE_ENUM_TO_STR(SYS_SETSOCKOPT);
		CASE_ENUM_TO_STR(SYS_GETSOCKOPT);
		CASE_ENUM_TO_STR(SYS_SENDMSG);
		CASE_ENUM_TO_STR(SYS_RECVMSG);
		CASE_ENUM_TO_STR(SYS_ACCEPT4);
		CASE_ENUM_TO_STR(SYS_RECVMMSG);
		CASE_ENUM_TO_STR(SYS_SENDMMSG);
		default: return "SYS_???";
	}
}

constexpr size_t NUM_SOCKETCALLS = SYS_SENDMMSG + 1;
/* index 0 is unused / invalid */
static constexpr std::array<size_t, NUM_SOCKETCALLS> NUM_SOCKETCALL_ARGS{
	0, 3, 3, 3, 2, 3, 3, 3, 4, 4, 4, 6, 6, 2, 5, 5, 3, 3, 4, 5, 4
};

void SocketCallArgs::processValue(const Tracee &proc) {
	const auto callnum = cosmos::to_integral(m_type.call());
	const auto num_args = NUM_SOCKETCALL_ARGS[callnum];

	try {
		if (m_call->is32BitEmulationABI()) {
			/* the tracee uses smaller `unsigned long` than us */
			std::vector<uint32_t> args(num_args);
			proc.readStructs(asPtr(), args);

			for (const auto arg: args) {
				m_args.push_back(arg);
			}
		} else {
			m_args.resize(num_args);
			proc.readStructs(asPtr(), m_args);
		}
	} catch(...) {
		m_args.clear();
		throw;
	}
}

std::string SocketCallArgs::str() const {

	std::string ret{"{"};

	using enum SocketCallType::Call;

	auto handle_bind_connect = [&ret](const auto &call) {
		ret += std::format("sockfd={}, sockaddr={}, addrlen={}",
			call.sockfd.str(),
			call.addr.str(),
			call.addrlen.str()
		);
	};

	switch (m_type.call()) {
	case SOCKET: {
		const auto &call = dynamic_cast<const SocketSystemCall&>(*m_call);
		ret += std::format("domain={}, type={}, prot={}",
			call.domain.str(),
			call.type.str(),
			call.prot.str()
		);
		break;
	} case SOCKETPAIR: {
		const auto &call = dynamic_cast<const SocketPairSystemCall&>(*m_call);
		ret += std::format("domain={}, type={}, prot={}, sv={}",
			call.domain.str(),
			call.type.str(),
			call.prot.str(),
			call.pair.str()
		);
		break;
	} case BIND: {
		const auto &call = dynamic_cast<const BindSystemCall&>(*m_call);
		handle_bind_connect(call);
		break;
	} case CONNECT: {
		const auto &call = dynamic_cast<const ConnectSystemCall&>(*m_call);
		handle_bind_connect(call);
		break;
	} case LISTEN: {
		const auto &call = dynamic_cast<const ListenSystemCall&>(*m_call);

		ret += std::format("sockfd={}, backlog={}",
			call.sockfd.str(),
			call.backlog.str()
		);

		break;
	} case ACCEPT: [[ fallthrough ]];
	  case ACCEPT4: {
		const auto &call = dynamic_cast<const AcceptSystemCall&>(*m_call);

		ret += std::format("sockfd={}, addr={}, addrlen={}",
			call.sockfd.str(),
			call.addr.str(),
			call.addrlen.str()
		);

		if (m_type.call() == ACCEPT4) {
			ret += std::format(", flags={}", call.flags.str());
		}

		break;
	} case SHUTDOWN: {
		const auto &call = dynamic_cast<const ShutdownSystemCall&>(*m_call);

		ret += std::format("sockfd={}, how={}",
			call.sockfd.str(),
			call.how.str()
		);

		break;
	} case GETPEERNAME: [[ fallthrough ]];
	  case GETSOCKNAME: {
		auto format = [&ret](const auto &call) {
			ret += std::format("sockfd={}, addr={}, addrlen={}",
				call.sockfd.str(),
				call.addr.str(),
				call.addrlen.str()
			);
		};

		if (m_type.call() == GETPEERNAME) {
			format(dynamic_cast<const GetPeerNameSystemCall&>(*m_call));
		} else {
			format(dynamic_cast<const GetSockNameSystemCall&>(*m_call));
		}

		break;
	} case RECV: [[ fallthrough ]];
	  case RECVFROM: {
		const auto &call = dynamic_cast<const RecvSystemCall&>(*m_call);

		ret += std::format("sockfd={}, buf={}, count={}, flags={}",
			call.sockfd.str(), call.buf.str(), call.count.str(), call.flags.str()
		);

		if (m_type.call() == RECVFROM) {
			const auto &fromcall = dynamic_cast<const RecvFromSystemCall&>(*m_call);

			ret += std::format(", addr={}, addrlen={}",
				fromcall.addr.str(), fromcall.addrlen.str()
			);
		}

		break;
	} case SEND: [[ fallthrough ]];
	  case SENDTO: {
		const auto &call = dynamic_cast<const SendSystemCall&>(*m_call);

		ret += std::format("sockfd={}, buf={}, count={}, flags={}",
			call.sockfd.str(), call.buf.str(), call.count.str(), call.flags.str()
		);

		if (m_type.call() == SENDTO) {
			const auto &tocall = dynamic_cast<const SendToSystemCall&>(*m_call);

			ret += std::format(", addr={}, addrlen={}",
				tocall.addr.str(), tocall.addrlen.str()
			);
		}

		break;
	} case RECVMSG: {
		const auto &call = dynamic_cast<const RecvMsgSystemCall&>(*m_call);

		ret += std::format("sockfd={}, msg={}, flags={}",
			call.sockfd.str(), call.msg.str(), call.flags.str()
		);
		break;
	} default: return "???";
	} // end switch

	return ret + "}";
}

void SocketPair::processValue(const Tracee &) {
	m_valid = false;
	m_pair.fill(cosmos::FileNum::INVALID);
}

void SocketPair::updateData(const Tracee &proc) {
	if (!m_call->hasResultValue())
		return;
	std::vector<int> fds;
	proc.readVector(asPtr(), fds, 2);

	for (size_t i = 0; i < fds.size(); i++) {
		m_pair[i] = cosmos::FileNum{fds[i]};
	}

	m_valid = true;
}

std::string SocketPair::str() const {
	if (!m_call->hasResultValue()) {
		return format::pointer(ptr());
	} else if (!m_valid) {
		return formatBadPointer();
	}

	return std::format("[{}, {}]",
		cosmos::to_integral(m_pair[0]),
		cosmos::to_integral(m_pair[1]));
}

namespace {

void format_addr(std::string &out, const cosmos::IP4Address &addr) {
	out += std::format(", port={}, addr=\"{}\"",
		addr.port().toHost(),
		addr.ipAsString()
	);
};

void format_addr(std::string &out, const cosmos::IP6Address &addr) {
	out += std::format(", port={}, flowinfo={}, addr=\"{}\", scope_id={}",
		addr.port().toHost(),
		addr.getFlowInfo(),
		addr.ipAsString(),
		cosmos::to_integral(addr.getScopeID())
	);
};

void format_addr(std::string &out, const cosmos::UnixAddress &addr) {
	out += std::format(", path=\"{}\"",
		addr.label()
	);
};

} // end anon ns

std::string SocketAddress::str() const {
	if (!m_addr) {
		return formatBadPointer();
	}

	std::string ret{"{"};

	ret += std::format("family={}",
		SocketDomain::label(SocketDomain::Domain{m_addr->ss_family})
	);

	if (const auto addr_var = addr(); addr_var) {
		const auto addr = *addr_var;

		std::visit([&ret](const auto &_addr) {
				format_addr(ret, _addr);
			}, addr);
	} else {
		ret += ", ???";
	}


	return ret + "}";
}

SocketAddress::SocketAddress(
		const ItemCfg &cfg,
		std::variant<const IntValue*,
			const PointerToScalar<int>*> len) :
		PointerValue(cfg.applyDefaults(ItemCfg{
			.label = "addr",
			.desc = "struct sockaddr*"})) {

	if (std::holds_alternative<const IntValue*>(len)) {
		m_len = std::get<const IntValue*>(len);
	} else {
		m_lenp = std::get<const PointerToScalar<int>*>(len);
	}

	/* `len` generally comes after the `addr` */
	m_flags.set(Flag::DEFER_FILL);
}

int SocketAddress::addrLen() const {
	if (m_len)
		return m_len->value();
	else
		return *m_lenp->value();
}

void SocketAddress::processValue(const Tracee &proc) {

	if ((this->isOut() && proc.isEnterStop()) ||
			isZero() ||
			(proc.isExitStop() && !m_call->hasResultValue())) {
		m_addr.reset();
		return;
	}

	m_addr.emplace();

	/* if the caller passed an excess size here let's try with what we
	 * have */
	const auto addr_len = std::min(
			addrLen() >= 0 ?
				static_cast<size_t>(addrLen()) :
				0,
			sizeof(*m_addr));

	if (!addr_len) {
		m_addr.reset();
		return;
	}

	try {
		proc.readBlob(ptr(),
				reinterpret_cast<char*>(&(*m_addr)),
				addr_len);
	} catch (const std::exception &) {
		m_addr.reset();
	}
}

std::optional<SocketAddress::AddressVariant> SocketAddress::addr() const {
	if (!valid())
		return {};

	using enum SocketDomain::Domain;

	switch (domain()) {
		default: return {};
		case INET: return cosmos::IP4Address{reinterpret_cast<const sockaddr_in&>(*m_addr)};
		case INET6: return cosmos::IP6Address{reinterpret_cast<const sockaddr_in6&>(*m_addr)};
		case UNIX: return cosmos::UnixAddress{
				   reinterpret_cast<const sockaddr_un&>(*m_addr),
				   addrLen() >= 0 ?
					   static_cast<size_t>(addrLen()) :
					   0};
	}
}

std::string AcceptFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(SOCK_NONBLOCK);
	BITFLAGS_ADD(SOCK_CLOEXEC);

	return BITFLAGS_STR();
}

void AddressLengthPointer::processValue(const Tracee &proc) {
	m_available.reset();
	m_filled.reset();

	PointerToScalar<int>::processValue(proc);

	m_available = value();
}

void AddressLengthPointer::updateData(const Tracee &proc) {
	PointerToScalar<int>::updateData(proc);

	if (m_call->hasResultValue()) {
		m_filled = value();
	}
}

std::string AddressLengthPointer::str() const {
	if (!m_available)
		return formatBadPointer();

	std::string ret = std::to_string(*m_available);

	if (m_filled) {
		ret += std::format(" → {}", *m_filled);
	}

	return ret;
}

std::string ShutdownType::str() const {
	switch (cosmos::to_integral(m_dir)) {
		CASE_ENUM_TO_STR(SHUT_RD);
		CASE_ENUM_TO_STR(SHUT_WR);
		CASE_ENUM_TO_STR(SHUT_RDWR);
		default: return "SHUT_???";
	}
}

std::string SendRecvFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(MSG_CONFIRM);
	BITFLAGS_ADD(MSG_DONTROUTE);
	BITFLAGS_ADD(MSG_DONTWAIT);
	BITFLAGS_ADD(MSG_EOR);
	BITFLAGS_ADD(MSG_MORE);
	BITFLAGS_ADD(MSG_NOSIGNAL);
	BITFLAGS_ADD(MSG_OOB);
	BITFLAGS_ADD(MSG_FASTOPEN);
	BITFLAGS_ADD(MSG_CMSG_CLOEXEC);
	BITFLAGS_ADD(MSG_ERRQUEUE);
	BITFLAGS_ADD(MSG_PEEK);
	BITFLAGS_ADD(MSG_TRUNC);
	BITFLAGS_ADD(MSG_CTRUNC);
	BITFLAGS_ADD(MSG_WAITALL);
	BITFLAGS_ADD(MSG_WAITFORONE);
	BITFLAGS_ADD(MSG_ZEROCOPY);

	return BITFLAGS_STR();
}

std::string RecvMessageHeader::str() const {
	if (!m_in_header) {
		return formatBadPointer();
	}

	std::string ret{"{"};

	ret += std::format("msg_name={}, msg_namelen={} → {}, msg_iov={}, msg_iovlen={}, msg_control={}, msg_controllen={} → {}, msg_flags={}",
		m_msg_name.str(),
		m_in_header->msg_namelen, m_msg_namelen.str(),
		m_msg_iov.str(), m_msg_iovlen.str(),
		controlStr(),
		m_in_header->msg_controllen, m_msg_controllen.str(),
		m_msg_flags.str()
	);

	ret += "}";
	return ret;
}

static std::string format_opt_level(const cosmos::OptLevel level) {
	switch (cosmos::to_integral(level)) {
	CASE_ENUM_TO_STR(SOL_SOCKET);
	CASE_ENUM_TO_STR(IPPROTO_IP);
	CASE_ENUM_TO_STR(IPPROTO_IPV6);
	CASE_ENUM_TO_STR(IPPROTO_TCP);
	CASE_ENUM_TO_STR(IPPROTO_UDP);
	default: return "LEVEL_???";
	}
}

using ReceiveMessageHeader = cosmos::ReceiveMessageHeader;
using ControlMessage = ReceiveMessageHeader::ControlMessage;

static std::string format_ctrl_type(const ControlMessage &msg) {
	if (const auto unix_msg = msg.asUnixMessage(); unix_msg) {
		switch (cosmos::to_integral(*unix_msg)) {
			CASE_ENUM_TO_STR(SCM_RIGHTS);
			CASE_ENUM_TO_STR(SCM_CREDENTIALS);
			default: return "SCM_???";
		}
	} else if (const auto ip4_msg = msg.asIP4Message(); ip4_msg) {
		switch (cosmos::to_integral(*ip4_msg)) {
			CASE_ENUM_TO_STR(IP_RECVERR);
			CASE_ENUM_TO_STR(IP_PKTINFO);
			CASE_ENUM_TO_STR(IP_ORIGDSTADDR);
			CASE_ENUM_TO_STR(IP_TOS);
			CASE_ENUM_TO_STR(IP_TTL);
			default: return "IP_???";
		}
	} else if (const auto ip6_msg = msg.asIP6Message(); ip6_msg) {
		switch (cosmos::to_integral(*ip6_msg)) {
			CASE_ENUM_TO_STR(IPV6_RECVERR);
			CASE_ENUM_TO_STR(IPV6_PKTINFO);
			default: return "IPV6_???";
		}
	} else {
		return std::to_string(msg.raw().cmsg_type);
	}
}

static std::string format_unix_rights(const ControlMessage &msg) {
	cosmos::UnixRightsMessage rights;
	rights.deserialize(msg);
	cosmos::UnixRightsMessage::FileNumVector vec;
	rights.takeFDs(vec);

	std::string ret{"["};
	bool first = true;

	for (const auto fd: vec) {
		if (first)
			first = false;
		else
			ret += ", ";
		ret += std::to_string(cosmos::to_integral(fd));
	}

	ret += "]";
	return ret;
}

std::string format_unix_creds(const ControlMessage &msg) {
	cosmos::UnixCredentialsMessage creds_msg;
	creds_msg.deserialize(msg);
	const auto &creds = creds_msg.creds();

	std::string ret{"{"};
	ret += std::format("pid={}, uid={}, gid={}",
		creds.processID(),
		creds.userID(),
		creds.groupID()
	);
	ret += "}";
	return ret;
}

template <cosmos::SocketFamily FAMILY>
std::string format_inet_recverr(const ControlMessage &msg) {
	cosmos::SocketErrorMessage<FAMILY> err_msg;
	err_msg.deserialize(msg);
	const auto &err = *err_msg.error();

	auto format_origin = [](auto origin) -> std::string {
		switch (cosmos::to_integral(origin)) {
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_NONE);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_LOCAL);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_ICMP);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_ICMP6);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_TXSTATUS);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_ZEROCOPY);
			CASE_ENUM_TO_STR(SO_EE_ORIGIN_TXTIME);
			default: return "SO_EE_ORIGIN_???";
		}
	};

	std::string ret{"{"};

	// TODO: complete evaluation of the remaining ee_??? fields

	ret += std::format("ee_errno={} ({}), ee_origin={}",
		get_errno_label(err.errnum()),
		std::to_string(cosmos::to_integral(err.errnum())),
		format_origin(err.origin())
	);

	ret += "}";

	return ret;
}

static std::string format_ctrl_data(const ControlMessage &msg) {

	// TODO: implement remaining aux message types in libcosmos and here

	if (const auto unix_msg = msg.asUnixMessage(); unix_msg) {
		using enum cosmos::UnixMessage;
		switch (*unix_msg) {
			case RIGHTS: return format_unix_rights(msg);
			case CREDENTIALS: return format_unix_creds(msg);
			default: break;
		}
	} else if (const auto ip4_msg = msg.asIP4Message(); ip4_msg) {
		using enum cosmos::IP4Message;
		switch (*ip4_msg) {
			case RECVERR: return format_inet_recverr<
				cosmos::SocketFamily::INET>(msg);
			case PKTINFO: break;
			case ORIGDSTADDR: break;
			case TOS: break;
			case TTL: break;
		}
	} else if (const auto ip6_msg = msg.asIP6Message(); ip6_msg) {
		using enum cosmos::IP6Message;
		switch (*ip6_msg) {
			case RECVERR: return format_inet_recverr<
				cosmos::SocketFamily::INET6>(msg);
			case PKTINFO: break;
		}
	}

	/* fallback for any unhandled message levels / types */
	return clues::format::buffer(
		reinterpret_cast<const std::byte*>(msg.data()),
		msg.dataLength(), clues::format::Flag::BINARY);
}

std::string RecvMessageHeader::controlStr() const {
	const auto header_opt = header();

	if (!m_msg_control.availableBytes() || !header_opt) {
		return m_msg_control.str();
	}

	const auto &header = *header_opt;

	std::string ret{"["};

	for (const auto &ctrl: header) {
		ret += "{";
		ret += std::format("cmsg_len={}, cmsg_level={}, cmsg_type={}, cmsg_data={}",
			ctrl.dataLength(),
			format_opt_level(ctrl.level()),
			format_ctrl_type(ctrl),
			format_ctrl_data(ctrl)
		);
		ret += "}";
	}

	ret += "]";
	return ret;
}

namespace {

class Header :
	public cosmos::ReceiveMessageHeader {
public: // functions

	Header() = default;

	Header(const struct msghdr &hdr,
			const std::vector<std::byte> &control = {}) {
		copyHeader(hdr);
		copyControl(control);
		m_header.msg_iov = nullptr;
	}

	void copyHeader(const struct msghdr &hdr) {
		std::memcpy(rawHeader(), &hdr, sizeof(hdr));
	}

	void copyControl(const std::vector<std::byte> &data) {
		m_control_buffer.resize(data.size());
		std::memcpy(m_control_buffer.data(), data.data(), data.size());
		m_header.msg_control =
			reinterpret_cast<void*>(m_control_buffer.data());
	}
};

} // end anon ns

/*
 * in 32-bit emulation context fetch the 32-bit msghdr struct and copy its
 * fields into `out`.
 */
bool RecvMessageHeader::fetchMsgHdr32(const Tracee &proc, std::optional<struct msghdr> &out) {
	msghdr32 hdr32;
	if (!proc.readStruct(asPtr(), hdr32)) {
		out.reset();
		return false;
	}

	out.emplace();

	out->msg_name = convert_compat_ptr(hdr32.msg_name);
	out->msg_namelen = hdr32.msg_namelen;
	out->msg_iov = convert_compat_ptr<iovec*>(hdr32.msg_iov);
	out->msg_iovlen = hdr32.msg_iovlen;
	out->msg_control = convert_compat_ptr(hdr32.msg_control);
	out->msg_controllen = hdr32.msg_controllen;
	out->msg_flags = hdr32.msg_flags;

	return true;
}


std::optional<ReceiveMessageHeader> RecvMessageHeader::header() const {
	if (!m_out_header) {
		return {};
	}

	return Header{*m_out_header, convertControlHeader32()};
}

void RecvMessageHeader::processValue(const Tracee &proc) {
	m_out_header.reset();

	if (m_call->is32BitEmulationABI()) {
		fetchMsgHdr32(proc, m_in_header);
	} else {
		proc.readStructIntoOptional(asPtr(), m_in_header);
	}

	if (!m_in_header) {
		resetSubItems(proc);
		return;
	}

	processSubItemValue(m_msg_namelen,
			scalar_to_word(m_in_header->msg_namelen), proc);
	processSubItemValue(m_msg_name,
			ptr_to_word(m_in_header->msg_name), proc);
	processSubItemValue(m_msg_iovlen,
			scalar_to_word(m_in_header->msg_iovlen), proc);
	processSubItemValue(m_msg_iov,
			ptr_to_word(m_in_header->msg_iov), proc);
	processSubItemValue(m_msg_controllen,
			scalar_to_word(m_in_header->msg_controllen), proc);
	processSubItemValue(m_msg_control,
			ptr_to_word(m_in_header->msg_control), proc);
}

void RecvMessageHeader::updateData(const Tracee &proc) {
	if (m_call->is32BitEmulationABI()) {
		fetchMsgHdr32(proc, m_out_header);
	} else {
		proc.readStructIntoOptional(asPtr(), m_out_header);
	}

	if (!m_out_header)
		return;

	/*
	 * since some of these sub-items don't expect updates we need to call
	 * `processValue()` on them here as well to actually update the data
	 */
	processSubItemValue(m_msg_namelen,
			scalar_to_word(m_out_header->msg_namelen), proc);
	updateSubItemData(m_msg_name, proc);
	updateSubItemData(m_msg_iovlen, proc);
	updateSubItemData(m_msg_iov, proc);
	processSubItemValue(m_msg_flags,
			scalar_to_word(m_out_header->msg_flags), proc);
	processSubItemValue(m_msg_controllen,
			scalar_to_word(m_out_header->msg_controllen), proc);
	updateSubItemData(m_msg_control, proc);
	/*
	 *  make sure we always have all control data since we need to inspect
	 *  e.g. passed file descriptors data; we will need it in `header()`.
	 */
	m_msg_control.fetchRemainingData(proc);
}

void RecvMessageHeader::resetSubItems(const Tracee &proc) {
	processSubItemValue(m_msg_namelen, Word::ZERO, proc);
	processSubItemValue(m_msg_name, Word::ZERO, proc);
	processSubItemValue(m_msg_iovlen, Word::ZERO, proc);
	processSubItemValue(m_msg_iov, Word::ZERO, proc);
	processSubItemValue(m_msg_controllen, Word::ZERO, proc);
	processSubItemValue(m_msg_control, Word::ZERO, proc);
}

std::vector<std::byte> RecvMessageHeader::convertControlHeader32() const {
	if (!m_call->is32BitEmulationABI() || m_msg_controllen.value() == 0)
		return m_msg_control.data();
	/*
	 * unfortunately the struct cmsghdr also differs in size between
	 * 32-bit and 64-bit. this means we need to rearrange the binary data
	 * structure to match what our 64 bit tracer process expects.
	 *
	 * TODO: this might also affect the payload, which is not currently
	 * considered. The UNIX domain socket control messages don't differ in
	 * payload between 32-bit and 64-bit, but others might?
	 */
	const auto &control32 = m_msg_control.data();
	size_t convert_pos = 0;
	std::vector<std::byte> ret;
	/*
	 * make sure no reallocations will occur while we are increasing the
	 * size of the return vector, otherwise pointers might be invalidated
	 * when resizing it.
	 */
	ret.reserve(control32.size() * 2);

	auto add_bytes = [&ret](const size_t count) -> std::byte* {
		const auto oldsize = ret.size();
		ret.resize(ret.size() + count);
		return ret.data() + oldsize;
	};

	auto add_cmsghdr = [add_bytes]() -> struct cmsghdr* {
		const auto ptr = add_bytes(sizeof(struct cmsghdr));
		return reinterpret_cast<cmsghdr*>(ptr);
	};

	auto get_cmsghdr32 = [&control32, &convert_pos]() {
		auto ptr = reinterpret_cast<const cmsghdr32*>(control32.data() + convert_pos);
		convert_pos += sizeof(cmsghdr32);
		return ptr;
	};

	while (convert_pos < control32.size()) {
		if (control32.size() - convert_pos < sizeof(cmsghdr32)) {
			/* trailing data ? */
			LOG_WARN("unexpected trailing data in control message");
			break;
		}
		auto msg32 = get_cmsghdr32();
		auto msg = add_cmsghdr();

		msg->cmsg_level = msg32->cmsg_level;
		msg->cmsg_type = msg32->cmsg_type;

		const auto payload_bytes = msg32->cmsg_len - sizeof(cmsghdr32);
		const auto payload_dst = add_bytes(payload_bytes);
		std::memcpy(payload_dst, control32.data() + convert_pos, payload_bytes);
		convert_pos += payload_bytes;

		/* alignment for 32-bit is already considered in the length
		 * field of msg32, but we might need to increase the length
		 * for the 64-bit message, so recalculate it */
		const auto aligned_len = CMSG_LEN(payload_bytes);
		constexpr size_t HDR_DIFF_BYTES = sizeof(cmsghdr) - sizeof(cmsghdr32);
		/* subtract the extra bytes we have in the 64-bit struct cmsghdr */
		const auto extra_bytes = aligned_len - msg32->cmsg_len - HDR_DIFF_BYTES;
		msg->cmsg_len = aligned_len;
		if (extra_bytes > 0) {
			for (size_t extra = 0; extra < extra_bytes; extra++) {
				ret.push_back({});
			}
		}
	}

	return ret;
}

} // end ns
