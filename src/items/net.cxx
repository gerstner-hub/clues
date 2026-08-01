// C++
#include <algorithm>

// cosmos
#include <cosmos/utils.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/net.hxx>
#include <clues/macros.h>
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
		ret += std::format("sockfd={}, sockaddr={}, addrlen={}",
			call.sockfd.str(),
			call.addr.str(),
			call.addrlen.str()
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

void SocketAddress::processValue(const Tracee &proc) {

	m_addr.emplace();

	/* if the caller passed an excess size here let's try with what we
	 * have */
	const auto addr_len = std::min(
			m_len.value() >= 0 ?
				static_cast<size_t>(m_len.value()) :
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
				   m_len.value() >= 0 ?
					   static_cast<size_t>(m_len.value()) :
					   0};
	}
}

} // end ns
