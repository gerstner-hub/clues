// cosmos
#include <cosmos/utils.hxx>

// clues
#include <clues/items/net.hxx>
#include <clues/macros.h>
#include <clues/private/utils.hxx>
#include <clues/syscalls/net.hxx>

namespace clues::item {

std::string SocketDomain::str() const {
	switch (cosmos::to_integral(m_domain)) {
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

	const auto &socket_call = dynamic_cast<const SocketSystemCall&>(*m_call);

	using Domain = SocketDomain::Domain;

	switch (socket_call.domain.domain()) {
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

} // end ns
