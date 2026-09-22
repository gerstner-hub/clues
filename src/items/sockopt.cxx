// C++
#include <algorithm>

// clues
#include <clues/items/sockopt.hxx>
#include <clues/macros.h>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

void SockOptLevel::processValue(const Tracee &) {
	m_level = Level{valueAs<int>()};
}

std::string SockOptLevel::str() const {
	switch (cosmos::to_integral(m_level)) {
		CASE_ENUM_TO_STR(SOL_IPV6);
		CASE_ENUM_TO_STR(SOL_IP);
		CASE_ENUM_TO_STR(SOL_NETLINK);
		CASE_ENUM_TO_STR(SOL_PACKET);
		CASE_ENUM_TO_STR(SOL_RAW);
		CASE_ENUM_TO_STR(SOL_SOCKET);
		CASE_ENUM_TO_STR(IPPROTO_UDP);
		CASE_ENUM_TO_STR(IPPROTO_TCP);
		default: return "SOL_???";
	}
}

namespace {

std::string opt_name_str(const SockOptName::IP6Option opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "IPV6_???";
	}
}

std::string opt_name_str(const SockOptName::IPOption opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "IP_???";
	}
}

std::string opt_name_str(const SockOptName::NetlinkOption opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "NL_???";
	}
}

std::string opt_name_str(const SockOptName::PacketOption opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "PACKET_???";
	}
}

std::string opt_name_str(const SockOptName::SocketOption opt,
		const SockOptType opt_type) {
	switch (cosmos::to_integral(opt)) {
		case SO_ATTACH_FILTER: {
			return opt_type == SockOptType::GET ?
				"SO_GET_FILTER" :
				"SO_ATTACH_FILTER";
		}
		CASE_ENUM_TO_STR(SO_ACCEPTCONN);
		CASE_ENUM_TO_STR(SO_ATTACH_BPF);
		CASE_ENUM_TO_STR(SO_ATTACH_REUSEPORT_CBPF);
		CASE_ENUM_TO_STR(SO_ATTACH_REUSEPORT_EBPF);
		CASE_ENUM_TO_STR(SO_BINDTODEVICE);
		CASE_ENUM_TO_STR(SO_BROADCAST);
		CASE_ENUM_TO_STR(SO_BSDCOMPAT);
		CASE_ENUM_TO_STR(SO_DEBUG);
		CASE_ENUM_TO_STR(SO_DETACH_BPF);
		CASE_ENUM_TO_STR(SO_DOMAIN);
		CASE_ENUM_TO_STR(SO_ERROR);
		CASE_ENUM_TO_STR(SO_DONTROUTE);
		CASE_ENUM_TO_STR(SO_INCOMING_CPU);
		CASE_ENUM_TO_STR(SO_INCOMING_NAPI_ID);
		CASE_ENUM_TO_STR(SO_KEEPALIVE);
		CASE_ENUM_TO_STR(SO_LINGER);
		CASE_ENUM_TO_STR(SO_LOCK_FILTER);
		CASE_ENUM_TO_STR(SO_MARK);
		CASE_ENUM_TO_STR(SO_OOBINLINE);
		CASE_ENUM_TO_STR(SO_PASSCRED);
		CASE_ENUM_TO_STR(SO_PASSSEC);
		CASE_ENUM_TO_STR(SO_PEEK_OFF);
		CASE_ENUM_TO_STR(SO_PEERCRED);
		CASE_ENUM_TO_STR(SO_PEERSEC);
		CASE_ENUM_TO_STR(SO_PRIORITY);
		CASE_ENUM_TO_STR(SO_PROTOCOL);
		CASE_ENUM_TO_STR(SO_RCVBUF);
		CASE_ENUM_TO_STR(SO_RCVBUFFORCE);
		CASE_ENUM_TO_STR(SO_RCVLOWAT);
		CASE_ENUM_TO_STR(SO_SNDLOWAT);
		CASE_ENUM_TO_STR(SO_RCVTIMEO);
		CASE_ENUM_TO_STR(SO_SNDTIMEO);
		CASE_ENUM_TO_STR(SO_REUSEADDR);
		CASE_ENUM_TO_STR(SO_REUSEPORT);
		CASE_ENUM_TO_STR(SO_RXQ_OVFL);
		CASE_ENUM_TO_STR(SO_SELECT_ERR_QUEUE);
		CASE_ENUM_TO_STR(SO_SNDBUF);
		CASE_ENUM_TO_STR(SO_SNDBUFFORCE);
		CASE_ENUM_TO_STR(SO_TIMESTAMP);
		CASE_ENUM_TO_STR(SO_TIMESTAMPNS);
		CASE_ENUM_TO_STR(SO_TYPE);
		CASE_ENUM_TO_STR(SO_BUSY_POLL);
		default: return "SO_???";
	}
}

std::string opt_name_str(const SockOptName::TCPOption opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "TCP_???";
	}
}

std::string opt_name_str(const SockOptName::UDPOption opt, const SockOptType) {
	switch (cosmos::to_integral(opt)) {
		default: return "UDP_???";
	}
}

std::string opt_name_str(const std::monostate, const SockOptType) {
	return "<none>";
}

} // end anon ns

std::string SockOptName::str() const {
	return std::visit([this](const auto opt) { return opt_name_str(opt, m_opt_type); }, m_opt_variant);
}

void SockOptName::processValue(const Tracee &) {
	const auto val = valueAs<int>();
	using enum SockOptLevel::Level;

	switch (m_level_arg.level()) {
		case SOCKET: m_opt_variant = SocketOption{val}; break;
		default: m_opt_variant = std::monostate{}; break;
	}
}

void AttachFilterSockOpt::processValue(const Tracee &proc) {
	m_prog.reset();
	m_filters.clear();

	if (m_optlen.value() < int(sizeof(struct sock_fprog))) {
		return;
	}

	return FilterProg::processValue(proc);
}

void GetFilterSocktOpt::processValue(const Tracee &) {
	m_filters.clear();

	/*
	 * synthesize the `struct sock_fprog`.
	 */
	m_prog.emplace();
	/*
	 * this contains the amount of `struct sock_filter` available for
	 * output. we'll update it on system call return with the actually
	 * present data.
	 */
	m_prog->len = *m_optlen.value();
	m_prog->filter = valueAs<struct sock_filter*>();
}

void GetFilterSocktOpt::updateData(const Tracee &proc) {
	if (!m_call->hasResultValue()) {
		m_prog->len = 0;
	} else if (const auto len = m_optlen.value();
			!len || *len <= 0 || *len > UINT16_MAX) {
		m_prog->len = 0;
	} else {
		/* only consider the data that is actually there */
		m_prog->len = std::min(
				m_prog->len,
				static_cast<unsigned short>(*len));

		/* now fetch the `struct filter_prog` into the synthesized
		 * `struct sock_fprog` */
		fetchFilters(proc);
	}
}

} // end ns
