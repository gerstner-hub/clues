// C++
#include <algorithm>

// clues
#include <clues/items/sockopt.hxx>
#include <clues/logger.hxx>
#include <clues/macros.h>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>
#include <clues/private/utils.hxx>

namespace clues::item {

void SockOptLevel::processData(const Tracee &) {
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
		CASE_ENUM_TO_STR(SO_BPF_EXTENSIONS);
		CASE_ENUM_TO_STR(SO_BINDTODEVICE);
		CASE_ENUM_TO_STR(SO_BINDTOIFINDEX);
		CASE_ENUM_TO_STR(SO_BROADCAST);
		CASE_ENUM_TO_STR(SO_BSDCOMPAT);
		CASE_ENUM_TO_STR(SO_DEBUG);
		CASE_ENUM_TO_STR(SO_DETACH_BPF);
		CASE_ENUM_TO_STR(SO_DETACH_REUSEPORT_BPF);
		CASE_ENUM_TO_STR(SO_DOMAIN);
		CASE_ENUM_TO_STR(SO_ERROR);
		CASE_ENUM_TO_STR(SO_DONTROUTE);
		CASE_ENUM_TO_STR(SO_INCOMING_CPU);
		CASE_ENUM_TO_STR(SO_INCOMING_NAPI_ID);
		CASE_ENUM_TO_STR(SO_INQ);
		CASE_ENUM_TO_STR(SO_KEEPALIVE);
		CASE_ENUM_TO_STR(SO_LINGER);
		CASE_ENUM_TO_STR(SO_LOCK_FILTER);
		CASE_ENUM_TO_STR(SO_MARK);
		CASE_ENUM_TO_STR(SO_RCVMARK);
		CASE_ENUM_TO_STR(SO_RCVPRIORITY);
		CASE_ENUM_TO_STR(SO_NO_CHECK);
		CASE_ENUM_TO_STR(SO_OOBINLINE);
		CASE_ENUM_TO_STR(SO_PASSCRED);
		CASE_ENUM_TO_STR(SO_PASSSEC);
		CASE_ENUM_TO_STR(SO_PASSPIDFD);
		CASE_ENUM_TO_STR(SO_PASSRIGHTS);
		CASE_ENUM_TO_STR(SO_PEEK_OFF);
		CASE_ENUM_TO_STR(SO_PEERCRED);
		CASE_ENUM_TO_STR(SO_PEERSEC);
		CASE_ENUM_TO_STR(SO_PEERPIDFD);
		CASE_ENUM_TO_STR(SO_PRIORITY);
		CASE_ENUM_TO_STR(SO_PROTOCOL);
		CASE_ENUM_TO_STR(SO_RCVBUF);
		CASE_ENUM_TO_STR(SO_RCVBUFFORCE);
		CASE_ENUM_TO_STR(SO_RCVLOWAT);
		CASE_ENUM_TO_STR(SO_SNDLOWAT);
		CASE_ENUM_TO_STR(SO_RCVTIMEO_OLD);
		CASE_ENUM_TO_STR(SO_SNDTIMEO_OLD);
		CASE_ENUM_TO_STR(SO_RCVTIMEO_NEW);
		CASE_ENUM_TO_STR(SO_SNDTIMEO_NEW);
		CASE_ENUM_TO_STR(SO_REUSEADDR);
		CASE_ENUM_TO_STR(SO_REUSEPORT);
		CASE_ENUM_TO_STR(SO_RESERVE_MEM);
		CASE_ENUM_TO_STR(SO_RXQ_OVFL);
		CASE_ENUM_TO_STR(SO_SELECT_ERR_QUEUE);
		CASE_ENUM_TO_STR(SO_SNDBUF);
		CASE_ENUM_TO_STR(SO_SNDBUFFORCE);
		CASE_ENUM_TO_STR(SO_TIMESTAMP);
		CASE_ENUM_TO_STR(SO_TIMESTAMPNS);
		CASE_ENUM_TO_STR(SO_TYPE);
		CASE_ENUM_TO_STR(SO_TXREHASH);
		CASE_ENUM_TO_STR(SO_BUSY_POLL);
		CASE_ENUM_TO_STR(SO_PREFER_BUSY_POLL);
		CASE_ENUM_TO_STR(SO_BUSY_POLL_BUDGET);
		CASE_ENUM_TO_STR(SO_BUF_LOCK);
		CASE_ENUM_TO_STR(SO_NETNS_COOKIE);
		CASE_ENUM_TO_STR(SO_WIFI_STATUS);
		CASE_ENUM_TO_STR(SO_NOFCS);
		CASE_ENUM_TO_STR(SO_ZEROCOPY);
		CASE_ENUM_TO_STR(SO_CNX_ADVICE);
		CASE_ENUM_TO_STR(SO_RIGHTS_NOTRUNC);
		CASE_ENUM_TO_STR(SO_DEVMEM_DONTNEED);
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

void SockOptName::processData(const Tracee &) {
	const auto val = valueAs<int>();
	using enum SockOptLevel::Level;

	switch (m_level_arg.level()) {
		case SOCKET: m_opt_variant = SocketOption{val}; break;
		default: m_opt_variant = std::monostate{}; break;
	}
}

template <typename STRUCT>
void SetSockOptStruct<STRUCT>::processData(const Tracee &proc) {
	if (const auto len = m_optlen.value(); len < 0 ||
			(size_t)len < sizeof(STRUCT)) {
		m_struct.reset();
		return;
	}

	if constexpr (requires (STRUCT& t) { t.raw(); }) {
		proc.readRawStructIntoOptional(asPtr(), m_struct);
	} else {
		proc.readStructIntoOptional(asPtr(), m_struct);
	}
}

template <typename STRUCT>
void GetSockOptStruct<STRUCT>::updateData(const Tracee &proc) {
	if (!m_call->hasResultValue()) {
		return;
	} else if (const auto len = *m_optlen.value();
			len < 0 || (size_t)len < sizeof(STRUCT)) {
		return;
	}

	if constexpr (requires (STRUCT& t) { t.raw(); }) {
		proc.readRawStructIntoOptional(asPtr(), m_struct);
	} else {
		proc.readStructIntoOptional(asPtr(), m_struct);
	}
}

void ClassicBPFSockOpt::processData(const Tracee &proc) {
	m_prog.reset();
	m_filters.clear();

	if (m_optlen.value() < int(sizeof(struct sock_fprog))) {
		return;
	}

	return FilterProg::processData(proc);
}

void GetFilterSocktOpt::processData(const Tracee &) {
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

std::string LingerSockOptBase::str() const {
	if (!m_linger) {
		return PointerValue::str();
	}

	const auto linger = m_linger->raw();

	return std::format("{{l_onoff={}, l_linger={}}}",
			linger->l_onoff, linger->l_linger);
}

void LingerSockOptBase::fetch(const Tracee &proc, const int optlen) {
	m_linger.reset();

	if (optlen < 0 || (size_t)optlen < sizeof(struct linger)) {
		return;
	}

	proc.readRawStructIntoOptional(asPtr(), m_linger);
}

void GetLingerSockOpt::updateData(const Tracee &proc) {
	if (m_call->hasResultValue()) {
		fetch(proc, *m_optlen.value());
	}
}

void SetLingerSockOpt::processData(const Tracee &proc) {
	fetch(proc, m_optlen.value());
}

std::string GetPeerCredSockOpt::str() const {
	if (!m_struct) {
		return PointerOutValue::str();
	}

	const auto &creds = *data();

	return std::format("{{pid={}, uid={}, gid={}}}",
		cosmos::to_integral(creds.processID()),
		cosmos::to_integral(creds.userID()),
		cosmos::to_integral(creds.groupID())
	);
}

void ProtocolSockOpt::updateData(const Tracee &proc) {
	GetSockOptVal<int>::updateData(proc);

	if (!value()) {
		return;
	}

	const auto &sockopt_sc = dynamic_cast<const GetSockOptSystemCall&>(*m_call);
	const auto fd_map = proc.fdInfoMap();
	auto it = fd_map.find(sockopt_sc.sockfd.fd());
	if (it == fd_map.end()) {
		LOG_WARN(std::format(
			"couldn't find sockfd {} to deduce protocol",
			cosmos::to_integral(sockopt_sc.sockfd.fd())));
		return;
	} else if (!it->second.sock_domain) {
		/* shouldn't ever happen */
		LOG_WARN(std::format(
			"couldn't find socket domain for fd {} to deduce protocol",
			cosmos::to_integral(sockopt_sc.sockfd.fd())));
		return;
	}

	const auto domain = *it->second.sock_domain;

	m_prot = SocketProtocol::create_variant(domain, *value());
}

std::string ProtocolSockOpt::str() const {
	auto prot_visitor = [this](auto prot) -> std::string {
		if constexpr (!std::is_same_v<decltype(prot), std::monostate>) {
			return std::string{SocketProtocol::label(prot)};
		}

		return std::format("unknown ({})", *value());
	};

	return std::visit(prot_visitor, m_prot);
}

void SetTimeValSockOpt::processData(const Tracee &proc) {
	if (const auto len = m_optlen.value(); len < 0 ||
			(size_t)len < traceeStructSize()) {
		m_timeval.reset();
		return;
	}

	TimeValParameter::processData(proc);
}

void GetTimeValSockOpt::updateData(const Tracee &proc) {
	if (!m_call->hasResultValue()) {
		return;
	} else if (const auto len = *m_optlen.value(); len < 0 ||
			(size_t)len < traceeStructSize()) {
		return;
	}

	TimeValParameter::updateData(proc);
}

void SetTimeSpecSockOpt::processData(const Tracee &proc) {
	if (const auto len = m_optlen.value(); len < 0 ||
			(size_t)len < traceeStructSize()) {
		m_timespec.reset();
		return;
	}

	TimeSpecParameter::processData(proc);
}

void GetTimeSpecSockOpt::updateData(const Tracee &proc) {
	if (!m_call->hasResultValue()) {
		return;
	} else if (const auto len = *m_optlen.value(); len < 0 ||
			(size_t)len < traceeStructSize()) {
		return;
	}

	TimeSpecParameter::updateData(proc);
}

template <class BASE, class OPT_LEN>
std::string BufLockSockOptT<BASE, OPT_LEN>::str() const {
	if (!m_mask) {
		return BASE::str();
	}

	BITFLAGS_FORMAT_START(*m_mask);

	BITFLAGS_ADD(SOCK_SNDBUF_LOCK);
	BITFLAGS_ADD(SOCK_RCVBUF_LOCK);

	return BITFLAGS_STR();
}

void GetBufLockSockOpt::updateData(const Tracee &proc) {
	GetSockOptVal::updateData(proc);

	if (this->value()) {
		m_mask.emplace(LockMask{*this->value()});
	} else {
		m_mask.reset();
	}
}

void SetBufLockSockOpt::processData(const Tracee &proc) {
	SetSockOptVal::processData(proc);

	if (this->value()) {
		m_mask.emplace(LockMask{*this->value()});
	} else {
		m_mask.reset();
	}
}

std::string SetDevMemDontNeedSockOpt::str() const {
	if (!data()) {
		return item::PointerInValue::str();
	}

	const auto &token = *data();

	return std::format("{{token_start={}, token_count={}}}",
			token.token_start, token.token_count);
}

} // end ns
