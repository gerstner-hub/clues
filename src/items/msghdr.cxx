// cosmos
#include <cosmos/formatting.hxx>
#include <cosmos/net/inet/aux.hxx>
#include <cosmos/net/unix/aux.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/msghdr.hxx>
#include <clues/logger.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/msghdr.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string RecvMessageHeader::str() const {
	if (!m_in_header) {
		return formatBadPointer();
	}

	std::string ret{"{"};

	const auto in_len = std::to_string(m_in_header->msg_namelen);
	const auto out_len = m_msg_namelen.str();

	const auto ctl_in_len = std::to_string(m_in_header->msg_controllen);
	const auto ctl_out_len = std::to_string(m_out_header->msg_controllen);

	ret += std::format("msg_name={}, msg_namelen={}, msg_iov={}, msg_iovlen={}, msg_control={}, msg_controllen={}, msg_flags={}",
		m_msg_name.str(),
		m_in_header->msg_namelen ? std::format("{} → {}", in_len, out_len) : in_len,
		m_msg_iov.str(), m_msg_iovlen.str(),
		controlStr(header()),
		m_in_header->msg_controllen ? std::format("{} → {}", ctl_in_len, ctl_out_len) : ctl_in_len, m_msg_controllen.str(),
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
	if (const auto unix_msg = cosmos::as_unix_message(msg); unix_msg) {
		switch (cosmos::to_integral(*unix_msg)) {
			CASE_ENUM_TO_STR(SCM_RIGHTS);
			CASE_ENUM_TO_STR(SCM_CREDENTIALS);
			default: return "SCM_???";
		}
	} else if (const auto ip4_msg = cosmos::as_ip4_message(msg); ip4_msg) {
		switch (cosmos::to_integral(*ip4_msg)) {
			CASE_ENUM_TO_STR(IP_RECVERR);
			CASE_ENUM_TO_STR(IP_PKTINFO);
			CASE_ENUM_TO_STR(IP_ORIGDSTADDR);
			CASE_ENUM_TO_STR(IP_TOS);
			CASE_ENUM_TO_STR(IP_TTL);
			default: return "IP_???";
		}
	} else if (const auto ip6_msg = cosmos::as_ip6_message(msg); ip6_msg) {
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

	if (const auto unix_msg = cosmos::as_unix_message(msg); unix_msg) {
		using enum cosmos::UnixMessage;
		switch (*unix_msg) {
			case RIGHTS: return format_unix_rights(msg);
			case CREDENTIALS: return format_unix_creds(msg);
			default: break;
		}
	} else if (const auto ip4_msg = cosmos::as_ip4_message(msg); ip4_msg) {
		using enum cosmos::IP4Message;
		switch (*ip4_msg) {
			case RECVERR: return format_inet_recverr<
				cosmos::SocketFamily::INET>(msg);
			case PKTINFO: break;
			case ORIGDSTADDR: break;
			case TOS: break;
			case TTL: break;
		}
	} else if (const auto ip6_msg = cosmos::as_ip6_message(msg); ip6_msg) {
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
		if (m_control_buffer.empty())
			return;
		std::memcpy(m_control_buffer.data(), data.data(), data.size());
		m_header.msg_control =
			reinterpret_cast<void*>(m_control_buffer.data());
	}
};

void convert_to64(const msghdr32 &hdr32, struct msghdr &hdr64) {
	hdr64.msg_name = convert_compat_ptr(hdr32.msg_name);
	hdr64.msg_namelen = hdr32.msg_namelen;
	hdr64.msg_iov = convert_compat_ptr<iovec*>(hdr32.msg_iov);
	hdr64.msg_iovlen = hdr32.msg_iovlen;
	hdr64.msg_control = convert_compat_ptr(hdr32.msg_control);
	hdr64.msg_controllen = hdr32.msg_controllen;
	hdr64.msg_flags = hdr32.msg_flags;
}

} // end anon ns

/*
 * in 32-bit emulation context fetch the 32-bit msghdr struct and copy its
 * fields into `out`.
 */
bool MessageHeaderBase::fetchMsgHdr32(const Tracee &proc,
		std::optional<struct msghdr> &out) {
	msghdr32 hdr32;
	if (!proc.readStruct(asPtr(), hdr32)) {
		out.reset();
		return false;
	}

	out.emplace();
	convert_to64(hdr32, *out);

	return true;
}

std::vector<std::byte> MessageHeaderBase::convertControlHeader32() const {
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

std::string MessageHeaderBase::controlStr(
		const std::optional<cosmos::ReceiveMessageHeader> &_hdr) const {
	if (!m_msg_control.availableBytes() || !_hdr) {
		return m_msg_control.str();
	}

	const auto &header = *_hdr;

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

std::optional<ReceiveMessageHeader> RecvMessageHeader::header() const {
	if (!m_out_header) {
		return {};
	}

	return Header{*m_out_header, convertControlHeader32()};
}

void RecvMessageHeader::processData(const Tracee &proc) {
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

	fillSubItems(proc);
}

void RecvMessageHeader::updateData(const Tracee &proc) {
	if (m_call->is32BitEmulationABI()) {
		fetchMsgHdr32(proc, m_out_header);
	} else {
		proc.readStructIntoOptional(asPtr(), m_out_header);
	}

	if (!m_out_header)
		return;

	updateSubItems(proc);
}

void RecvMessageHeader::resetSubItems(const Tracee &proc) {
	processSubItemValue(m_msg_namelen, Word::ZERO, proc);
	processSubItemValue(m_msg_name, Word::ZERO, proc);
	processSubItemValue(m_msg_iovlen, Word::ZERO, proc);
	processSubItemValue(m_msg_iov, Word::ZERO, proc);
	processSubItemValue(m_msg_controllen, Word::ZERO, proc);
	processSubItemValue(m_msg_control, Word::ZERO, proc);
	processSubItemValue(m_msg_flags, Word::ZERO, proc);
}

void RecvMessageHeader::fillSubItems(const Tracee &proc) {
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

void RecvMessageHeader::updateSubItems(const Tracee &proc) {
	/*
	 * since some of these sub-items don't expect updates we need to call
	 * `processData()` on them here as well to actually update the data
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

void SendMessageHeader::processData(const Tracee &proc) {

	if (m_call->is32BitEmulationABI()) {
		fetchMsgHdr32(proc, m_header);
	} else {
		proc.readStructIntoOptional(asPtr(), m_header);
	}

	if (!m_header) {
		resetSubItems(proc);
		return;
	}

	fillSubItems(proc);
}

void SendMessageHeader::fillSubItems(const Tracee &proc) {
	processSubItemValue(m_msg_flags,
			scalar_to_word(m_header->msg_flags), proc);
	processSubItemValue(m_msg_namelen,
			scalar_to_word(m_header->msg_namelen), proc);
	processSubItemValue(m_msg_name,
			ptr_to_word(m_header->msg_name), proc);
	processSubItemValue(m_msg_iovlen,
			scalar_to_word(m_header->msg_iovlen), proc);
	processSubItemValue(m_msg_iov,
			ptr_to_word(m_header->msg_iov), proc);
	processSubItemValue(m_msg_controllen,
			scalar_to_word(m_header->msg_controllen), proc);
	processSubItemValue(m_msg_control,
			ptr_to_word(m_header->msg_control), proc);
}

void SendMessageHeader::resetSubItems(const Tracee &proc) {
	processSubItemValue(m_msg_namelen, Word::ZERO, proc);
	processSubItemValue(m_msg_name, Word::ZERO, proc);
	processSubItemValue(m_msg_iovlen, Word::ZERO, proc);
	processSubItemValue(m_msg_flags, Word::ZERO, proc);
	processSubItemValue(m_msg_iov, Word::ZERO, proc);
	processSubItemValue(m_msg_controllen, Word::ZERO, proc);
	processSubItemValue(m_msg_control, Word::ZERO, proc);
	/* do this analogous to RecvMessageHeader */
	m_msg_control.fetchRemainingData(proc);
}

std::optional<ReceiveMessageHeader> SendMessageHeader::header() const {
	if (!m_header) {
		return {};
	}

	return Header{*m_header, convertControlHeader32()};
}

std::string SendMessageHeader::str() const {
	if (!m_header) {
		return formatBadPointer();
	}

	std::string ret{"{"};

	ret += std::format("msg_name={}, msg_namelen={}, msg_iov={}, msg_iovlen={}, msg_control={}, msg_controllen={}, msg_flags={}",
		m_msg_name.str(),
		m_header->msg_namelen,
		m_msg_iov.str(), m_msg_iovlen.str(),
		controlStr(header()),
		m_header->msg_controllen,
		m_msg_flags.str()
	);

	ret += "}";
	return ret;
}

template <typename HDR_ITEM>
bool MessageHeaderVectorBase<HDR_ITEM>::fetchRawHeaders(const Tracee &proc) {
	m_raw_headers.clear();

	if (m_call->is32BitEmulationABI()) {
		std::vector<struct mmsghdr32> hdrs32;
		hdrs32.resize(m_num_msgs.valueAs<unsigned int>());

		if (!proc.readStructs(asPtr(), hdrs32)) {
			return false;
		}

		for (const auto &hdr32: hdrs32) {
			auto &hdr = m_raw_headers.emplace_back();
			convert_to64(hdr32.msg_hdr, hdr.msg_hdr);
			hdr.msg_len = hdr32.msg_len;
		}
	} else {
		m_raw_headers.resize(m_num_msgs.valueAs<unsigned int>());

		if (!proc.readStructs(asPtr(), m_raw_headers)) {
			return false;
		}
	}

	return true;
}

template <typename HDR_ITEM>
void MessageHeaderVectorBase<HDR_ITEM>::processData(const Tracee &proc) {
	m_headers.clear();
	if (!fetchRawHeaders(proc)) {
		return;
	}

	/* avoid reallocation in the loop below to maintain the same sub-item
	 * addresses during the lifetime of the header items */
	m_headers.reserve(m_raw_headers.size());

	for (size_t i = 0; i < m_raw_headers.size(); i++) {
		const auto &raw = m_raw_headers[i];
		auto &header = m_headers.emplace_back(m_call, raw.msg_hdr);

		header.fillSubItems(proc);
	}
}

template <typename HDR_ITEM>
std::string MessageHeaderVectorBase<HDR_ITEM>::str() const {
	if (m_headers.empty())
		return formatBadPointer();

	std::string ret = "[";
	bool first = true;

	for (const auto &header: m_headers) {
		if (first) {
			first = false;
		} else {
			ret += ", ";
		}

		ret += std::format("{{msg_hdr={}, msg_len={}}}",
			header.str(),
			getMsgLenStr(header)
		);
	}

	return ret + "]";
}

RecvMultiMessageHeader::RecvMultiMessageHeader(const SystemCall *call,
		const struct msghdr &hdr) :
		RecvMessageHeader{m_bytes_received},
		m_bytes_received{ItemCfg{ItemType::PARAM_OUT, "msg_len"}} {
	m_call = call;
	m_in_header.emplace();
	std::memcpy(&*m_in_header, &hdr, sizeof(hdr));
}

void RecvMultiMessageHeader::setOutHeader(
		const struct msghdr &hdr, const Tracee &proc) {
	m_out_header.emplace();
	std::memcpy(&(*m_out_header), &hdr, sizeof(hdr));
	updateSubItems(proc);
}

void RecvMessageHeaderVector::updateData(const Tracee &proc) {
	 if (!fetchRawHeaders(proc)) {
		 /* no output headers available ... */
		return;
	 }

	 for (size_t i = 0; i < m_raw_headers.size(); i++) {
		const auto &raw = m_raw_headers[i];
		auto &header = m_headers[i];
		header.setBytesReceived(raw.msg_len, proc);
		header.setOutHeader(raw.msg_hdr, proc);
	 }
}

std::string RecvMessageHeaderVector::getMsgLenStr(
		const RecvMultiMessageHeader &item) const {
	if (!item.bytesReceived())
		return "???";

	return std::to_string(*item.bytesReceived());
}

SendMultiMessageHeader::SendMultiMessageHeader(const SystemCall *call,
		const struct msghdr &hdr) {
	m_call = call;
	m_header.emplace();
	std::memcpy(&*m_header, &hdr, sizeof(hdr));
}

void SendMessageHeaderVector::updateData(const Tracee &proc) {
	 if (!fetchRawHeaders(proc)) {
		/*
		 * if this fails we can still show the input data, but will
		 * show '?' as `msg_len`.
		 */
		return;
	 }

	 for (size_t i = 0; i < m_raw_headers.size(); i++) {
		const auto &raw = m_raw_headers[i];
		auto &header = m_headers[i];
		header.setBytesSent(raw.msg_len);
	 }
}

std::string SendMessageHeaderVector::getMsgLenStr(
		const SendMultiMessageHeader &item) const {
	if (!item.bytesSent())
		return "???";

	return std::to_string(*item.bytesSent());
}

} // end ns
