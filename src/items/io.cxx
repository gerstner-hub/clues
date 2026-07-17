// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/io.hxx>
#include <clues/logger.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/iovec.hxx>
#include <clues/private/kernel/select.hxx>
#include <clues/private/utils.hxx>
#include <clues/syscalls/io.hxx>
#include <clues/Tracee.hxx>
#include <sys/epoll.h>

namespace clues::item {

void PipeEnds::updateData(const Tracee &proc) {
	int ends[2];

	if (!proc.readStruct(asPtr(), ends)) {
		// probably bad userspace address or Tracee died
		reset();
		return;
	}

	m_read_end = cosmos::FileNum{ends[0]};
	m_write_end = cosmos::FileNum{ends[1]};
}

std::string PipeEnds::str() const {
	if (haveEnds()) {
		const auto ends_array = std::format("{}, {}", m_read_end, m_write_end);
		return clues::format::pointer(asPtr(), ends_array);
	} else {
		return clues::format::pointer(asPtr());
	}
}

std::string PipeFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

#define O_NOTIFICATION_PIPE O_EXCL

	BITFLAGS_ADD(O_CLOEXEC);
	BITFLAGS_ADD(O_DIRECT);
	BITFLAGS_ADD(O_NONBLOCK);
	/*
	 * This notification pipe mechanism is a pretty weird communication
	 * mechanism towards the kernel which can be used to e.g. get
	 * information out keyring events. A bit of a misused pipe for
	 * netlink-like purposes.
	 *
	 * From the tracing POV all we could do is interpreting the messages
	 * exchanged on such a pipe, but it doesn't seem worth the effort,
	 * I've never seen it in production.
	 */
	BITFLAGS_ADD(O_NOTIFICATION_PIPE);

	return BITFLAGS_STR();
}

void PipeFlags::processValue(const Tracee &) {
	m_flags = Flags{valueAs<int>()};
}

void IOVectorBase::processValue(const Tracee &tracee) {
	m_buffers.resize(m_vector_count_par.valueAs<size_t>());

	auto obtain_specs = [this, &tracee](auto &specs) {
		specs.resize(m_buffers.size());
		if (!tracee.readStructs(ptr(), specs))
			return;

		for (size_t i = 0; i < specs.size(); i++) {
			const auto &native = specs[i];
			auto &buffer = m_buffers[i];
			buffer.base = ForeignPtr{
				static_cast<uintptr_t>(native.iov_base)
			};
			buffer.len = native.iov_len;
			buffer.filled = 0;
			buffer.data.clear();
		}
	};

	if (m_call->is32BitEmulationABI()) {
		std::vector<clues::iovec32> specs;
		obtain_specs(specs);
	} else {
		std::vector<clues::iovec> specs;
		obtain_specs(specs);
	}
}

std::string IOVectorBase::str() const {
	std::string ret = "[";

	bool first = true;

	for (const auto &buffer: m_buffers) {
		if (first) {
			first = false;
		} else {
			ret += ", ";
		}
		ret += std::format("{{iov_base={}, iov_len={}}}",
			buffer.data.empty() ?
				format::pointer(buffer.base) :
				format::pointer(buffer.base,
					format::buffer(buffer.data.data(),
					buffer.data.size())),
			buffer.len
		);
	}

	return ret + "]";
}

void IOVectorBase::fetchBuffer(const Tracee &tracee, Buffer &buffer,
		const size_t left_to_fetch) {
	buffer.filled = std::min(left_to_fetch, buffer.len);
	const auto to_fetch = std::min(tracee.maxBufferPrefetch(), buffer.filled);
	buffer.data.resize(to_fetch);

	try {
		tracee.readBlob(buffer.base,
				reinterpret_cast<char*>(buffer.data.data()),
				to_fetch);
	} catch (const cosmos::CosmosError &e) {
		LOG_ERROR("Failed to fetch buffer data from Tracee: " << e.what());
		buffer.data.clear();
	}
}

void ReadVector::updateData(const Tracee &tracee) {
	if (m_call->hasErrorCode())
		return;

	size_t left_to_fetch = m_obtained_bytes_par.valueAs<size_t>();

	for (auto &buffer: m_buffers) {
		if (left_to_fetch == 0)
			break;

		fetchBuffer(tracee, buffer, left_to_fetch);
		left_to_fetch -= buffer.filled;
	}
}

void WriteVector::processValue(const Tracee &tracee) {
	IOVectorBase::processValue(tracee);

	/* we can fill the buffer data right away */
	for (auto &buffer: m_buffers) {
		/* on output there's always enough payload data present */
		fetchBuffer(tracee, buffer, buffer.len);
	}
}

std::string ReadWriteFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(RWF_DSYNC);
	BITFLAGS_ADD(RWF_HIPRI);
	BITFLAGS_ADD(RWF_SYNC);
	BITFLAGS_ADD(RWF_NOWAIT);
	BITFLAGS_ADD(RWF_APPEND);
	BITFLAGS_ADD(RWF_NOAPPEND);
	BITFLAGS_ADD(RWF_ATOMIC);
	BITFLAGS_ADD(RWF_DONTCACHE);

	return BITFLAGS_STR();
}

void ReadWriteFlags::processValue(const Tracee &) {
	m_flags = Flags{valueAs<int>()};
}

void CombinedOffsetValue::processValue(const Tracee &) {
	off_t upper = valueAs<off_t>() << 32;
	off_t lower = m_lower_bits.valueAs<off_t>();

	m_offset = lower | upper;
}

std::string CombinedOffsetValue::str() const {
	return std::to_string(m_offset);
}

void Whence::processValue(const Tracee &) {
	m_type = valueAs<SeekType>();
}

std::string Whence::str() const {
	switch (cosmos::to_integral(m_type)) {
		CASE_ENUM_TO_STR(SEEK_SET);
		CASE_ENUM_TO_STR(SEEK_CUR);
		CASE_ENUM_TO_STR(SEEK_END);
		CASE_ENUM_TO_STR(SEEK_DATA);
		CASE_ENUM_TO_STR(SEEK_HOLE);
		default: return "SEEK_???";
	}
}

std::string EventFDFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(EFD_CLOEXEC);
	BITFLAGS_ADD(EFD_NONBLOCK);
	BITFLAGS_ADD(EFD_SEMAPHORE);

	return BITFLAGS_STR();
}

void EventFDFlags::processValue(const Tracee &) {
	m_flags = valueAs<Flags>();
}

std::string EPollCreateFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(EPOLL_CLOEXEC);

	return BITFLAGS_STR();
}

void EPollCreateFlags::processValue(const Tracee &) {
	m_flags = valueAs<Flags>();
}

const fd_set* FDSet::Array::raw() const {
	static_assert(NUM_ULONGS * sizeof(m_array[0]) == sizeof(fd_set),
			"fd_set size mismatch");
	return reinterpret_cast<const fd_set*>(m_array.data());
}

bool FDSet::Array::isSet(const cosmos::FileNum fd) const {
	return FD_ISSET(cosmos::to_integral(fd), raw());
}

std::string FDSet::Array::str(const int max_fd) const {
	std::string ret{"["};

	bool first = true;

	auto set = raw();

	for (int fd = 0; fd < max_fd; fd++) {
		if (FD_ISSET(fd, set)) {
			if (first) {
				first = false;
			} else {
				ret += ", ";
			}

			ret += std::to_string(fd);
		}
	}

	return ret + "]";
}

void FDSet::processValue(const Tracee &proc) {
	m_ev_set.reset();

	if (isZero()) {
		m_req_set.reset();
		return;
	}

	m_req_set.emplace();

	/*
	 * this data structure should always be 1024 bits in size no matter
	 * what ABI.
	 */

	if (!proc.readStruct(asPtr(), *m_req_set->raw())) {
		m_req_set.reset();
	}
}

void FDSet::updateData(const Tracee &proc) {
	if (!m_req_set)
		return;

	if (!m_call->hasResultValue())
		return;

	m_ev_set.emplace();

	if (!proc.readStruct(asPtr(), *m_ev_set->raw())) {
		/* this is an unfortunate state, we failed to read the updated
		 * set from the kernel ... */
		m_ev_set.reset();
	}
}

std::string FDSet::str() const {
	if (!m_req_set) {
		return formatBadPointer();
	}

	auto ret = m_req_set->str(maxFD());

	if (m_ev_set) {
		ret += " → " + m_ev_set->str(maxFD());
	}

	return ret;
}

void OldSelectArgs::processValue(const Tracee &proc) {
	struct select_arg_struct args;

	if (!proc.readStruct(asPtr(), args)) {
		m_valid = false;
		return;
	}

	nfds = args.nfds;
	readfds = ForeignPtr(args.readset_p);
	writefds = ForeignPtr(args.writeset_p);
	exceptfds = ForeignPtr(args.exceptset_p);
	timeout = ForeignPtr(args.timeval_p);

	m_valid = true;
}

std::string OldSelectArgs::str() const {
	auto &select_call = dynamic_cast<const SelectSystemCall&>(*m_call);

	return std::format("{{nfds={}, readfds={}, writefds={}, exceptds={}, timeout={}}}",
		select_call.nfds.str(), select_call.readfds.str(),
		select_call.writefds.str(), select_call.exceptfds.str(),
		select_call.timeout.str());

}

} // end ns
