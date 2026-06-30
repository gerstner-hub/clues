// C++
#include <format>

// Linux
#include <sys/utsname.h>

// cosmos
#include <cosmos/error/RuntimeError.hxx>

// clues
#include <clues/format.hxx>
#include <clues/private/kernel/uname.hxx>
#include <clues/private/utils.hxx>
#include <clues/syscalls/other.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string GetRandomFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(GRND_RANDOM);
	BITFLAGS_ADD(GRND_NONBLOCK);

	return BITFLAGS_STR();
}

void GetRandomFlagsValue::processValue(const Tracee&) {
	m_flags = cosmos::GetRandomFlags{valueAs<int>()};
}

void RSeqFlagsValue::processValue(const Tracee&) {
	m_flags = Flags{valueAs<int>()};
}

std::string RSeqFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(RSEQ_FLAG_UNREGISTER);

	return BITFLAGS_STR();
}

void RSeqParameter::updateData(const Tracee &tracee) {
	const auto &rseq_call = dynamic_cast<const RSeqSystemCall&>(*m_call);

	if (!rseq_call.hasResultValue())
		return;

	m_data.resize(rseq_call.rseq_len.value());

	try {
		tracee.readBlob(this->ptr(), m_data.data(), m_data.size());
	} catch (const std::exception &ex) {
		// shouldn't really happen
		m_data.clear();
		return;
	}
}

std::string RSeqParameter::str() const {
	if (m_data.empty() || m_data.size() < sizeof(struct rseq)) {
		return "<invalid>";
	}

	const auto &rs = *data();

	BITFLAGS_FORMAT_START_RAW(rs.flags);
	BITFLAGS_ADD(RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT);
	BITFLAGS_ADD(RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL);
	BITFLAGS_ADD(RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE);
	const auto flags_str = BITFLAGS_STR();

	return std::format("{{cpu_id_start={}, cpu_id={}, rseq_cs={}, "
			"flags={}, node_id={}, mm_cid={}}}",
		rs.cpu_id_start, rs.cpu_id,
		format::pointer((ForeignPtr)rs.rseq_cs),
		flags_str, rs.node_id, rs.mm_cid
	);
}

std::string UnameStruct::str() const {
	if (!m_uname) {
		return PointerOutValue::formatBadPointer();
	}

	auto ret =  std::format("{{sysname=\"{}\", nodename=\"{}\", release=\"{}\", version=\"{}\", machine=\"{}\"",
		m_uname->sysName(), m_uname->nodeName(), m_uname->release(),
		m_uname->version(), m_uname->machine()
	);

	if (m_call->callNr() == SystemCallNr::UNAME) {
		ret += std::format(", domainname=\"{}\"", m_uname->domainName());
	}

	ret += "}";

	return ret;
}

void UnameStruct::updateData(const Tracee &proc) {
	PointerOutValue::updateData(proc);

	if (!m_call->hasResultValue()) {
		return;
	}

	auto copy_struct = [this, &proc](auto &kernel) {
		m_uname.reset(new UnameStruct::Uname{});

		if (!proc.readStruct(this->ptr(), kernel)) {
			m_uname.reset();
			return;
		}

		auto &ours = *m_uname->buf();

		/*
		 * when the system call succeeded then we should be able to
		 * safely assume these strings are properly null terminated.
		 *
		 * the older structs only have shorted buffers, so we should
		 * have no issue with buffer overflows either.
		 */

		std::strcpy(ours.sysname, kernel.sysname);
		std::strcpy(ours.nodename, kernel.nodename);
		std::strcpy(ours.release, kernel.release);
		std::strcpy(ours.version, kernel.version);
		std::strcpy(ours.machine, kernel.machine);

		if constexpr (std::is_same_v<decltype(kernel), new_utsname>) {
			std::strcpy(ours.domainname, kernel.domainname);
		}
	};

	switch (m_call->callNr()) {
		case SystemCallNr::UNAME: {
			new_utsname kernel;
			copy_struct(kernel);
			break;
		} case SystemCallNr::OLDUNAME: {
			old_utsname kernel;
			copy_struct(kernel);
			break;
		} case SystemCallNr::OLDOLDUNAME: {
			oldold_utsname kernel;
			copy_struct(kernel);
			break;
		} default: throw cosmos::RuntimeError{"unexpected uname system call"};
	}
}

} // end ns
