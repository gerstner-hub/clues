// C++
#include <format>

// clues
#include <clues/format.hxx>
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

} // end ns
