// C++
#include <limits>
#include <sstream>

// clues
#include <clues/format.hxx>
#include <clues/items/limits.hxx>
#include <clues/macros.h>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>
// private
#include <clues/private/kernel/other.hxx>

namespace clues::item {

std::string ResourceType::str() const {
	switch (valueAs<int>()) {
		CASE_ENUM_TO_STR(RLIMIT_AS);
		CASE_ENUM_TO_STR(RLIMIT_CORE);
		CASE_ENUM_TO_STR(RLIMIT_CPU);
		CASE_ENUM_TO_STR(RLIMIT_DATA);
		CASE_ENUM_TO_STR(RLIMIT_FSIZE);
		CASE_ENUM_TO_STR(RLIMIT_LOCKS);
		CASE_ENUM_TO_STR(RLIMIT_MEMLOCK);
		CASE_ENUM_TO_STR(RLIMIT_MSGQUEUE);
		CASE_ENUM_TO_STR(RLIMIT_NICE);
		CASE_ENUM_TO_STR(RLIMIT_NOFILE);
		CASE_ENUM_TO_STR(RLIMIT_NPROC);
		CASE_ENUM_TO_STR(RLIMIT_RSS);
		CASE_ENUM_TO_STR(RLIMIT_RTPRIO);
		CASE_ENUM_TO_STR(RLIMIT_RTTIME);
		CASE_ENUM_TO_STR(RLIMIT_SIGPENDING);
		CASE_ENUM_TO_STR(RLIMIT_STACK);
		default: return "unknown";
	}
}

std::string ResourceLimit::str() const {
	if (!m_limit)
		return "NULL";

	std::stringstream ss;

	ss
		<< "{rlim_cur=" << format::limit(m_limit->rlim_cur) << ", rlim_max="
		<< format::limit(m_limit->rlim_max) << "}";

	return ss.str();
}

void ResourceLimit::updateData(const Tracee &proc) {
	auto update_rlimit = [this, &proc]<typename RLIM_T>() {
		RLIM_T rlim;

		if (!proc.readStruct(m_val, rlim)) {
			m_limit.reset();
			return;
		}

		m_limit = rlimit{};

		/*
		 * RLIM_INFINITY is simply the maximum of unsigned long, thus
		 * check the ABI-specific maximum value here and translate it
		 * into the native RLIM_INFINITY;
		 */
		constexpr auto RLIM_T_INFINITY = std::numeric_limits<decltype(rlim.rlim_cur)>::max();
		if (rlim.rlim_cur == RLIM_T_INFINITY)
			m_limit->rlim_cur = RLIM_INFINITY;
		else
			m_limit->rlim_cur = rlim.rlim_cur;

		if (rlim.rlim_max == RLIM_T_INFINITY)
			m_limit->rlim_max = RLIM_INFINITY;
		else
			m_limit->rlim_max = rlim.rlim_max;
	};

	if (isCompatSyscall()) {
		update_rlimit.operator()<struct rlimit32>();
	} else {
		update_rlimit.operator()<struct rlimit64>();
	}

}

bool ResourceLimit::isCompatSyscall() const {
	if (m_call->callNr() == SystemCallNr::PRLIMIT64)
		// prlimit64() always uses 64-bit wide fields
		return false;

	const auto abi = m_call->abi();

	return abi == ABI::I386;
}

} // end ns
