// C++
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>

// Linux
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#ifdef __x86_64__
#	include <sys/prctl.h> // arch_prctl constants
#	include <asm/prctl.h> // "	"
#endif
#include <linux/futex.h> // futex(2)
#include <signal.h>
#include <sys/resource.h> // *rlimit()

// clues
#include <clues/format.hxx>
#include <clues/items/items.hxx>
#include <clues/macros.h>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>

namespace clues::item {

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	ss << valueAs<long*>();
	return ss.str();
}

#ifdef __x86_64__

std::string ArchCodeParameter::str() const {
#	define chk_arch_case(MODE) case MODE: return #MODE;
	switch (valueAs<int>()) {
		chk_arch_case(ARCH_SET_FS)
		chk_arch_case(ARCH_GET_FS)
		chk_arch_case(ARCH_SET_GS)
		chk_arch_case(ARCH_GET_GS)
		default: return "unknown";
	}
}
#endif // __x86_64__

std::string FutexOperation::str() const {
	/*
	 * there are a number of undocumented constants and some flags can be
	 * or'd in like FUTEX_PRIVATE_FLAG. Without exactly understanding that
	 * we can't sensibly trace this ...
	 * it seems the man page doesn't tell the complete story, strace
	 * understands all the "private" stuff that can also be found in the
	 * header.
	 */
	switch (valueAs<int>() & FUTEX_CMD_MASK) {
		CASE_ENUM_TO_STR(FUTEX_WAIT);
		CASE_ENUM_TO_STR(FUTEX_WAIT_BITSET);
		CASE_ENUM_TO_STR(FUTEX_WAKE);
		CASE_ENUM_TO_STR(FUTEX_WAKE_BITSET);
		CASE_ENUM_TO_STR(FUTEX_FD);
		CASE_ENUM_TO_STR(FUTEX_REQUEUE);
		CASE_ENUM_TO_STR(FUTEX_CMP_REQUEUE);
		default: return cosmos::sprintf("unknown (%lld)", cosmos::to_integral(m_val));
	}
}

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
		<< "rlim_cur(" << format::limit(m_limit->rlim_cur) << "), rlim_max("
		<< format::limit(m_limit->rlim_max) << ")";

	return ss.str();
}

void ResourceLimit::updateData(const Tracee &proc) {
	if (!m_limit) {
		m_limit = rlimit{};
	}

	if (!proc.readStruct(m_val, *m_limit)) {
		m_limit.reset();
	}
}

} // end ns
