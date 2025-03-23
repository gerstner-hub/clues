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
#include <time.h>
#include <signal.h>
#include <sys/resource.h> // *rlimit()

// clues
#include <clues/format.hxx>
#include <clues/items/items.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/proc/mman.hxx>
#include <cosmos/proc/signal.hxx>

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

std::string MemoryProtectionParameter::str() const {
	std::stringstream ss;

	using cosmos::mem::AccessFlag;
	const auto flags = cosmos::mem::AccessFlags{valueAs<AccessFlag>()};

	if (flags == cosmos::mem::AccessFlags{}) {
		ss << "PROT_NONE";
	} else {
		if (flags[AccessFlag::READ])
			ss << "PROT_READ|";
		if (flags[AccessFlag::WRITE])
			ss << "PROT_WRITE|";
		if (flags[AccessFlag::EXEC])
			ss << "PROT_EXEC";
		if (flags[AccessFlag::SEM])
			ss << "PROT_SEM";
		if (flags[AccessFlag::SAO])
			ss << "PROT_SAO";
	}

	auto ret = ss.str();

	if (ret.empty()) {
		ret = "???";
	} else if (ret.back() == '|') {
		ret.erase(ret.size() - 1);
	}

	return ret;
}


#define ENUM_CASE(NAME) case NAME: return #NAME

std::string SigSetOperation::str() const {
	switch (valueAs<int>()) {
		ENUM_CASE(SIG_BLOCK);
		ENUM_CASE(SIG_UNBLOCK);
		ENUM_CASE(SIG_SETMASK);
		default: return cosmos::sprintf("unknown (%lld)", cosmos::to_integral(m_val));
	}
}

void TimespecParameter::fetch(const Tracee &proc) {
	if (!m_timespec) {
		m_timespec = timespec{};
	}

	if (!proc.readStruct(m_val, *m_timespec)) {
		m_timespec.reset();
	}
}

std::string TimespecParameter::str() const {
	if (!m_timespec)
		return "NULL";

	std::stringstream ss;

	ss << m_timespec->tv_sec << "s, " << m_timespec->tv_nsec << "ns";

	return ss.str();
}

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
		ENUM_CASE(FUTEX_WAIT);
		ENUM_CASE(FUTEX_WAIT_BITSET);
		ENUM_CASE(FUTEX_WAKE);
		ENUM_CASE(FUTEX_WAKE_BITSET);
		ENUM_CASE(FUTEX_FD);
		ENUM_CASE(FUTEX_REQUEUE);
		ENUM_CASE(FUTEX_CMP_REQUEUE);
		default: return cosmos::sprintf("unknown (%lld)", cosmos::to_integral(m_val));
	}
}

std::string ClockID::str() const {
	switch (valueAs<clockid_t>()) {
		ENUM_CASE(CLOCK_REALTIME);
		ENUM_CASE(CLOCK_REALTIME_COARSE);
		ENUM_CASE(CLOCK_TAI);
		ENUM_CASE(CLOCK_MONOTONIC);
		ENUM_CASE(CLOCK_MONOTONIC_RAW);
		ENUM_CASE(CLOCK_MONOTONIC_COARSE);
		ENUM_CASE(CLOCK_BOOTTIME);
		ENUM_CASE(CLOCK_PROCESS_CPUTIME_ID);
		ENUM_CASE(CLOCK_THREAD_CPUTIME_ID);
		default: return cosmos::sprintf("unknown (%lld)", cosmos::to_integral(m_val));
	}
}

std::string ClockNanoSleepFlags::str() const {
	switch (valueAs<int>()) {
		ENUM_CASE(TIMER_ABSTIME);
		case 0: return "<relative-time>";
		default: return cosmos::sprintf("unknown (%lld)", cosmos::to_integral(m_val));
	}
}

std::string SignalNumber::str() const {
	std::string s;
	return format::signal(valueAs<cosmos::SignalNr>());
}

std::string SigactionParameter::str() const {
	if (!m_sigaction)
		return "NULL";

	std::stringstream ss;

	ss << "handler(";

	if (m_sigaction->handler == SIG_IGN)
		ss << "SIG_IGN";
	else if (m_sigaction->handler == SIG_DFL)
		ss << "SIG_DFL";
	else
		ss << (void*)m_sigaction->handler;

	ss << "), sa_mask(" << format::signal_set(m_sigaction->mask) << "), sa_flags("
		<< format::saflags(m_sigaction->flags) << "), sa_restorer("
		<< (void*)m_sigaction->restorer << ")";

	return ss.str();
}

void SigactionParameter::processValue(const Tracee &proc) {
	if (!m_sigaction) {
		m_sigaction = kernel_sigaction{};
	}

	if (!proc.readStruct(m_val, *m_sigaction)) {
		m_sigaction.reset();
	}
}

void SigSetParameter::processValue(const Tracee &proc) {
	if (!m_sigset) {
		m_sigset = sigset_t{};
	}

	if (!proc.readStruct(m_val, *m_sigset)) {
		m_sigset.reset();
	}
}

std::string SigSetParameter::str() const {
	if (m_sigset) {
		return format::signal_set(*m_sigset);
	} else {
		return "NULL";
	}
}

std::string ResourceType::str() const {
	switch (valueAs<int>()) {
		ENUM_CASE(RLIMIT_AS);
		ENUM_CASE(RLIMIT_CORE);
		ENUM_CASE(RLIMIT_CPU);
		ENUM_CASE(RLIMIT_DATA);
		ENUM_CASE(RLIMIT_FSIZE);
		ENUM_CASE(RLIMIT_LOCKS);
		ENUM_CASE(RLIMIT_MEMLOCK);
		ENUM_CASE(RLIMIT_MSGQUEUE);
		ENUM_CASE(RLIMIT_NICE);
		ENUM_CASE(RLIMIT_NOFILE);
		ENUM_CASE(RLIMIT_NPROC);
		ENUM_CASE(RLIMIT_RSS);
		ENUM_CASE(RLIMIT_RTPRIO);
		ENUM_CASE(RLIMIT_RTTIME);
		ENUM_CASE(RLIMIT_SIGPENDING);
		ENUM_CASE(RLIMIT_STACK);
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
