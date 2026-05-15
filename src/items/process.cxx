#include <clues/items/process.hxx>
#include <clues/format.hxx>
#include <clues/Tracee.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

std::string WaitOptionsItem::str() const {
	BITFLAGS_FORMAT_START(m_options);
	BITFLAGS_ADD(WEXITED);
	BITFLAGS_ADD(WSTOPPED);
	BITFLAGS_ADD(WCONTINUED);
	BITFLAGS_ADD(WNOHANG);
	BITFLAGS_ADD(WNOWAIT);
	BITFLAGS_ADD(__WALL);
	BITFLAGS_ADD(__WCLONE);
	BITFLAGS_ADD(__WNOTHREAD);

	return BITFLAGS_STR();
}

void ResourceUsageItem::updateData(const Tracee &proc) {
	m_rusage.emplace(ResourceUsage{});

	if (!proc.readStruct(asPtr(), m_rusage->raw())) {
		m_rusage.reset();
	}
}

std::string ResourceUsageItem::str() const {
	if (!m_rusage)
		return "NULL";

	const auto ru = m_rusage->raw();

	return std::format("{{utime={}, stime={}, maxrss={}, ixrss={}, "
			"idrss={}, isrss={}, minflt={}, majflt={}, nswap={}, "
			"inblock={}, oublock={}, msgsnd={}, msgrcv={}, "
			"nsignals={}, nvcsw={}, nivcsw={}}}",
			format::timeval(ru.ru_utime), format::timeval(ru.ru_stime),
			ru.ru_maxrss, ru.ru_ixrss,
			ru.ru_idrss, ru.ru_isrss,
			ru.ru_minflt, ru.ru_majflt,
			ru.ru_nswap,
			ru.ru_inblock, ru.ru_oublock,
			ru.ru_msgsnd, ru.ru_msgrcv,
			ru.ru_nsignals,
			ru.ru_nvcsw, ru.ru_nivcsw);
}

std::string WaitStatusItem::scalarToString() const {
	if (!m_status) {
		return "???";
	}

	if (m_status->exited()) {
		return std::format("WIFEXITED && WEXITSTATUS == {}",
				cosmos::to_integral(*m_status->status()));
	} else if (m_status->signaled()) {
		std::string ret{"WIFSIGNALED &&"};
		if (m_status->dumped()) {
			ret += " WCOREDUMP &&";
		}
		ret += std::format(" WTERMSIG == {}",
				format::signal(m_status->termSig()->raw()));
		return ret;
	} else {
		return "?!?";
	}
}

} // end ns
