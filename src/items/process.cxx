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

void ResourceUsageItem::processValue(const Tracee &proc) {
	m_rusage.emplace(ResourceUsage{});

	if (!proc.readStruct(asPtr(), m_rusage->raw())) {
		m_rusage.reset();
	}
}

std::string ResourceUsageItem::str() const {
	if (!m_rusage)
		return "NULL";

	const auto ru = m_rusage->raw();

	std::stringstream ss;
	ss
		<< "{utime=" << format::timeval(ru.ru_utime)
		<< ", stime=" << format::timeval(ru.ru_stime)
		<< ", maxrss=" << ru.ru_maxrss
		<< ", ixrss=" << ru.ru_ixrss
		<< ", idrss" << ru.ru_idrss
		<< ", isrss" << ru.ru_isrss
		<< ", minflt=" << ru.ru_minflt
		<< ", majflt=" << ru.ru_majflt
		<< ", nswap=" << ru.ru_nswap
		<< ", inblock=" << ru.ru_inblock
		<< ", oublock=" << ru.ru_oublock
		<< ", msgsnd=" << ru.ru_msgsnd
		<< ", msgrcv=" << ru.ru_msgrcv
		<< ", nsignals=" << ru.ru_nsignals
		<< ", nvcsw=" << ru.ru_nvcsw
		<< ", nivcsw=" << ru.ru_nivcsw
		<< "}";

	return ss.str();
}

std::string WaitStatusItem::scalarToString() const {
	if (!m_status) {
		return "???";
	}

	std::stringstream ss;

	if (m_status->exited()) {
		ss << "WIFEXITED && WEXITSTATUS == " << cosmos::to_integral(*m_status->status());
	} else if (m_status->signaled()) {
		ss << "WIFSIGNALED &&";
		if (m_status->dumped()) {
			ss << "WCOREDUMP &&";
		}
		ss << "WTERMSIG == " << format::signal(m_status->termSig()->raw(), false);
	}

	return ss.str();
}

} // end ns
