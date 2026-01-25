// clues
#include <clues/format.hxx>
#include <clues/items/signal.hxx>
#include <clues/macros.h>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>

// cosmos
#include <cosmos/formatting.hxx>
#include <cosmos/proc/signal.hxx>

namespace clues::item {

std::string SigSetOperation::str() const {
	switch (cosmos::to_integral(m_op)) {
		CASE_ENUM_TO_STR(SIG_BLOCK);
		CASE_ENUM_TO_STR(SIG_UNBLOCK);
		CASE_ENUM_TO_STR(SIG_SETMASK);
		default: return cosmos::sprintf("unknown (%d)", valueAs<int>());
	}
}

std::string SignalNumber::str() const {
	if (m_val == Word::ZERO && m_call->callNr() == SystemCallNr::FCNTL) {
		/*
		 * this is a special case for fcntl(fd, GETSIG), a zero value
		 * means that SIGIO without extended information is delivered.
		 */
		return "0 (default SIGIO)";
	}
	return format::signal(valueAs<cosmos::SignalNr>());
}

std::string SigactionParameter::str() const {
	if (!m_sigaction)
		return "NULL";

	std::stringstream ss;

	ss
		<< "{"
		<< "handler=";

	if (m_sigaction->handler == SIG_IGN)
		ss << "SIG_IGN";
	else if (m_sigaction->handler == SIG_DFL)
		ss << "SIG_DFL";
	else
		ss << (void*)m_sigaction->handler;

	ss << ", sa_mask=" << format::signal_set(m_sigaction->mask) << ", sa_flags="
		<< format::saflags(m_sigaction->flags) << ", sa_restorer="
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


} // end ns
