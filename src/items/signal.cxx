// clues
#include <clues/format.hxx>
#include <clues/items/signal.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/sigaction.hxx>
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

std::string SigActionParameter::str() const {
	if (!m_sigaction)
		return "NULL";

	std::stringstream ss;

	ss
		<< "{"
		<< "handler=";

	if (m_sigaction->isIgnored())
		ss << "SIG_IGN";
	else if (m_sigaction->isDefaultAction())
		ss << "SIG_DFL";
	else
		ss << (void*)m_sigaction->raw()->sa_handler;

	ss << ", sa_mask=" << format::signal_set(*(m_sigaction->mask().raw())) << ", sa_flags="
		<< format::saflags(m_sigaction->getFlags().raw()) << ", sa_restorer="
		<< (void*)m_sigaction->raw()->sa_restorer << ")";

	return ss.str();
}

void SigActionParameter::processValue(const Tracee &proc) {
	using SigAction = cosmos::SigAction;

	if (!m_sigaction) {
		m_sigaction = SigAction{};
	}

	clues::kernel_sigaction kern_act;

	if (!proc.readStruct(asPtr(), kern_act)) {
		m_sigaction.reset();
	}

	auto &clues_act = *m_sigaction;
	auto raw_act = const_cast<struct sigaction*>(
			static_cast<const SigAction&>(clues_act).raw());
	auto &mask = clues_act.mask();
	*mask.raw() = kern_act.mask;
	raw_act->sa_restorer = kern_act.restorer;
	raw_act->sa_handler = kern_act.handler;
	raw_act->sa_flags = static_cast<int>(kern_act.flags);
}

void SigSetParameter::processValue(const Tracee &proc) {
	if (!m_sigset) {
		m_sigset = sigset_t{};
	}

	if (!proc.readStruct(asPtr(), *m_sigset)) {
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
