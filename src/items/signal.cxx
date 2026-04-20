// clues
#include <clues/format.hxx>
#include <clues/items/signal.hxx>
#include <clues/logger.hxx>
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

	const auto raw = m_sigaction->raw();

	std::stringstream ss;

	ss
		<< "{"
		<< "handler=";

	if (m_sigaction->getFlags()[cosmos::SigAction::Flag::SIGINFO]) {
		ss << format::pointer(ForeignPtr{reinterpret_cast<uintptr_t>(raw->sa_sigaction)});
	} else {
		if (raw->sa_handler == SIG_IGN)
			ss << "SIG_IGN";
		else if (raw->sa_handler == SIG_DFL)
			ss << "SIG_DFL";
		else
			ss << format::pointer(ForeignPtr{reinterpret_cast<uintptr_t>(raw->sa_handler)});
	}

	ss << ", mask=" << format::signal_set(m_sigaction->mask()) << ", flags="
		<< format::saflags(m_sigaction->getFlags().raw()) << ", restorer="
		<< format::pointer(ForeignPtr{reinterpret_cast<uintptr_t>(raw->sa_restorer)}) << "}";

	return ss.str();
}

namespace {

template <typename KERN_SIGACTION>
void convert_to(const KERN_SIGACTION &kern_act, cosmos::SigAction &action) {
	auto raw_act = const_cast<struct sigaction*>(static_cast<const cosmos::SigAction&>(action).raw());
	auto &mask = action.mask();
	mask.clear();

	if constexpr (sizeof(kern_act.mask) > 4) {
		*mask.raw() = kern_act.mask;
	}

	if constexpr (sizeof(kern_act.mask) == 4) {
		/*
		 * old sigaction struct, only assign the first word of the
		 * sigset. For this we need to fiddle in the private data
		 * portion of libc's sigset_t...
		 */
		mask.raw()->__val[0] = kern_act.mask;
	}

	using RestorerPtr = void (*)();
	using HandlerPtr = void (*)(int);

	/*
	 * TODO: the cosmos::SigAction object is applying some magic to the
	 * signal handler callback which doesn't fit our tracing scenario
	 * well.
	 *
	 * The type assumes that the information is always for the current
	 * process, thus it won't reflect properly our situation. We'd need a
	 * dedicated, maybe at least derived type to fix this.
	 */
	raw_act->sa_restorer = (RestorerPtr)(uintptr_t)kern_act.restorer;
	raw_act->sa_handler = (HandlerPtr)(uintptr_t)kern_act.handler;
	raw_act->sa_flags = static_cast<int>(kern_act.flags);

}

template <typename KERN_SIGACTION>
void fetch_sigaction(const ForeignPtr ptr, const Tracee &proc, std::optional<cosmos::SigAction> &action) {
	KERN_SIGACTION kern_act;

	if (!proc.readStruct(ptr, kern_act)) {
		action.reset();
		return;
	}

	convert_to(kern_act, *action);
}

} // end anon ns

void SigActionParameter::processValue(const Tracee &proc) {

	if (isOut() && proc.isEnterStop()) {
		m_sigaction.reset();
		return;
	}

	if (!m_sigaction) {
		m_sigaction = cosmos::SigAction{};
	}

	switch (m_call->callNr()) {
		case SystemCallNr::RT_SIGACTION: {
			if (m_call->is32BitEmulationABI()) {
				fetch_sigaction<kernel_sigaction32>(asPtr(), proc, m_sigaction);
			} else {
				fetch_sigaction<kernel_sigaction>(asPtr(), proc, m_sigaction);
			}
			break;
		} case SystemCallNr::SIGACTION: {
			fetch_sigaction<kernel_old_sigaction>(asPtr(), proc, m_sigaction);
			break;
		} default: {
			m_sigaction.reset();
			LOG_WARN("Unexpected system call encountered in SigActionParameter");
			break;
		}
	}
}

void SigSetParameter::processValue(const Tracee &proc) {
	if (proc.isEnterStop() && isOut()) {
		m_sigset.reset();
		return;
	}

	if (!m_sigset) {
		m_sigset = cosmos::SigSet{};
	}

	if (m_call->callNr() == SystemCallNr::SIGPROCMASK) {
		uint32_t mask;
		/* legacy i386 sigprocmask() using a 32-bit sigset_t */
		if (!proc.readStruct(asPtr(), mask)) {
			m_sigset.reset();
			return;
		}

		m_sigset->raw()->__val[0] = mask;
	} else {
		if (!proc.readStruct(asPtr(), *m_sigset->raw())) {
			m_sigset.reset();
			return;
		}
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
