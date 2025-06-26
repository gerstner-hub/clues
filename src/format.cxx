// C++
#include <sstream>

// Linux
#include <sys/resource.h> // *rlimit()

// cosmos
#include <cosmos/string.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/SystemCall.hxx>
#include <clues/format.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/macros.h>

namespace clues::format {

std::string signal(const cosmos::SignalNr signal) {
	std::stringstream ss;

	const auto SIGRTMIN_PRIV = SIGRTMIN - 2;

	if (const auto raw = cosmos::to_integral(signal); raw < SIGRTMIN_PRIV || raw > SIGRTMAX) {
		switch (raw) {
			CASE_ENUM_TO_STR(SIGINT);
			CASE_ENUM_TO_STR(SIGTERM);
			CASE_ENUM_TO_STR(SIGHUP);
			CASE_ENUM_TO_STR(SIGQUIT);
			CASE_ENUM_TO_STR(SIGILL);
			CASE_ENUM_TO_STR(SIGABRT);
			CASE_ENUM_TO_STR(SIGFPE);
			CASE_ENUM_TO_STR(SIGKILL);
			CASE_ENUM_TO_STR(SIGPIPE);
			CASE_ENUM_TO_STR(SIGSEGV);
			CASE_ENUM_TO_STR(SIGALRM);
			CASE_ENUM_TO_STR(SIGUSR1);
			CASE_ENUM_TO_STR(SIGUSR2);
			CASE_ENUM_TO_STR(SIGCONT);
			CASE_ENUM_TO_STR(SIGSTOP);
			CASE_ENUM_TO_STR(SIGTSTP);
			CASE_ENUM_TO_STR(SIGTTIN);
			CASE_ENUM_TO_STR(SIGTTOU);
			CASE_ENUM_TO_STR(SIGTRAP);
			CASE_ENUM_TO_STR(SIGBUS);
			CASE_ENUM_TO_STR(SIGSTKFLT);
			CASE_ENUM_TO_STR(SIGCHLD);
			CASE_ENUM_TO_STR(SIGIO);
			CASE_ENUM_TO_STR(SIGPROF);
			CASE_ENUM_TO_STR(SIGSYS);
			CASE_ENUM_TO_STR(SIGWINCH);
			CASE_ENUM_TO_STR(SIGPWR);
			CASE_ENUM_TO_STR(SIGURG);
			CASE_ENUM_TO_STR(SIGXCPU);
			CASE_ENUM_TO_STR(SIGVTALRM);
			CASE_ENUM_TO_STR(SIGXFSZ);
			default: ss << "unknown (" << raw << ")"; break;
		}
	} else if (raw >= SIGRTMIN_PRIV && raw < SIGRTMIN) {
		ss << "glibc internal signal";
	} else {
		ss << "SIGRT" << raw - SIGRTMIN;
	}

	ss << " (" << cosmos::Signal{signal}.name() << ")";

	return ss.str();
}

std::string signal_set(const sigset_t &set) {
	std::stringstream ss;

	ss << "{";

	for (int signum = 1; signum < SIGRTMAX; signum++) {
		if (sigismember(&set, signum)) {
			ss << format::signal(cosmos::SignalNr{signum}) << ", ";
		}
	}

	ss << "}";

	auto ret = ss.str();
	if (cosmos::is_suffix(ret, ", ")) {
		ret = ret.substr(0, ret.size() - 2);
	}

	return ret;
}

std::string saflags(const int flags) {
#define chk_sa_flag(FLAG) if (flags & FLAG) { \
	if (!first) ss << "|";\
	else first = false;\
	\
	ss << #FLAG;\
}

	std::stringstream ss;
	bool first = true;

	chk_sa_flag(SA_NOCLDSTOP);
	chk_sa_flag(SA_NOCLDWAIT);
	chk_sa_flag(SA_NODEFER);
	chk_sa_flag(SA_ONSTACK);
	chk_sa_flag(SA_RESETHAND);
	chk_sa_flag(SA_RESTART);
	chk_sa_flag(SA_SIGINFO);
	chk_sa_flag(SA_RESTORER);

	return ss.str();
}

std::string limit(const uint64_t lim) {
	if (lim == RLIM_INFINITY)
		return "RLIM_INFINITY";
	// these seem to have the same value on some platforms, triggering
	// -Wduplicated-cond. So only make the check if the constants actually
	// differ.
#if RLIM_INFINITY != RLIM64_INFINITY
	else if (lim == RLIM64_INFINITY)
		return "RLIM64_INFINITY";
#endif
	else if ((lim % 1024) == 0)
		return std::to_string(lim / 1024) + " * " + "1024";
	else
		return std::to_string(lim);
}

std::string si_code(const cosmos::SigInfo::Source src) {
	const auto raw = cosmos::to_integral(src);

	switch (raw) {
		CASE_ENUM_TO_STR(SI_USER);
		CASE_ENUM_TO_STR(SI_KERNEL);
		CASE_ENUM_TO_STR(SI_QUEUE);
		CASE_ENUM_TO_STR(SI_TIMER);
		CASE_ENUM_TO_STR(SI_MESGQ);
		CASE_ENUM_TO_STR(SI_ASYNCIO);
		CASE_ENUM_TO_STR(SI_SIGIO);
		CASE_ENUM_TO_STR(SI_TKILL);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::SysData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(SYS_SECCOMP);
		CASE_ENUM_TO_STR(SYS_USER_DISPATCH);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::SegfaultData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(SEGV_MAPERR);
		CASE_ENUM_TO_STR(SEGV_ACCERR);
		CASE_ENUM_TO_STR(SEGV_BNDERR);
		CASE_ENUM_TO_STR(SEGV_PKUERR);
		CASE_ENUM_TO_STR(SEGV_ACCADI);
		CASE_ENUM_TO_STR(SEGV_ADIDERR);
		CASE_ENUM_TO_STR(SEGV_ADIPERR);
		CASE_ENUM_TO_STR(SEGV_MTEAERR);
		CASE_ENUM_TO_STR(SEGV_MTESERR);
		CASE_ENUM_TO_STR(SEGV_CPERR);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::BusData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(BUS_ADRALN);
		CASE_ENUM_TO_STR(BUS_ADRERR);
		CASE_ENUM_TO_STR(BUS_OBJERR);
		CASE_ENUM_TO_STR(BUS_MCEERR_AR);
		CASE_ENUM_TO_STR(BUS_MCEERR_AO);
		default: return std::to_string(raw);
	}
}

std::string ptrace_arch(const cosmos::ptrace::Arch arch) {
	const auto raw = cosmos::to_integral(arch);

	switch (raw) {
		CASE_ENUM_TO_STR(AUDIT_ARCH_X86_64);
		CASE_ENUM_TO_STR(AUDIT_ARCH_I386);
		default: return std::to_string(raw);
	}
}

std::string child_event(const cosmos::SigInfo::ChildData::Event event) {
	const auto raw = cosmos::to_integral(event);

	switch (raw) {
		CASE_ENUM_TO_STR(CLD_EXITED);
		CASE_ENUM_TO_STR(CLD_KILLED);
		CASE_ENUM_TO_STR(CLD_DUMPED);
		CASE_ENUM_TO_STR(CLD_TRAPPED);
		CASE_ENUM_TO_STR(CLD_STOPPED);
		CASE_ENUM_TO_STR(CLD_CONTINUED);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::PollData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(POLL_IN);
		CASE_ENUM_TO_STR(POLL_OUT);
		CASE_ENUM_TO_STR(POLL_MSG);
		CASE_ENUM_TO_STR(POLL_ERR);
		CASE_ENUM_TO_STR(POLL_PRI);
		CASE_ENUM_TO_STR(POLL_HUP);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::IllData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(ILL_ILLOPC);
		CASE_ENUM_TO_STR(ILL_ILLOPN);
		CASE_ENUM_TO_STR(ILL_ILLADR);
		CASE_ENUM_TO_STR(ILL_ILLTRP);
		CASE_ENUM_TO_STR(ILL_PRVOPC);
		CASE_ENUM_TO_STR(ILL_PRVREG);
		CASE_ENUM_TO_STR(ILL_COPROC);
		CASE_ENUM_TO_STR(ILL_BADSTK);
		CASE_ENUM_TO_STR(ILL_BADIADDR);
		default: return std::to_string(raw);
	}
}

std::string si_reason(const cosmos::SigInfo::FPEData::Reason reason) {
	const auto raw = cosmos::to_integral(reason);

	switch (raw) {
		CASE_ENUM_TO_STR(FPE_INTDIV);
		CASE_ENUM_TO_STR(FPE_INTOVF);
		CASE_ENUM_TO_STR(FPE_FLTDIV);
		CASE_ENUM_TO_STR(FPE_FLTOVF);
		CASE_ENUM_TO_STR(FPE_FLTUND);
		CASE_ENUM_TO_STR(FPE_FLTRES);
		CASE_ENUM_TO_STR(FPE_FLTINV);
		CASE_ENUM_TO_STR(FPE_FLTSUB);
		CASE_ENUM_TO_STR(FPE_FLTUNK);
		CASE_ENUM_TO_STR(FPE_CONDTRAP);
		default: return std::to_string(raw);
	}
}

std::string poll_event(const cosmos::PollEvent event) {
	const auto raw = cosmos::to_integral(event);

	switch (raw) {
		CASE_ENUM_TO_STR(POLLIN);
		CASE_ENUM_TO_STR(POLLPRI);
		CASE_ENUM_TO_STR(POLLOUT);
		CASE_ENUM_TO_STR(POLLRDHUP);
		CASE_ENUM_TO_STR(POLLERR);
		CASE_ENUM_TO_STR(POLLHUP);
		CASE_ENUM_TO_STR(POLLNVAL);
		CASE_ENUM_TO_STR(POLLWRBAND);
		default: return std::to_string(raw);
	}
}

std::string poll_events(const cosmos::PollEvents events) {
	constexpr auto HIGHEST = 1 << (sizeof(cosmos::PollEvent) * 8 - 1);
	std::string ret;

	size_t bit = 1;
	do {
		const auto flag = cosmos::PollEvent{static_cast<cosmos::PollEvents::EnumBaseType>(bit)};

		if (events[flag]) {
			if (bit != 1) {
				ret += "|";
			}
			ret += poll_event(flag);
		}

		bit <<= 1;
	} while (bit != HIGHEST);

	return ret;
}

std::string sig_info(const cosmos::SigInfo &info) {
	using SigInfo = cosmos::SigInfo;
	std::stringstream ss;

	auto add_process_ctx = [&ss](const cosmos::ProcessCtx ctx) {
		ss << ", si_pid=" << cosmos::to_integral(ctx.pid);
		ss << ", si_uid=" << cosmos::to_integral(ctx.uid);
	};

	auto add_custom_data = [&ss](const SigInfo::CustomData data) {
		ss << ", si_int=" << data.asInt();
		ss << ", si_ptr=" << data.asPtr();
	};

	ss << info.sigNr() << " {";
	if (info.source() != SigInfo::Source::KERNEL ||
			info.raw()->si_code == SI_KERNEL) {
		ss << "si_code=" << format::si_code(info.source());
	} else {
		// we have to use the raw number instead
		ss << "si_code=" << info.raw()->si_code;
	}

	if (auto user_data = info.userSigData(); user_data) {
		add_process_ctx(user_data->sender);
	} else if (auto queue_data = info.queueSigData(); queue_data) {
		add_process_ctx(queue_data->sender);
		add_custom_data(queue_data->data);
	} else if (auto msg_queue_data = info.msgQueueData(); msg_queue_data) {
		add_process_ctx(msg_queue_data->msg_sender);
		add_custom_data(msg_queue_data->data);
	} else if (auto timer_data = info.timerData(); timer_data) {
		ss << ", si_timerid=" << cosmos::to_integral(timer_data->id);
		ss << ", si_overrun=" << timer_data->overrun;
	} else if (auto sys_data = info.sysData(); sys_data) {
		ss << ", reason=" << format::si_reason(sys_data->reason);
		ss << ", si_addr=" << sys_data->call_addr;
		ss << ", si_syscall=" << sys_data->call_nr
			<< "(" << SystemCall::name(SystemCallNr{static_cast<uint64_t>(sys_data->call_nr)})
			<< ")";
		ss << ", si_arch=" << format::ptrace_arch(sys_data->arch);
		ss << ", si_errno=" << sys_data->error;
	} else if (auto child_data = info.childData(); child_data) {
		// translated si_code
		ss << " (" << format::child_event(child_data->event) << ")";
		add_process_ctx(child_data->child);
		ss << ", si_status=" << info.raw()->si_status;
		if (child_data->signal) {
			ss << " (" << *child_data->signal << ")";
		} else {
			ss << " (exit code)";
		}
		if (child_data->user_time) {
			ss << ", si_utime=" << cosmos::to_integral(*child_data->user_time);
		}
		if (child_data->system_time) {
			ss << ", si_stime=" << cosmos::to_integral(*child_data->system_time);
		}
	} else if (auto poll_data = info.pollData(); poll_data) {
		// translated si_code
		ss << " (" << format::si_reason(poll_data->reason) << ")";
		ss << ", si_fd=" << cosmos::to_integral(poll_data->fd);
		ss << ", si_band=" << format::poll_events(poll_data->events);
	} else if (auto ill_data = info.illData(); ill_data) {
		// TODO: In C++20 we can use a templated lambda to output the
		// common fault data for SIGILL, SIGFPE etc.
		// translated si_code
		ss << " (" << format::si_reason(ill_data->reason) << ")";
		ss << ", si_addr=" << ill_data->addr;
	} else if (auto fpe_data = info.fpeData(); fpe_data) {
		// translated si_code
		ss << " (" << format::si_reason(fpe_data->reason) << ")";
		ss << ", si_addr=" << fpe_data->addr;
	} else if (auto segv_data = info.segfaultData(); segv_data) {
		// translated si_code
		ss << " (" << format::si_reason(segv_data->reason) << ")";
		ss << ", si_addr=" << segv_data->addr;
		if (auto bound = segv_data->bound; bound) {
			ss << ", si_lower=" << bound->lower;
			ss << ", si_upper=" << bound->upper;
		}
		if (auto key = segv_data->key; key) {
			ss << ", si_pkey=" << cosmos::to_integral(*key);
		}
	} else if (auto bus_data = info.busData(); bus_data) {
		// translated si_code
		ss << " (" << format::si_reason(bus_data->reason) << ")";
		ss << ", si_addr=" << bus_data->addr;
		if (auto lsb = bus_data->addr_lsb; lsb) {
			ss << ", si_addr_lsb=" << *lsb;
		}
	}

	ss << "}";

	return ss.str();
}

} // end ns
