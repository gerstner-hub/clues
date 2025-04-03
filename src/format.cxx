// C++
#include <sstream>

// Linux
#include <sys/resource.h> // *rlimit()

// cosmos
#include <cosmos/string.hxx>
#include <cosmos/utils.hxx>

// clues
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

} // end ns
