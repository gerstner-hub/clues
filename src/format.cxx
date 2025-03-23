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

namespace clues::format {

std::string signal(const cosmos::SignalNr signal) {
#	define SIG_CASE(NAME) case NAME: ss << #NAME; break

	std::stringstream ss;

	const auto SIGRTMIN_PRIV = SIGRTMIN - 2;

	if (const auto raw = cosmos::to_integral(signal); raw < SIGRTMIN_PRIV || raw > SIGRTMAX) {
		switch (raw) {
			SIG_CASE(SIGINT);
			SIG_CASE(SIGTERM);
			SIG_CASE(SIGHUP);
			SIG_CASE(SIGQUIT);
			SIG_CASE(SIGILL);
			SIG_CASE(SIGABRT);
			SIG_CASE(SIGFPE);
			SIG_CASE(SIGKILL);
			SIG_CASE(SIGPIPE);
			SIG_CASE(SIGSEGV);
			SIG_CASE(SIGALRM);
			SIG_CASE(SIGUSR1);
			SIG_CASE(SIGUSR2);
			SIG_CASE(SIGCONT);
			SIG_CASE(SIGSTOP);
			SIG_CASE(SIGTSTP);
			SIG_CASE(SIGTTIN);
			SIG_CASE(SIGTTOU);
			SIG_CASE(SIGTRAP);
			SIG_CASE(SIGBUS);
			SIG_CASE(SIGSTKFLT);
			SIG_CASE(SIGCHLD);
			SIG_CASE(SIGIO);
			SIG_CASE(SIGPROF);
			SIG_CASE(SIGSYS);
			SIG_CASE(SIGWINCH);
			SIG_CASE(SIGPWR);
			SIG_CASE(SIGURG);
			SIG_CASE(SIGXCPU);
			SIG_CASE(SIGVTALRM);
			SIG_CASE(SIGXFSZ);
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
