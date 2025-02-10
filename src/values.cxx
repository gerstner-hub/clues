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
#include <sys/prctl.h> // arch_prctl constants
#include <asm/prctl.h> // "	"
#endif
#include <linux/futex.h> // futex(2)
#include <time.h>
#include <signal.h>
#include <sys/resource.h> // *rlimit()

// clues
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>
#include <clues/values.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/proc/mman.hxx>
#include <cosmos/proc/signal.hxx>

namespace {

std::string signal_label(const cosmos::SignalNr signal) {
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

std::string format_signal_set(const sigset_t &set) {
	std::stringstream ss;

	ss << "{";

	for (int signum = 1; signum < SIGRTMAX; signum++) {
		if (sigismember(&set, signum)) {
			ss << signal_label(cosmos::SignalNr{signum}) << ", ";
		}
	}

	ss << "}";

	auto ret = ss.str();
	if (cosmos::is_suffix(ret, ", ")) {
		ret = ret.substr(0, ret.size() - 2);
	}

	return ret;
}

std::string saflags_label(const int flags) {
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

std::string format_limit(uint64_t lim) {
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

} // end namespace


namespace clues {

std::string FileDescriptor::str() const {
	const auto fd = valueAs<cosmos::FileNum>();

	if (m_at_semantics && fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";
	else
		return std::to_string(cosmos::to_integral(fd));
}

std::string FileDescriptorReturnValue::str() const {
	const auto fd = cosmos::to_integral(valueAs<cosmos::FileNum>());

	if (fd >= 0)
		return std::to_string(fd);
	else
		return std::string{"Failed: "} + cosmos::ApiError::msg(cosmos::Errno{fd * -1});
}

std::string ErrnoResult::str() const {
	if (const auto res = valueAs<int>(); res >= m_first_valid) {
		return std::to_string((int)m_val);
	} else {
		const auto err = cosmos::Errno{res < 0 ? -res : res};
		return std::string{get_errno_label(err)} + " (" + std::to_string(res) + ")";
	}
}

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	ss << valueAs<long*>();
	return ss.str();
}

std::string StringData::str() const {
	return cosmos::sprintf("\"%s\"", m_str.c_str());
}

void StringData::fetch(const Tracee &proc) {
	// the address of the string in the userspace address space
	const auto addr = valueAs<long*>();
	proc.readString(addr, m_str);
}

void StringArrayData::processValue(const Tracee &proc) {
	const auto array_start = valueAs<long*>();
	std::vector<long*> string_addrs;
	m_strs.clear();

	// first read in all start adresses of the c-strings for the string array
	proc.readVector(array_start, string_addrs);

	for (const auto &addr: string_addrs) {
		m_strs.push_back(std::string{});
		proc.readString(addr, m_strs.back());
	}
}

std::string StringArrayData::str() const {
	std::string ret;
	ret += "[";

	for (const auto &str: m_strs) {
		ret += "\"";
		ret += str;
		ret += "\", ";
	}

	if (!m_strs.empty())
		ret.erase(ret.size() - 2);

	ret += "]";

	return ret;
}

#define chk_open_flag(FLAG) if (flags & FLAG) ss << "|" << #FLAG;

std::string OpenFlagsValue::str() const {
	std::stringstream ss;

	const auto flags = valueAs<int>();

	ss << "0x" << std::hex << flags << " (";

	// the access mode consists of the lower two bits
	const auto open_mode = cosmos::OpenMode{flags & 0x3};

	switch (open_mode) {
		default: ss << "O_???"; break;
		case cosmos::OpenMode::READ_ONLY: ss << "O_RDONLY"; break;
		case cosmos::OpenMode::WRITE_ONLY: ss << "O_WRONLY"; break;
		case cosmos::OpenMode::READ_WRITE: ss << "O_RDWR"; break;
	}

	chk_open_flag(O_APPEND);
	chk_open_flag(O_ASYNC);
	chk_open_flag(O_CLOEXEC);
	chk_open_flag(O_CREAT);
	chk_open_flag(O_DIRECT);
	chk_open_flag(O_DIRECTORY);
	chk_open_flag(O_DSYNC);
	chk_open_flag(O_EXCL);
	chk_open_flag(O_LARGEFILE);
	chk_open_flag(O_NOATIME);
	chk_open_flag(O_NOCTTY);
	chk_open_flag(O_NOFOLLOW);
	chk_open_flag(O_NONBLOCK);
	chk_open_flag(O_PATH);
	chk_open_flag(O_SYNC);
	chk_open_flag(O_TMPFILE);
	chk_open_flag(O_TRUNC);

	ss << ")";

	return ss.str();
}

std::string AccessModeParameter::str() const {
	using cosmos::fs::AccessCheck;
	const auto checks = cosmos::fs::AccessChecks{valueAs<int>()};

	std::stringstream ss;

	if (checks == cosmos::fs::AccessChecks{}) {
		ss << "F_OK";
	} else {
		if (checks[AccessCheck::READ_OK]) {
			ss << "R_OK|";
		}
		if (checks[AccessCheck::WRITE_OK]) {
			ss << "W_OK|";
		}
		if (checks[AccessCheck::EXEC_OK]) {
			ss << "X_OK";
		}
	}

	auto ret = ss.str();

	if (ret.empty()) {
		ret = "???";
	} else if (ret.back() == '|') {
		ret.erase(ret.size() - 1);
	}

	return ret;
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

std::string FileModeParameter::str() const {
	std::stringstream ss;

	const auto mode = cosmos::FileModeBits{valueAs<mode_t>()};

	auto chk_mode_flag = [&ss, mode](const cosmos::FileModeBit bit, const char *ch) {
		if (mode[bit])
			ss << ch;
		else
			ss << '-';
	};

	ss << "0x" << std::hex << valueAs<mode_t>() << " (";

	using cosmos::FileModeBit;

	chk_mode_flag(FileModeBit::SETUID,      "s");
	chk_mode_flag(FileModeBit::SETGID,      "S");
	chk_mode_flag(FileModeBit::STICKY,      "t");
	chk_mode_flag(FileModeBit::OWNER_READ,  "r");
	chk_mode_flag(FileModeBit::OWNER_WRITE, "w");
	chk_mode_flag(FileModeBit::OWNER_EXEC,  "x");
	chk_mode_flag(FileModeBit::GROUP_READ,  "r");
	chk_mode_flag(FileModeBit::GROUP_WRITE, "w");
	chk_mode_flag(FileModeBit::GROUP_EXEC,  "x");
	chk_mode_flag(FileModeBit::OTHER_READ,  "r");
	chk_mode_flag(FileModeBit::OTHER_WRITE, "w");
	chk_mode_flag(FileModeBit::OTHER_EXEC,  "x");

	ss << ")";

	return ss.str();
}

std::string StatParameter::str() const {
	if (!m_stat) {
		return "NULL";
	}

	std::stringstream ss;

	ss << "st_size = " << m_stat->st_size << ", ";
	ss << "st_dev = " << m_stat->st_dev;

	return ss.str();
}

void StatParameter::updateData(const Tracee &proc) {
	if (!m_stat) {
		m_stat = std::make_optional<struct stat>({});
	}

	if (!proc.readStruct(m_val, *m_stat)) {
		m_stat.reset();
	}
}

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

std::string DirEntries::str() const {
	std::stringstream ss;
	const auto result = m_call->result().valueAs<int>();

	if (result < 0) {
		ss << "undefined";
	} else if(result == 0) {
		ss << "empty";
	} else {
		ss << m_entries.size() << " entries: ";

		for (const auto &entry: m_entries) {
			ss << entry << ", ";
		}
	}

	return ss.str();
}

void DirEntries::updateData(const Tracee &proc) {
	m_entries.clear();

	// the amount of data stored at the DirEntries location depends on the system call result value.
	const auto bytes = m_call->result().valueAs<size_t>();

	if (bytes <= 0)
		// error or empty
		return;

	/*
	 * first copy over all the necessary data from the tracee
	 */
	std::unique_ptr<char> buffer(new char[bytes]);
	proc.readBlob(valueAs<long*>(), buffer.get(), bytes);

	struct linux_dirent *cur = nullptr;
	size_t pos = 0;

	// NOTE: to avoid copying here we could simply store a linux_dirent in
	// the object and keep only a vector of string_view

	while (pos < bytes) {
		cur = (struct linux_dirent*)(buffer.get() + pos);
		const auto namelen = cur->d_reclen - 2 - offsetof(struct linux_dirent, d_name);
		m_entries.emplace_back(std::string{cur->d_name, namelen});
		pos += cur->d_reclen;
	}
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

std::string SignalNumber::str() const {
	std::string s;
	return signal_label(valueAs<cosmos::SignalNr>());
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

	ss << "), sa_mask(" << format_signal_set(m_sigaction->mask) << "), sa_flags("
		<< saflags_label(m_sigaction->flags) << "), sa_restorer("
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
		return format_signal_set(*m_sigset);
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
		<< "rlim_cur(" << format_limit(m_limit->rlim_cur) << "), rlim_max("
		<< format_limit(m_limit->rlim_max) << ")";

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
