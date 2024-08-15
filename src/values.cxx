// C++
#include <cstring>
#include <sstream>
#include <iomanip>

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
#include <cosmos/formatting.hxx>
#include <cosmos/error/ApiError.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/proc/mman.hxx>
#include <cosmos/proc/Signal.hxx>

namespace clues {

std::string ErrnoResult::str() const {
	if ((int)m_val < m_highest) {
		const auto err = -(int)m_val;
		return std::string(get_errno_label(cosmos::Errno{err})) + " (" + std::to_string(err) + ")";
	} else {
		return std::to_string((int)m_val);
	}
}

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	ss << (long*)m_val;
	return ss.str();
}

std::string FileDescriptor::str() const {
	int fd = (int)m_val;

	if (m_at_semantics && fd == AT_FDCWD)
		return "AT_FDCWD";
	else
		return std::to_string((int)m_val);
}

std::string FileDescriptorReturnValue::str() const {
	int fd = (int)m_val;

	if (fd >= 0)
		return std::to_string((int)m_val);

	return std::string{"Failed: "} + cosmos::ApiError::msg(cosmos::Errno{fd * -1});
}

void StringData::fetch(const Tracee &proc) {
	// the address of the string in the userspace address space
	const long *addr = reinterpret_cast<long*>(m_val);
	readTraceeString(proc, addr, m_str);
}

void StringArrayData::processValue(const Tracee &proc) {
	const long *array_start = reinterpret_cast<long*>(m_val);
	std::vector<long*> string_addrs;
	m_strs.clear();

	// first read in all start adresses of the c-strings for the string array
	readTraceeVector(proc, array_start, string_addrs);

	for (const auto &addr: string_addrs) {
		m_strs.push_back( std::string() );
		readTraceeString(proc, addr, m_strs.back() );
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

	if (! m_strs.empty())
		ret.erase( ret.size() - 2 );

	ret += "]";

	return ret;
}

#define chk_open_flag(FLAG) if (flags & FLAG) ss << "|" << #FLAG;

std::string OpenFlagsValue::str() const {
	std::stringstream ss;

	ss << "0x" << std::hex << cosmos::to_integral(m_val) << " (";

	// the access mode is made of the lower two bits
	const auto open_mode = cosmos::OpenMode{int(cosmos::to_integral(m_val) & 0x3)};

	switch (open_mode) {
		default: ss << "O_???"; break;
		case cosmos::OpenMode::READ_ONLY: ss << "O_RDONLY"; break;
		case cosmos::OpenMode::WRITE_ONLY: ss << "O_WRONLY"; break;
		case cosmos::OpenMode::READ_WRITE: ss << "O_RDWR"; break;
	}

	const auto flags = cosmos::to_integral(m_val);

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
	if (m_val == Word::ZERO)
		return "F_OK";

	using cosmos::fs::AccessCheck;
	const auto checks = cosmos::fs::AccessChecks{int(m_val)};

	std::stringstream ss;

	if (checks[AccessCheck::READ_OK]) {
		ss << "R_OK|";
	}
	if (checks[AccessCheck::WRITE_OK]) {
		ss << "W_OK|";
	}
	if (checks[AccessCheck::EXEC_OK]) {
		ss << "X_OK";
	}

	auto ret = ss.str();

	if (ret.empty()) {
		ret = "???";
	} else if (ret.back() == '|') {
		ret.erase(ret.size() - 1);
	}

	return ret;
}

std::string FileModeParameter::str() const {
	std::stringstream ss;

	const auto mode = cosmos::FileModeBits{valueAs<mode_t>()};

	auto chk_mode_flag = [&ss, mode](const cosmos::FileModeBit bit, const char *ch) {
		if (mode[bit])
			ss << ch;
		else
			ss << '-';
	};

	ss << "0x" << std::hex << cosmos::to_integral(m_val) << " (";

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

#ifdef __x86_64__

std::string ArchCodeParameter::str() const {
#	define chk_arch_case(MODE) case MODE: return #MODE;
	switch (cosmos::to_integral(m_val)) {
		chk_arch_case(ARCH_SET_FS)
		chk_arch_case(ARCH_GET_FS)
		chk_arch_case(ARCH_SET_GS)
		chk_arch_case(ARCH_GET_GS)
		default: return "unknown";
	}
}
#endif // __x86_64__

StatParameter::~StatParameter() {
	delete m_stat;
}

std::string StatParameter::str() const {
	std::stringstream ss;

	ss << "st_size = " << m_stat->st_size << ", ";
	ss << "st_dev = " << m_stat->st_dev;

	return ss.str();
}

void StatParameter::updateData(const Tracee &proc) {
	readStruct(proc, m_val, m_stat);
}

extern "C" {

/*
 * the man page says there's no header for this
 */
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
	/*
	 * following fields, cannot be sensibly accessed by the compiler,
	 * needs to be calculated during runtime, therefore only as comments
	char pad; // zero padding byte
	char d_type; // file type since Linux 2.6.4
	*/
};

}

std::string DirEntries::str() const {
	std::stringstream ss;
	const auto &res_par = m_call->result();
	const auto result = res_par.valueAs<int>();

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

	// the amount of data stored at the DirEntries location depends on the
	// system call result value
	const auto &res_par = m_call->result();
	const auto bytes = res_par.valueAs<size_t>();

	if (bytes <= 0)
		return;

	/*
	 * first copy over all the necessary data from the tracee
	 */
	char *buffer = new char[bytes];
	readTraceeBlob(
		proc,
		reinterpret_cast<long*>(this->value()),
		buffer,
		bytes);

	struct linux_dirent *cur = nullptr;
	size_t pos = 0;

	while (pos < bytes) {
		cur = (struct linux_dirent*)(buffer + pos);
		m_entries.push_back( cur->d_name );
		pos += cur->d_reclen;
	}

	delete[] buffer;
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

std::string FutexOperation::str() const {
	/*
	 * there are a number of undocumented constants and some flags can be
	 * or'd in like FUTEX_PRIVATE_FLAG. Without exactly understanding that
	 * we can't sensibly trace this ...
	 * seems the man page doesn't tell the complete story, strace
	 * understands all the "private" stuff that can also be found in the
	 * header
	 */
	switch (int(m_val) & FUTEX_CMD_MASK) {
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

void TimespecParameter::fetch(const Tracee &proc) {
	// the address of the struct in the userspace address space
	const long *addr = reinterpret_cast<long*>(m_val);

	if (! addr)
		// NULL time specification
		return;

	if (! m_timespec)
		m_timespec = new struct timespec;

	readTraceeStruct(proc, addr, *m_timespec);
}


TimespecParameter::~TimespecParameter() {
	delete m_timespec;
}

std::string TimespecParameter::str() const {
	if (! m_timespec)
		return "NULL";

	std::stringstream ss;

	ss << m_timespec->tv_sec << "s, " << m_timespec->tv_nsec << "ns";

	return ss.str();
}

#define SIG_CASE(NAME) case NAME: ss << #NAME; break

namespace {

void printSignal(std::string &s, const cosmos::SignalNr signal) {
	std::stringstream ss;
	s.clear();

	const auto SIGRTMIN_PRIV = SIGRTMIN - 2;

	if (const auto raw = cosmos::to_integral(signal); raw < (SIGRTMIN_PRIV) || raw > SIGRTMAX) {
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

	s = ss.str();
}

void printSignalSet(std::string &s, const sigset_t &set) {
	std::stringstream ss;

	s.clear();

	ss << "{";

	for (int signum = 1; signum < SIGRTMAX; signum++) {
		if (sigismember(&set, signum)) {
			printSignal(s, cosmos::SignalNr{signum});

			ss << s << ", ";
		}
	}

	ss << "}";

	s = ss.str();
}

} // end namespace

std::string SignalNumber::str() const {
	std::string s;
	printSignal(s, valueAs<cosmos::SignalNr>());
	return s;
}

#define chk_sa_flag(FLAG) if( flags & FLAG ) { \
	if ( !first ) ss << "|";\
	else first = false;\
	\
	ss << #FLAG;\
}

std::string saflags_str(const int flags) {
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

std::string SigactionParameter::str() const {
	if (! m_sigaction)
		return "NULL";

	std::stringstream ss;


	ss << "handler(";

	if (m_sigaction->handler == SIG_IGN)
		ss << "SIG_IGN";
	else if (m_sigaction->handler == SIG_DFL)
		ss << "SIG_DFL";
	else 
		ss << (void*)m_sigaction->handler;

	std::string mask_str;
	printSignalSet(mask_str, m_sigaction->mask);

	ss << "), sa_mask(" << mask_str << "), sa_flags("
		<< saflags_str(m_sigaction->flags) << "), sa_restorer("
		<< (void*)m_sigaction->restorer << ")";

	return ss.str();
}

SigactionParameter::~SigactionParameter() {
	delete m_sigaction;
}

void SigactionParameter::processValue(const Tracee &proc) {
	readStruct(proc, m_val, m_sigaction);
}

SigSetParameter::~SigSetParameter() {
	delete m_sigset;
}

void SigSetParameter::processValue(const Tracee &proc) {
	readStruct(proc, m_val, m_sigset);
}

std::string SigSetParameter::str() const {
	std::string s;
	printSignalSet(s, *m_sigset);

	return s;
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

std::string printLimit(uint64_t lim) {
	if (lim == RLIM_INFINITY)
		return "RLIM_INFINITY";
	// these seem to have the the same value on some platforms, triggering
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

std::string ResourceLimit::str() const {
	if (! m_limit)
		return "NULL";

	std::stringstream ss;

	ss
		<< "rlim_cur(" << printLimit(m_limit->rlim_cur) << "), rlim_max("
		<< printLimit(m_limit->rlim_max) << ")";

	return ss.str();
}

ResourceLimit::~ResourceLimit() {
	delete m_limit;
}

void ResourceLimit::updateData(const Tracee &proc) {
	readStruct(proc, m_val, m_limit);
}

} // end ns
