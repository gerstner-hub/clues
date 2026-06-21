// C++
#include <iostream>
#include <regex>
#include <utility>
#include <vector>

// clues
#include <clues/arch.hxx>

// Test
#include "TestBase.hxx"
#include "TracerInvoker.hxx"

/*
 * This tests the command line tracer `clues` on an application level by
 * inspecting the output when tracing well-known sample binaries and matching
 * against regular expressions.
 */

namespace {

struct StringVector :
		public std::vector<std::string> {
	constexpr StringVector(const char *s) :
		std::vector<std::string>{{std::string{s}}} {
	}

	constexpr StringVector(std::initializer_list<const char*> l) {
		for (const auto s: l) {
			push_back(std::string{s});
		}
	}
};

#ifdef COSMOS_I386
#	define NEW_MMAP "mmap2()"
#else
#	define NEW_MMAP "mmap()"
#endif

/*
 * these search/replace patterns allow to use symbolic names in regular
 * expressions in TestSpec.exprs below. This way regular expressions are
 * easier to write and read and we can also adapt more easily to changes in
 * tracer output.
 */
const std::vector<std::pair<std::string, std::string>> REGEX_SEARCH_REPLACE = {
	{"{addr}", R"(0x[0-9a-f]+)"},
	{"{hex}", R"(0x[0-9a-f]+)"},
	{"{fd}", R"([0-9]+)"},
	{"{bitmask}", R"(0x[0-9a-f]+)"},
	{"{decimal}", R"([0-9]+)"},
	{"{pid}", R"([0-9]+)"},
	// match a string surrounded by double-quotes, also supporting
	// embedded escaped \" characters.
	// Optionally a suffix ending in (...) if the string was truncated.
	{"{string}", R"("(?:\\.|[^"\\])*(\.\.\.)?")"},
	{"{bool}", R"((false|true))"},
};

struct TestSpec {
	/// Basename and command line of the sample binary to run. If empty then the name found in `filter` will be used as basename.
	StringVector sample_cmdline;
	/// Filter to pass to `clues` `-e` argument like `openat,openat2`
	std::string filter;
	/// Regular expressions to match against trace output.
	std::vector<std::string> exprs;
	/// A name for the test case.
	std::string_view label;

	constexpr TestSpec(const StringVector cmdline, const std::string _filter, const std::vector<std::string> _exprs, const std::string_view _label = {}) :
		sample_cmdline{cmdline},
		filter{_filter},
		exprs{_exprs},
		label{_label} {
	}
};

const std::vector<TestSpec> TEST_SPECS{
#ifdef CLUES_HAVE_ACCESS
	TestSpec{"access", "access,faccessat,faccessat2", {
			R"(access\(path="/etc/fstab", check=R_OK\) = 0)",
			R"(faccessat\(fd={fd}, path="fstab", check=W_OK\) = 13)",
			R"(faccessat2\(fd={fd}, path="fstab", check=X_OK, flags={bitmask} \(AT_EACCESS\)\) = 13)"
		}, "*access*()"
	},
#endif
#ifdef CLUES_HAVE_ALARM
	TestSpec{{}, "alarm", {
		R"(alarm\(seconds={decimal}\) = 0)"
	}},
#endif
#ifdef CLUES_HAVE_ARCH_PRCTL
	TestSpec{"prctl", "arch_prctl", {
			R"(arch_prctl\(op=ARCH_SET_CPUID, enable=[01]\) = [0-9]+)",
			R"(arch_prctl\(op=ARCH_GET_CPUID\) = [0-9]+)",
#	ifdef COSMOS_X86_64
			R"(arch_prctl\(op=ARCH_GET_FS, \*base={addr} → \[{addr}\]\) = 0)",
			R"(arch_prctl\(op=ARCH_GET_GS, \*base={addr} → \[{addr}\]\) = 0)",
			R"(arch_prctl\(op=ARCH_SET_FS, base={addr}\) = 0)",
			R"(arch_prctl\(op=ARCH_SET_GS, base={addr}\) = 0)"
#	endif
	}},
#endif
	TestSpec{{}, "break", {
			R"(break\(req_addr=0x4711\) = {addr})"
	}, "brk()"},
	TestSpec{{"nanosleep", "0", "500"}, "clock_nanosleep", {
			R"(clock_nanosleep\(clockid=CLOCK_MONOTONIC, flags=TIMER_ABSTIME, time=\{{decimal}s, {decimal}ns\}, rem={addr}\) = 0)"
	}},
	TestSpec{{"nanosleep", "0", "500"}, "nanosleep", {
			R"(nanosleep\(req_time=\{{decimal}s, {decimal}ns\}, rem_time=\{{decimal}s, {decimal}ns\}\) = 0)"
	}},
	TestSpec{"clone", "clone,clone3", {
			R"(clone\(flags={bitmask} \(CLONE_.*SIGCHLD\), stack={addr}, parent_tid={addr} → \[{decimal}\]\) = {pid})",
			R"(clone3\(cl_args=\{flags=0x[0-9a-f]+ \(CLONE_CHILD_SETTID.*CLONE_PIDFD\), pidfd=0x[0-9a-f]+ → \[[0-9\], child_tid=0x[0-9a-f]+, parent_tid=0x[0-9a-f]+ → [[0-9]+], exit_signal=SIGCHLD, stack=NULL, stack_size=0, set_tid=NULL, set_tid_size=0}, size=88\) = [0-9]+)"
	}, "clone*()"},
	TestSpec{{}, "close", {
			R"(close\(fd=[0-9]\))"
	}},
	TestSpec{{}, "execve", {
			R"(execve\(filename="[^"]+", argv=\[[^\]]+\], envp=\[.*\]\) = 0)",
	}},
	TestSpec{{"execve", "execveat"}, "execveat", {
			R"(execveat\(fd=[0-9], filename="", argv=\[[^\]]+\], envp=\[.*\], flags=0x[0-9a-f]+ \(AT_EMPTY_PATH\)\) = 0)",
	}},
	TestSpec{"exit", "exit_group", {
			R"(exit_group\(status=[0-9]+\) = )"
	}},
	TestSpec{{}, "getrandom", {
			R"(getrandom\(buf="[^"]+", size=16, flags=0x0 \(\)\) = 16)",
	}},
	TestSpec{"fcntl", "fcntl,fcntl64", {
			/* output differs quite chaotically here between x86-64 and i386, thus we need to add some degree of freedom in some spots */
			R"(fcntl(64)?\(fd=[0-9]+, op=F_DUPFD, lowest_fd=[0-9]+\) = [0-9]+)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_DUPFD_CLOEXEC, lowest_fd=[0-9]+\) = [0-9]+)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETFD\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETFD, fdflags=0x1 \(FD_CLOEXEC\)\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETFD\) = 0x1)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETFL, flags=0x400 \(O_RDONLY\|O_APPEND\)\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETFL\) = 0x401 \(O_WRONLY\|O_APPEND\))",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLK(64)?, flock=\{l_type=F_RDLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLK(64)?, flock=\{l_type=F_UNLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLKW(64)?, flock=\{l_type=F_RDLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETLK(64)?, flock=\{l_type=F_UNLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLK(64)?, flock=\{l_type=F_WRLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLK(64)?, flock=\{l_type=F_UNLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_OFD_SETLK(64)?, flock=\{l_type=F_RDLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_OFD_SETLKW(64)?, flock=\{l_type=F_RDLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_OFD_GETLK(64)?, flock=\{l_type=F_RDLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_OFD_SETLK(64)?, flock=\{l_type=F_WRLCK, l_whence=SEEK_CUR, l_start=10, l_len=100, l_pid=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETOWN, pid=[0-9]+\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETOWN\) = [0-9]+)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETOWN_EX, owner_ex=\{type=F_OWNER_PGRP, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETOWN_EX, owner_ex=\{type=F_OWNER_PID, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETOWN_EX, owner_ex=\{type=F_OWNER_PID, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETOWN_EX, owner_ex=\{type=F_OWNER_TID, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETOWN_EX, owner_ex=\{type=F_OWNER_TID, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETOWN_EX, owner_ex=\{type=F_OWNER_PGRP, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETOWN_EX, owner_ex=\{type=F_OWNER_PGRP, id=[0-9]+\}\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETSIG, signum=.*\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETSIG\) = )",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETSIG, signum=SIGUSR1\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETSIG\) = SIGUSR1)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETLEASE\) = F_UNLCK)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLEASE, lease=F_WRLCK\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLEASE, lease=F_RDLCK\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETLEASE\) = F_RDLCK)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETLEASE, lease=F_UNLCK\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_NOTIFY, events=0x80000009 \(DN_ACCESS\|DN_DELETE\|DN_MULTISHOT\)\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_NOTIFY, events=0x0 \(\)\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_SETPIPE_SZ, pipe size=5192\) = [0-9]+)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GETPIPE_SZ\) = [0-9]+)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_ADD_SEALS, flags=0x2 \(F_SEAL_SHRINK\)\) = 0)",
			R"(fcntl(64)?\(fd=[0-9]+, op=F_GET_SEALS\) = 0x2)",
	}},
	TestSpec{{}, "futex", {
		R"(futex\(addr=0x[0-9a-f]+, op=0x1 \(FUTEX_WAKE\), nwakeup=[0-9]+\) = 0)",
		R"(futex\(addr=0x[0-9a-f]+, op=0x100 \(FUTEX_WAIT\|FUTEX_CLOCK_REALTIME\), value=[0-9]+, timeout=\{[0-9]+s, [0-9]+ns\}\) = [0-9]+)"
		/* TODO: cover more futex variants */
	}},
#ifdef CLUES_HAVE_LEGACY_GETDENTS
	TestSpec{{}, "getdents", {
		R"(getdents\(fd=[0-9]+, dirent=[0-9]+ entries: \{d_ino=[0-9]+, d_off=[0-9]+, d_reclen=[0-9]+, d_name="[^"]+", d_type=DT_[A-Z]+\}, .*\}, size=[0-9]+\) = [0-9]+)"
	}},
#endif
	TestSpec{"getdents", "getdents64", {
		R"(getdents64\(fd=[0-9]+, dirent=[0-9]+ entries: \{d_ino=[0-9]+, d_off=[0-9]+, d_reclen=[0-9]+, d_name="[^"]+", d_type=DT_[A-Z]+\}, .*\}, size=[0-9]+\) = [0-9]+)"
	}},
	TestSpec{"getids", "getuid", {
		R"(getuid\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "geteuid", {
		R"(geteuid\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "getgid", {
		R"(getgid\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "getegid", {
		R"(getegid\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "getpid", {
		R"(getpid\(\) = [0-9]+ \(pid\))"
	}},
	TestSpec{"getids", "getppid", {
		R"(getppid\(\) = [0-9]+ \(pid\))"
	}},
	TestSpec{"getids", "getpgid", {
		R"(getpgid\(pid=[0-9]+\) = [0-9]+ \(pgid\))"
	}},
	TestSpec{"getids", "gettid", {
		R"(gettid\(\) = [0-9]+ \(tid\))"
	}},
	TestSpec{"getids", "getsid", {
		R"(getsid\(pid=[0-9]+\) = [0-9]+ \(sid\))"
	}},
	TestSpec{"getids", "setsid", {
		R"(setsid\(\) = [0-9]+ \(sid\))"
	}},
	TestSpec{"rlimit", "getrlimit", {
		R"(getrlimit\(resource=RLIMIT_AS, limit=\{rlim_cur=(RLIM_INFINITY|[0-9]+), rlim_max=(RLIM_INFINITY|[0-9]+)\}\) = 0)"
	}},
	TestSpec{"rlimit", "setrlimit", {
		R"(setrlimit\(resource=RLIMIT_AS, limit=\{rlim_cur=RLIM_INFINITY, rlim_max=RLIM_INFINITY\}\) = [0-9]+)"
	}},
	TestSpec{"rlimit", "prlimit64", {
		R"(prlimit64\(pid=[0-9]+, resource=RLIMIT_AS, limit=NULL, old_limit=\{rlim_cur=[0-9* ]+, rlim_max=(RLIM_INFINITY|[0-9]+)\}\) = 0)"
	}},
	TestSpec{"robust_list", "get_robust_list", {
		R"(get_robust_list\(tid=[0-9]+, head=0x[0-9a-f]+ → \[0x[0-9a-f]+\], sizep=0x[0-9a-f]+ → \[[0-9]+\]\) = 0)"
	}},
	TestSpec{"robust_list", "set_robust_list", {
		R"(set_robust_list\(head=0x[0-9a-f]+, size=[0-9]+\) = 0)"
	}},
	TestSpec{"mmap", "mmap,mmap2", {
		R"(mmap(2)?\(hint=0x[0-9a-f]+, len=[0-9a-f]+, prot=0x[0-9a-f]+ \(PROT_READ\|PROT_EXEC\), flags=0x[0-9a-f]+ \(MAP_PRIVATE\|MAP_ANONYMOUS\), fd=-1, offset=[0-9a-f]+\) = 0x[0-9a-f]+)",
		NEW_MMAP
	}},
	TestSpec{"mmap", "mprotect", {
		R"(mprotect\(addr=0x[0-9a-f]+, length=[0-9]+, prot=0x2 \(PROT\_WRITE\)\) = [0-9]+)"
	}},
	TestSpec{"mmap", "munmap", {
		R"(munmap\(addr=0x[0-9a-f]+, len=[0-9]+\) = 0)"
	}},
#ifdef CLUES_HAVE_OPEN
	TestSpec{{}, "open", {
		R"(open\(filename="[^"]+", flags=0x40 \(O_RDONLY\|O_CREAT\), mode=0o[0-7]+ \(rwxr-xr-x\)\) = [0-9])"
	}},
#endif
	TestSpec{"open", "openat", {
		R"(openat\(fd=AT_FDCWD, filename="[^"]+", flags=0x[0-9a-f]+ \(O_RDONLY\|O_DIRECTORY[^\)]*\)\) = [0-9]+)"
	}},
	TestSpec{{}, "read", {
		R"(read\(fd={fd}, buf={string}, count={decimal}\) = {decimal})",
		/* failure to read should not show buffer contents */
		R"(read\(fd={fd}, buf={addr}, count={decimal}\) = [0-9]+.*errno)"
	}},
	TestSpec{"read", "pread64", {
		R"(pread64\(fd=[0-9]+, buf={string}, count=[0-9]+, offset=[0-9]+\) = [0-9]+)"
	}},
	TestSpec{"read", "readv", {
		R"(readv\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}\], iovcnt=[0-9]+\) = [0-9]+ \(bytes\))",
		R"(readv\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+, iov_len=[0-9]+\}\], iovcnt=[0-9]+\) = [0-9]+ \(bytes\))"

	}},
	TestSpec{"read", "preadv", {
		R"(preadv\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}], iovcnt=[0-9]+, offset=[0-9]+\) = [0-9]+ \(bytes\))"
	}},
	TestSpec{"read", "preadv2", {
		R"(preadv2\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}], iovcnt=[0-9]+, offset=[0-9]+, flags=0x[0-9a-f]+ \(RWF_[A-Z]+\)\) = [0-9]+ \(bytes\))"
	}},
	TestSpec{"sigaction", "rt_sigaction", {
		R"(rt_sigaction\(signum=SIGCHLD, sigaction=\{handler=0x[0-9a-f]+, mask=\{SIGUSR1\}, flags=SA_RESETHAND\|SA_RESTART(\|SA_RESTORER)?, restorer=(0x[0-9a-f]+|NULL)\}, old_action=\{handler=SIG_DFL, mask=\{\}, flags=[0-9]+, restorer=NULL\}, sigset_size=8\) = [0-9]+)"
	}},
	TestSpec{"sigprocmask", "rt_sigprocmask", {
		R"(rt_sigprocmask\(sigsetop=SIG_BLOCK, new mask=\{SIGUSR1\}, old mask=\{\}, sigset_size=8\) = [0-9]+)"
	}},
	TestSpec{{}, "set_tid_address", {
		R"(set_tid_address\(addr=0x[0-9a-f]+\) = [0-9]+)"
	}},
	TestSpec{{}, "tgkill", {
		R"(tgkill\(pid=[0-9]+, tid=[0-9]+, signum=.*[0-9]+.*\) = [0-9]+)"
	}},
	TestSpec{{}, "wait4", {
		R"(wait4\(pid=[0-9]+, wstatus=0x[0-9a-f]+ → [WIFEXITED && WEXITSTATUS == [0-9]+], options=0x[0-9a-f]+ \(WCONTINUED\), rusage=\{utime=\{[0-9]+s, [0-9]+us\}, stime=\{[0-9]+s, [0-9]+us\}, maxrss=[0-9]+, ixrss=[0-9]+, idrss=[0-9]+, isrss=[0-9]+, minflt=[0-9]+, majflt=[0-9]+, nswap=[0-9]+, inblock=[0-9]+, oublock=[0-9]+, msgsnd=[0-9]+, msgrcv=[0-9]+, nsignals=[0-9]+, nvcsw=[0-9]+, nivcsw=[0-9]+\}\) = [0-9]+)"
	}},
	TestSpec{{}, "write", {
		R"(write\(fd=[0-9]+, buf="[^"]+", count=[0-9]+\) = [0-9]+)"
	}},
	TestSpec{"write", "writev", {
		R"(writev\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}\], iovcnt=[0-9]+\) = [0-9]+ \(bytes\))"
	}},
	TestSpec{"write", "pwritev", {
		R"(pwritev\(fd=[0-9]+, iov=[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}], iovcnt=[0-9]+, offset=[0-9]+\) = [0-9]+ \(bytes\))"
	}},
	TestSpec{"write", "pwritev2", {
		R"(pwritev2\(fd=[0-9]+, iov=\[\{iov_base=0x[0-9a-f]+ → \["[^"]+"\], iov_len=[0-9]+\}, \{iov_base=0x[0-9a-f]+ → \["123456"\], iov_len=[0-9]+\}], iovcnt=[0-9]+, offset=[0-9]+, flags=0x[0-9]+ \(RWF_[A-Z]+\)\) = [0-9]+ \(bytes\))"
	}},
	TestSpec{"write", "pwrite64", {
		R"(pwrite64\(fd=[0-9]+, buf="[^"]+", count=[0-9]+, offset=[0-9]+\) = [0-9]+)"
	}},
	TestSpec{{}, "lseek", {
		R"(lseek\(fd=[0-9]+, offset=(-)?[0-9]+, whence=SEEK_[A-Z]+\) = [0-9]+ \(offset\))"
	}},
	TestSpec{"robust_list", "rseq", {
		R"(rseq\(rseq=\{cpu_id_start=[0-9]+, cpu_id=[0-9]+, rseq_cs=(NULL|0x[0-9a-f]+), flags=0x[0-9a-f]+ \(.*\), node_id=[0-9]+, mm_cid=[0-9]+\}, rseq_len=[0-9]+, flags=0x[0-9a-f]+ \(.*\), signature=0x[0-9a-f]+\) = 0 \(success\))"
	}},
	TestSpec{{}, "prctl", {
			R"(prctl\(op=PR_CAPBSET_DROP, cap=CAP_[A-Z_]+\) = [0-9]+.*\))",
			R"(prctl\(op=PR_CAPBSET_READ, cap=CAP_[A-Z_]+\) = {bool})",
			R"(prctl\(op=PR_CAP_AMBIENT, subop=PR_CAP_AMBIENT_RAISE, cap=CAP_[A-Z_]+\) = [0-9]+ .*)",
			R"(prctl\(op=PR_CAP_AMBIENT, subop=PR_CAP_AMBIENT_LOWER, cap=CAP_[A-Z_]+\) = 0 \(success\))",
			R"(prctl\(op=PR_CAP_AMBIENT, subop=PR_CAP_AMBIENT_IS_SET, cap=CAP_[A-Z_]+\) = false \(bool\))",
			R"(prctl\(op=PR_CAP_AMBIENT, subop=PR_CAP_AMBIENT_CLEAR_ALL\) = 0 \(success\))",
			R"(prctl\(op=PR_SET_CHILD_SUBREAPER, state={bool}\) = 0 \(success\))",
			R"(prctl\(op=PR_GET_CHILD_SUBREAPER, subreaper={addr} → \[{decimal}\]\) = 0 \(success\))",
			R"(prctl\(op=PR_SET_DUMPABLE, state={bool}\) = 0 \(success\))",
			R"(prctl\(op=PR_GET_DUMPABLE\) = {bool})",
			R"(prctl\(op=PR_GET_IO_FLUSHER\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_IO_FLUSHER, state={bool}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_GET_KEEPCAPS\) = {bool})",
			R"(prctl\(op=PR_SET_KEEPCAPS, state={bool}\) = 0 \(success\))",
			R"(prctl\(op=PR_MCE_KILL, subop=PR_MCE_KILL_CLEAR\) = 0 \(success\))",
			R"(prctl\(op=PR_MCE_KILL, subop=PR_MCE_KILL_SET, policy=PR_MCE_KILL_EARLY\) = 0 \(success\))",
			R"(prctl\(op=PR_MCE_KILL_GET\) = PR_MCE_KILL_EARLY \(policy\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_START_CODE, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_END_CODE, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_START_DATA, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_END_DATA, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_START_STACK, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_START_BRK, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_BRK, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_ARG_START, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_ARG_END, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_ENV_START, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_ENV_END, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_AUXV, addr={addr}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_EXE_FILE, fd={fd}\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_MAP, map=\{start_code={addr}, end_code={addr}, start_data={addr}, end_data={addr}, start_brk={addr}, brk={addr}, start_stack={addr}, arg_start={addr}, arg_end={addr}, env_start={addr}, env_end={addr}, auxv={addr}, auxv_size={decimal}, exe_fd={fd}\}, size={decimal}\) = [0-9]+)",
			/* this can fail with EPERM if CONFIG_CHECKPOINT_RESTORE is not set in the kernel */
			R"(prctl\(op=PR_SET_MM, subop=PR_SET_MM_MAP_SIZE, size={addr} → \[{decimal}\]\) = (0 \(success\)|.*EPERM))",
			R"(prctl\(op=PR_SET_VMA, attr=PR_SET_VMA_ANON_NAME, addr={addr}, size={decimal}, name={string}\) = {decimal})",
#ifndef __SANITIZE_ADDRESS__
			R"(prctl\(op=PR_SET_VMA, attr=PR_SET_VMA_ANON_NAME, addr={addr}, size={decimal}, name=NULL\) = {decimal})",
#endif
			R"(prctl\(op=PR_SET_NAME, name="new name"\) = 0 \(success\))",
			/* avoid internal ASAN BUG */
			R"(prctl\(op=PR_GET_NAME, name="new name"\) = 0 \(success\))",
			R"(prctl\(op=PR_SET_NO_NEW_PRIVS, state={bool}\) = 0 \(success\))",
			R"(prctl\(op=PR_GET_NO_NEW_PRIVS\) = {bool})",
			R"(prctl\(op=PR_SET_PDEATHSIG, signum=SIGSEGV\) = 0)",
			R"(prctl\(op=PR_GET_PDEATHSIG, sig={addr} → \[SIGSEGV\]\) = 0)",
			R"(prctl\(op=PR_SET_PTRACER, pid={pid}\) = 0 \(success\))",
			R"(prctl\(op=PR_SET_PTRACER, pid=PR_SET_PTRACER_ANY\) = 0 \(success\))",
			R"(prctl\(op=PR_GET_SECCOMP\) = 0 \(mode\))",
			R"(prctl\(op=PR_SET_SECCOMP, mode=SECCOMP_MODE_FILTER, filter=\{len={decimal}, filter={addr} → \[\{code=0x0005, jt=0, jf=0, k=0xa\}, \{code=0x0005, jt=0, jf=0, k=0x14\}\]\}\) = 22 \(EINVAL\))",
			R"(prctl\(op=PR_SET_SECUREBITS, bits={hex} \(SECBIT_NOROOT|SECBIT_NO_CAP_AMBIENT_RAISE\)\) = 1 \(EPERM\) \(errno\))",
			R"(prctl\(op=PR_GET_SECUREBITS\) = {hex} \(SECBIT_KEEP_CAPS\) \(bits\))",
			/* in some environments it is forbidden to disable this */
			R"(prctl\(op=PR_SET_SPECULATION_CTRL, misfeature=PR_SPEC_INDIRECT_BRANCH, setting=0x8 \(PR_SPEC_FORCE_DISABLE\)\) = (0 \(success\)|1 \(EPERM\)))",
			R"(prctl\(op=PR_GET_SPECULATION_CTRL, misfeature=PR_SPEC_INDIRECT_BRANCH\) = {hex} \(PR_[A-Z]+.*\) \(setting\))",
			R"(prctl\(op=PR_SET_SYSCALL_USER_DISPATCH, mode=PR_SYS_DISPATCH_ON, offset={addr}, size={decimal}, switch={addr}\) = 0 \(success\))",
			R"(prctl\(op=PR_SET_SYSCALL_USER_DISPATCH, mode=PR_SYS_DISPATCH_OFF\) = 0 \(success\))",

	}},
#ifdef CLUES_HAVE_PIPE1
	TestSpec{{}, "pipe", {
		R"(pipe\(pipefd=0x[0-9a-f]+ → \[[0-9]+, [0-9]+\]\) = 0)"
	}},
#endif
	TestSpec{"pipe", "pipe2", {
		R"(pipe2\(pipefd=0x[0-9a-f]+ → \[[0-9]+, [0-9]+\], flags=0x[0-9a-f]+ \(O_CLOEXEC\|O_DIRECT\)\) = 0)"
	}},
#ifdef CLUES_HAVE_FORK
	TestSpec{{}, "fork", {
		R"(fork\(\) = [0-9])"
	}},
#endif
#ifdef COSMOS_I386
	TestSpec{"getids", "getuid32", {
		R"(getuid32\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "geteuid32", {
		R"(geteuid32\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "getgid32", {
		R"(getgid32\(\) = [0-9]+)"
	}},
	TestSpec{"getids", "getegid32", {
		R"(getegid32\(\) = [0-9]+)"
	}},
	TestSpec{"stat", "oldstat", {
		R"(oldstat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_IFCHR\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, atim=[0-9]+s, mtim=[0-9]+s, ctim=[0-9]+s\}\) = [0-9]+)"
	}},
	TestSpec{"stat", "oldfstat", {
			R"(oldfstat\(fd=[0-9]+, stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, atim=[0-9]+s, mtim=[0-9]+s, ctim=[0-9]+s\}\) = 0)",
	}},
	TestSpec{"stat", "fstat", {
			R"(fstat\(fd=[0-9]+, stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)",
	}},
	TestSpec{"stat", "fstat64", {
			R"(fstat64\(fd=[0-9]+, stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)"
	}},
	TestSpec{"stat", "stat64", {
		R"(stat64\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_IFREG\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = [0-9]+)"
	}},
	TestSpec{"stat", "fstatat64", {
			R"(fstatat64\(fd=[0-9]+, string="os-release", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}, flags=0x800 \(AT_NO_AUTOMOUNT\)\) = 0)",
	}},
	TestSpec{{}, "stat", {
		R"(stat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_IFCHR\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = [0-9]+)"
	}},
	TestSpec{"stat", "lstat", {
			R"(lstat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)"
	}},
	TestSpec{"stat", "lstat64", {
		R"(lstat64\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)"
	}},
	TestSpec{"stat", "oldlstat", {
		R"(oldlstat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, rdev=0x[0-9a-f]+:0x[0-9a-f]+, size=[0-9]+, atim=[0-9]+s, mtim=[0-9]+s, ctim=[0-9]+s\}\) = 0)"
	}},
	/* old mmap call on i386 */
	TestSpec{"mmap", "mmap", {
		R"(mmap\(args=\{hint=0x[0-9a-f]+, length=[0-9a-f]+, prot=0x[0-9a-f]+ \(PROT_READ\|PROT_EXEC\), flags=0x[0-9a-f]+ \(MAP_PRIVATE\|MAP_ANONYMOUS\), fd=-1, offset=[0-9]+\}\) = 0x[0-9a-f]+)"
	}},
	TestSpec{{}, "sigaction", {
		R"(sigaction\(signum=SIGUSR1, sigaction=\{handler=0x[0-9a-f]+, mask=\{SIGCHLD\}, flags=SA_RESETHAND\|SA_RESTART, restorer=NULL\}, old_action=\{handler=SIG_DFL, mask=\{\}, flags=[0-9]+, restorer=NULL\}\) = [0-9]+)"
	}},
	TestSpec{{}, "sigprocmask", {
		R"(sigprocmask\(sigsetop=SIG_BLOCK, new mask=\{SIGUSR1\}, old mask=\{SIGUSR1\}\) = [0-9]+)"
	}},
	TestSpec{"lseek", "llseek", {
		R"(llseek\(fd=[0-9]+, offset=[0-9]+, result=0x[0-9a-f]+ → \[[0-9]+\], whence=SEEK_[A-Z]+\) = 0)"
	}},
#else
	TestSpec{"stat", "fstat", {
			R"(fstat\(fd=[0-9]+, stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)",
	}},
	TestSpec{"stat", "newfstatat", {
			R"(newfstatat\(fd=[0-9]+, string="os-release", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}, flags=0x800 \(AT_NO_AUTOMOUNT\)\) = 0)",
	}},
#	ifdef CLUES_HAVE_LSTAT
	TestSpec{"stat", "lstat", {
			R"(lstat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_[A-Z]+\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = 0)"
	}},
#	endif
#	ifdef CLUES_HAVE_STAT
	TestSpec{{}, "stat", {
		R"(stat\(path="[^"]+", stat=\{ino=[0-9]+, dev=0x[0-9a-f]+:0x[0-9a-f]+, mode=S_IFREG\|0o[0-7]+, nlink=[0-9]+, uid=0, gid=0, size=[0-9]+, blksize=[0-9]+, blocks=[0-9]+, atim=\{[0-9]+s, [0-9]+ns\}, mtim=\{[0-9]+s, [0-9]+ns\}, ctim=\{[0-9]+s, [0-9]+ns\}\}\) = [0-9]+)"
	}}
#	endif
#endif // else I386
};

class TracerSyscallTest : public cosmos::TestBase {
public:

	explicit TracerSyscallTest(const std::vector<TestSpec> &specs) :
			m_specs{std::move(specs)} {
	}

protected:

	void runTests() {
		/* this context on error always makes sense so enable it unconditionally */
		//if (cosmos::proc::get_env_var("CLUES_TEST_PRINT_LINES") != std::nullopt) {
			m_print_lines = true;
		//}

		if (m_argv.size() > 1) {
			m_limit_arg = m_argv[1];
		}

		{
			const auto exe = std::string{m_argv[0]};
			auto test_dir = exe.substr(0, exe.find_last_of("/"));
			m_samples_dir = test_dir + "/samples/";
		}

		for (const auto &spec: m_specs) {
			runSpec(spec);
		}

		// explicitly shut down to prevent a bogus file descriptor
		// leak alarm in TestBase
		m_invoker.shutdown();
	}

	std::string searchReplaceRegEx(std::string regex) {
		/* replace symbolic formatting specifiers by regular
		 * expression syntax */
		for (const auto& [search, replace]: REGEX_SEARCH_REPLACE) {
			for (auto pos = regex.find(search);
					pos != regex.npos;
					pos = regex.find(search, pos)) {
				regex.erase(pos, search.size());
				regex.insert(pos, replace);
			}
		}

		return regex;
	}

	void runSpec(const TestSpec &spec) {
		std::string label = std::string{spec.label};
		if (label.empty()) {
			label = spec.filter + "()";
		}

		if (!m_limit_arg.empty() && label.find(m_limit_arg) != 0) {
			// skip non-matching test case
			return;
		}

		START_TEST(std::string{label});
		const auto exe = findSample(spec.sample_cmdline.empty() ? spec.filter : spec.sample_cmdline[0]);
		std::vector<std::string> args;
		if (!spec.filter.empty()) {
			args.push_back("-e");
			args.push_back(spec.filter);
		}
		args.push_back("--");
		args.push_back(exe);
		for (auto it = spec.sample_cmdline.begin() + 1; it < spec.sample_cmdline.end(); it++) {
			args.push_back(*it);
		}

		std::vector<bool> matches;
		matches.resize(spec.exprs.size());
		std::vector<std::regex> regexps;
		for (const auto &expr: spec.exprs) {
			try {
				const auto replaced_expr = searchReplaceRegEx(expr);
				regexps.push_back(std::regex{replaced_expr});
			} catch (std::exception &ex) {
				std::cerr << std::format("Failed to compute regular expression '{}': {}", expr, ex.what()) << "\n";
				RUN_STEP("build regex", false);
			}
		}
		size_t num_found = 0;

		auto parser = [&matches, &regexps, &num_found, this](const std::string &line) {
			if (num_found == regexps.size())
				return;

			if (m_print_lines) {
				m_lines.push_back(line);
			}

			for (size_t i = 0; i < regexps.size(); i++) {
				if (matches[i])
					continue;

				if (std::regex_search(line, regexps[i])) {
					matches[i] = true;
					num_found++;
					return;
				}
			}
		};

		std::cout << "running 'clues ";
		for (const auto &arg: args) {
			std::cout << arg << " ";
		}
		std::cout << "'\n";
		m_lines.clear();
		m_invoker.run(args, parser);

		for (size_t i = 0; i < matches.size(); i++) {
			if (!matches[i]) {
				for (const auto &line: m_lines) {
					std::cerr << "> " << line << "\n";
				}
			}
			RUN_STEP(cosmos::sprintf("regexp '%s' found", spec.exprs[i].c_str()), matches[i] == true);
		}
	}

	std::string findSample(const std::string_view sample) {
		auto path = m_samples_dir + std::string{sample};

		if (!cosmos::fs::exists_file(path)) {
			throw cosmos::RuntimeError{cosmos::sprintf("Could not find sample program at %s", path.c_str())};
		}

		return path;
	}

	std::string m_samples_dir;
	TracerInvoker m_invoker;
	const std::vector<TestSpec> m_specs;
	std::vector<std::string> m_lines;
	bool m_print_lines = false;
	// only run test cases matching this label
	std::string m_limit_arg;
};

} // end anon ns

int main(const int argc, const char **argv) {
	TracerSyscallTest test{TEST_SPECS};
	return test.run(argc, argv);
}
