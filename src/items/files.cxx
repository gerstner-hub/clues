// C++
#include <sstream>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>

// clues
#include <clues/items/files.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/macros.h>
#include <clues/syscalls/fs.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

namespace {

std::string strip_back(std::string &&s, const char ch = '|') {
	if (s.back() == ch)
		s.pop_back();
	return s;
}

} // end anon ns

std::string FileDescriptor::str() const {
	const auto fd = valueAs<cosmos::FileNum>();

	if (m_at_semantics && fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";
	else
		return std::to_string(cosmos::to_integral(fd));
}

#define add_bitflag(FLAG) if (m_flags.raw() & FLAG) ss << #FLAG << '|';

std::string OpenFlagsValue::str() const {
	std::stringstream ss;

	const auto flags = valueAs<int>();

	ss << "0x" << std::hex << flags << " (";

	switch (m_mode) {
		default: ss << "O_???"; break;
		case cosmos::OpenMode::READ_ONLY: ss << "O_RDONLY"; break;
		case cosmos::OpenMode::WRITE_ONLY: ss << "O_WRONLY"; break;
		case cosmos::OpenMode::READ_WRITE: ss << "O_RDWR"; break;
	}

	if (m_flags.any()) {
		ss << '|';
	}

	add_bitflag(O_APPEND);
	add_bitflag(O_ASYNC);
	add_bitflag(O_CLOEXEC);
	add_bitflag(O_CREAT);
	add_bitflag(O_DIRECT);
	add_bitflag(O_DIRECTORY);
	add_bitflag(O_DSYNC);
	add_bitflag(O_EXCL);
	add_bitflag(O_LARGEFILE);
	add_bitflag(O_NOATIME);
	add_bitflag(O_NOCTTY);
	add_bitflag(O_NOFOLLOW);
	add_bitflag(O_NONBLOCK);
	add_bitflag(O_PATH);
	add_bitflag(O_SYNC);
	add_bitflag(O_TMPFILE);
	add_bitflag(O_TRUNC);

	return strip_back(ss.str()) + ")";
}

void OpenFlagsValue::processValue(const Tracee &) {
	const auto raw = valueAs<int>();
	// the access mode consists of the lower two bits
	m_mode = cosmos::OpenMode{raw & 0x3};
	m_flags = cosmos::OpenFlags{raw & ~0x3};
}

std::string AtFlagsValue::str() const {
	std::stringstream ss;

	ss << "0x" << std::hex << m_flags.raw() << " (";

	add_bitflag(AT_EMPTY_PATH);
	add_bitflag(AT_SYMLINK_NOFOLLOW);
	add_bitflag(AT_SYMLINK_FOLLOW);
	/*
	 * some AT_ constants share the same values and are system call
	 * dependent, thus we need to check the context here.
	 */
	if (m_call->callNr() == SystemCallNr::UNLINKAT)
		add_bitflag(AT_REMOVEDIR);
	if (m_call->callNr() == SystemCallNr::FACCESSAT2)
		add_bitflag(AT_EACCESS);

	return strip_back(ss.str()) + ")";
}

void AtFlagsValue::processValue(const Tracee&) {
	m_flags = AtFlags{valueAs<int>()};
}

std::string FileDescFlagsValue::str() const {
	std::stringstream ss;

	ss << "0x" << std::hex << m_flags.raw() << " (";

	add_bitflag(FD_CLOEXEC);

	return strip_back(ss.str()) + ")";
}

void FileDescFlagsValue::processValue(const Tracee &) {
	if (!isOut()) {
		m_flags = cosmos::FileDescriptor::DescFlags{valueAs<int>()};
	}
}

void FileDescFlagsValue::updateData(const Tracee &) {
	m_flags = cosmos::FileDescriptor::DescFlags{valueAs<int>()};
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
		return "???";
	}

	return strip_back(std::move(ret));
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

	ss
		<< "{"
		<< "st_size=" << m_stat->st_size << ", "
		<< "st_dev=" << m_stat->st_dev
		<< "}";

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

std::string DirEntries::str() const {
	std::stringstream ss;
	auto result = m_call->result();

	if (!result) {
		ss << "undefined";
	} else if (const auto size = result->valueAs<int>(); size == 0) {
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
	auto result = m_call->result();
	if (!result)
		// error occurred
		return;

	const auto bytes = result->valueAs<size_t>();
	if (bytes == 0)
		// empty
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

void FcntlOperation::processValue(const Tracee &) {
	m_op = valueAs<Oper>();
}

std::string FcntlOperation::str() const {
	if (!m_op) {
		throw cosmos::RuntimeError{"no operation stored"};
	}

	switch (cosmos::to_integral(*m_op)) {
		CASE_ENUM_TO_STR(F_DUPFD);
		CASE_ENUM_TO_STR(F_DUPFD_CLOEXEC);
		CASE_ENUM_TO_STR(F_GETFD);
		CASE_ENUM_TO_STR(F_SETFD);
		CASE_ENUM_TO_STR(F_GETFL);
		CASE_ENUM_TO_STR(F_SETFL);
		CASE_ENUM_TO_STR(F_SETLK);
		CASE_ENUM_TO_STR(F_SETLKW);
		CASE_ENUM_TO_STR(F_GETLK);
		CASE_ENUM_TO_STR(F_OFD_SETLK);
		CASE_ENUM_TO_STR(F_OFD_SETLKW);
		CASE_ENUM_TO_STR(F_OFD_GETLK);
		CASE_ENUM_TO_STR(F_GETOWN);
		CASE_ENUM_TO_STR(F_SETOWN);
		CASE_ENUM_TO_STR(F_GETOWN_EX);
		CASE_ENUM_TO_STR(F_SETOWN_EX);
		CASE_ENUM_TO_STR(F_GETSIG);
		CASE_ENUM_TO_STR(F_SETSIG);
		CASE_ENUM_TO_STR(F_SETLEASE);
		CASE_ENUM_TO_STR(F_GETLEASE);
		CASE_ENUM_TO_STR(F_NOTIFY);
		CASE_ENUM_TO_STR(F_SETPIPE_SZ);
		CASE_ENUM_TO_STR(F_GETPIPE_SZ);
		CASE_ENUM_TO_STR(F_ADD_SEALS);
		CASE_ENUM_TO_STR(F_GET_SEALS);
		CASE_ENUM_TO_STR(F_GET_RW_HINT);
		CASE_ENUM_TO_STR(F_SET_RW_HINT);
		CASE_ENUM_TO_STR(F_GET_FILE_RW_HINT);
		CASE_ENUM_TO_STR(F_SET_FILE_RW_HINT);
		default: return "???";
	}
}

void FLockParameter::processValue(const Tracee &proc) {
	/* all flock related operations provide input, so unconditionally
	 * process it */

	// TODO: handle flock32 case on i386 & friends

	clues::flock64 lock;

	if (!proc.readStruct(m_val, lock)) {
		m_lock.reset();
		return;
	}

	if (!m_lock) {
		m_lock = std::make_optional<cosmos::FileLock>(cosmos::FileLock::Type::READ_LOCK);
	}

	m_lock->l_type = lock.l_type;
	m_lock->l_whence = lock.l_whence;
	m_lock->l_start = lock.l_start;
	m_lock->l_len = lock.l_len;
	m_lock->l_pid = lock.l_pid;
}

void FLockParameter::updateData(const Tracee &proc) {
	const auto fcntl_sc = dynamic_cast<const FcntlSystemCall*>(m_call);
	if (!fcntl_sc || fcntl_sc->operation.operation() != item::FcntlOperation::Oper::GETLK) {
		// only the F_GETLK operation causes changes on output
		return;
	}

	processValue(proc);
}

std::string FLockParameter::str() const {
	auto type_str = [](short type) {
		switch(type) {
			CASE_ENUM_TO_STR(F_RDLCK);
			CASE_ENUM_TO_STR(F_WRLCK);
			CASE_ENUM_TO_STR(F_UNLCK);
			default: return "???";
		}
	};

	auto whence_str = [](short whence) {
		switch(whence) {
			CASE_ENUM_TO_STR(SEEK_SET);
			CASE_ENUM_TO_STR(SEEK_CUR);
			CASE_ENUM_TO_STR(SEEK_END);
			default: return "???";
		}
	};

	return cosmos::sprintf("{l_type=%s, l_whence=%s, l_start=%ld, l_len=%ld, l_pid=%d}",
			type_str(cosmos::to_integral(m_lock->type())),
			whence_str(cosmos::to_integral(m_lock->whence())),
			m_lock->start(),
			m_lock->start(),
			cosmos::to_integral(m_lock->pid())
	);
}

void FileDescOwner::processValue(const Tracee &) {
	const auto pid_or_pgid = valueAs<int>();

	if (pid_or_pgid >= 0) {
		m_pgid.reset();
		m_pid = cosmos::ProcessID{pid_or_pgid};
		m_short_name = "pid";
		m_long_name = "process id";
	} else {
		m_pid.reset();
		m_pgid = cosmos::ProcessGroupID{-pid_or_pgid};
		m_short_name = "pgid";
		m_long_name = "process group id";
	}
}

void FileDescOwner::updateData(const Tracee &proc) {
	if (isReturnValue())
		return processValue(proc);
}

std::string FileDescOwner::str() const {
	if (m_pid)
		return std::to_string(cosmos::to_integral(*m_pid));
	else
		return std::to_string(cosmos::to_integral(*m_pgid));
}

} // end ns
