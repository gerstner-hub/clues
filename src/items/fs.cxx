// C++
#include <sstream>

// cosmos
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/Tracee.hxx>
#include <clues/items/fs.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/macros.h>
#include <clues/syscalls/fs.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/private/utils.hxx>

namespace clues::item {

std::string FileDescriptor::str() const {
	const auto fd = valueAs<cosmos::FileNum>();

	if (m_at_semantics && fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";
	else
		return std::to_string(cosmos::to_integral(fd));
}

std::string OpenFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	switch (m_mode) {
		default: BITFLAGS_STREAM() << "O_???"; break;
		case cosmos::OpenMode::READ_ONLY:  BITFLAGS_STREAM() << "O_RDONLY"; break;
		case cosmos::OpenMode::WRITE_ONLY: BITFLAGS_STREAM() << "O_WRONLY"; break;
		case cosmos::OpenMode::READ_WRITE: BITFLAGS_STREAM() << "O_RDWR"; break;
	}

	BITFLAGS_STREAM() << '|';

	// TODO: O_LARGEFILE might not be visible for 32-bit emulation
	// binaries, since on x86_64 the constant is set to 0.

	BITFLAGS_ADD(O_APPEND);
	BITFLAGS_ADD(O_ASYNC);
	BITFLAGS_ADD(O_CLOEXEC);
	BITFLAGS_ADD(O_CREAT);
	BITFLAGS_ADD(O_DIRECT);
	BITFLAGS_ADD(O_DIRECTORY);
	BITFLAGS_ADD(O_DSYNC);
	BITFLAGS_ADD(O_EXCL);
	BITFLAGS_ADD(O_LARGEFILE);
	BITFLAGS_ADD(O_NOATIME);
	BITFLAGS_ADD(O_NOCTTY);
	BITFLAGS_ADD(O_NOFOLLOW);
	BITFLAGS_ADD(O_NONBLOCK);
	BITFLAGS_ADD(O_PATH);
	BITFLAGS_ADD(O_SYNC);
	BITFLAGS_ADD(O_TMPFILE);
	BITFLAGS_ADD(O_TRUNC);

	return BITFLAGS_STR();
}

void OpenFlagsValue::processValue(const Tracee &) {
	const auto raw = valueAs<int>();
	// the access mode consists of the lower two bits
	m_mode = cosmos::OpenMode{raw & 0x3};
	m_flags = cosmos::OpenFlags{raw & ~0x3};
}

std::string AtFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(AT_EMPTY_PATH);
	BITFLAGS_ADD(AT_SYMLINK_NOFOLLOW);
	BITFLAGS_ADD(AT_SYMLINK_FOLLOW);
	/*
	 * some AT_ constants share the same values and are system call
	 * dependent, thus we need to check the context here.
	 */
	if (m_call->callNr() == SystemCallNr::UNLINKAT)
		BITFLAGS_ADD(AT_REMOVEDIR);
	if (m_call->callNr() == SystemCallNr::FACCESSAT2)
		BITFLAGS_ADD(AT_EACCESS);

	return BITFLAGS_STR();
}

void AtFlagsValue::processValue(const Tracee&) {
	m_flags = AtFlags{valueAs<int>()};
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

	if (mode.none()) {
		return "0";
	}

	auto chk_mode_flag = [&ss, mode](const cosmos::FileModeBit bit, const char *ch) {
		if (mode[bit])
			ss << ch;
		else
			ss << '-';
	};

	ss << "0" << std::oct << valueAs<mode_t>() << " (";

	using cosmos::FileModeBit;

	// TODO: proper output format for the special bits like `ls` does it
	// is to replace the `x` either by lower case or upper case `s` or
	// `t`, depending on whether `x` is also set, or not.
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

} // end ns
