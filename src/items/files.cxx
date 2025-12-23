// C++
#include <sstream>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>

// clues
#include <clues/items/files.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string FileDescriptor::str() const {
	const auto fd = valueAs<cosmos::FileNum>();

	if (m_at_semantics && fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";
	else
		return std::to_string(cosmos::to_integral(fd));
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

} // end ns
