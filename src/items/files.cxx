// C++
#include <sstream>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>

// clues
#include <clues/items/files.hxx>

namespace clues::item {

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


} // end ns
