// C++
#include <iostream>
#include <fstream>

// clues
#include <clues/utils.hxx>

// generated
#include <clues/errnodb.hxx>
#include <clues/logger.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/DirStream.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/File.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/io/StreamAdaptor.hxx>
#include <cosmos/string.hxx>
#include <cosmos/utils.hxx>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || static_cast<size_t>(num) >= ERRNO_NAMES.size())
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

const char* get_kernel_errno_label(const KernelErrno err) {
	switch (err) {
	case KernelErrno::RESTART_SYS: return "RESTART_SYS";
	case KernelErrno::RESTART_NOINTR: return "RESTART_NOINTR";
	case KernelErrno::RESTART_NOHAND: return "RESTART_NOHAND";
	case KernelErrno::RESTART_RESTARTBLOCK: return "RESTART_RESTARTBLOCK";
	default: return "?INVALID?";
	}
}

const char* get_ptrace_event_str(const cosmos::ptrace::Event event) {
	using Event = cosmos::ptrace::Event;
	switch (event) {
		case Event::VFORK: return "VFORK";
		case Event::FORK: return "FORK";
		case Event::CLONE: return "CLONE";
		case Event::VFORK_DONE: return "VFORK_DONE";
		case Event::EXEC: return "EXEC";
		case Event::EXIT: return "EXIT";
		case Event::STOP: return "STOP";
		case Event::SECCOMP: return "SECCOMP";
		default: return "??? unknown ???";
	}
}

std::set<cosmos::FileNum> get_currently_open_fds(const cosmos::ProcessID pid) {
	std::set<cosmos::FileNum> ret;

	try {
		cosmos::DirStream dir{
			cosmos::sprintf("/proc/%d/fd", cosmos::to_integral(pid))};

		for (const auto &entry: dir) {
			if (entry.isDotEntry())
				continue;

			try {
				auto fd = std::stoi(entry.name());
				ret.insert(cosmos::FileNum{fd});
			} catch (...) {
				// not a number? shouldn't happen.
			}
		}
	} catch (const cosmos::ApiError &ex) {
		// process disappeared? let the caller handle that.
		throw;
	}

	return ret;
}

namespace {

FDInfo::Type to_fd_info_type(const std::string &type) {
	using Type = FDInfo::Type;
	if (type == "pipe")
		return Type::PIPE;
	else if (type == "socket")
		return Type::SOCKET;
	else if (type == "eventfd")
		return Type::EVENT_FD;
	else if (type == "eventpoll")
		return Type::EPOLL;
	else if (type == "pidfd")
		return Type::PID_FD;
	else if (type == "signalfd")
		return Type::SIGNAL_FD;
	else if (type == "timerfd")
		return Type::TIMER_FD;
	else if (type == "inotify")
		return Type::INOTIFY;
	// TODO: the following strings have not been verified during runtime
	else if (type == "bpf")
		return Type::BPF;
	else if (type == "perfevent")
		return Type::PERF_EVENT;

	LOG_WARN("Unknown /proc/<pid>/fd file type '" << type << "' encountered");
	return Type::UNKNOWN;
}

/// Parse the /proc/<pid>/fd type information found in `type_info` into `info`
/**
 * This fills `info.type`, possibly `info.path` and `info.inode`. The return
 * value indicates parsing success or failure.
 **/
bool parse_type_info(const std::string &type_info, FDInfo &info) {

	if (!type_info.empty() && type_info[0] == '/') {
		// this means it is a regular path
		info.path = type_info;
		info.type = FDInfo::Type::FS_PATH;
		// for regular paths the inode information is not readily
		// available, and we don't want to `stat()` just for this now.
		info.inode.reset();
		return true;
	}

	// see `man proc_pid_fd` for details about what to expect in `type_info`
	auto parts = cosmos::split(type_info, ":", cosmos::SplitFlags{}, 1);
	if (parts.size() != 2) {
		return false;
	}

	if (auto type = parts[0]; type == "anon_inode") {
		// format is "anon_inode:[<type>]
		// where the square brackets are not always present
		auto real_type = cosmos::stripped(parts[1], "[]");
		info.type = to_fd_info_type(real_type);
	} else {
		info.type = to_fd_info_type(type);
		// format is "<type>:[<inode>]"
		const auto inode_str = cosmos::stripped(parts[1], "[]");

		try {
			auto inode = std::stoul(inode_str);
			info.inode = cosmos::Inode{inode};
		} catch (...) {
			// not a number? shouldn't happen.
			LOG_WARN(__FUNCTION__ << ": non-numerical inode \""
					<< inode_str << "\"?!");
			return false;
		}
	}

	return true;
}

/// Parse additional file descriptor info from /proc/<pid>/fdinfo into `info`
/**
 * This function looks up the `fdinfo` for `info.fd` and assigns `info.mode`
 * and `info.flags`. This may throw a cosmos::ApiError in case accessing the
 * /proc file system fails, or cosmos::RuntimeError on unexpected parsing
 * errors.
 **/
void parse_fd_info(const cosmos::ProcessID pid, FDInfo &info) {
	cosmos::File fdinfo{
		cosmos::sprintf("/proc/%d/fdinfo/%d",
			cosmos::to_integral(pid),
			cosmos::to_integral(info.fd)),
		cosmos::OpenMode::READ_ONLY
	};

	cosmos::InputStreamAdaptor fdinfo_stream{fdinfo};

	std::string line;
	while (std::getline(fdinfo_stream, line).good()) {
		auto parts = cosmos::split(line, ":",
			cosmos::SplitFlag::STRIP_PARTS,
			1);
		if (parts.size() != 2)
			continue;
		else if (parts[0] != "flags")
			continue;

		// the flags are in octal. potential exception is handled by caller
		auto raw_flags = std::stoi(parts[1], nullptr, 8);
		const cosmos::OpenMode mode{
			raw_flags & (O_RDONLY|O_WRONLY|O_RDWR)};
		const cosmos::OpenFlags flags{
			raw_flags & ~(cosmos::to_integral(mode))};
		info.mode = mode;
		info.flags = flags;
		return;
	}

	throw cosmos::RuntimeError{"no flags found"};
}

} // end anon ns

std::vector<FDInfo> get_fd_infos(const cosmos::ProcessID pid) {
	std::vector<FDInfo> ret;
	cosmos::DirStream dir;
	const auto proc_pid_fd = cosmos::sprintf("/proc/%d/fd",
			cosmos::to_integral(pid));

	try {
		dir.open(proc_pid_fd);
	} catch (const cosmos::ApiError &ex) {
		// process disappeared? let caller handle this
		throw;
	}

	for (const auto &entry: dir) {
		if (entry.isDotEntry())
			continue;

		FDInfo info;

		try {
			auto fd = std::stoi(entry.name());
			info.fd = cosmos::FileNum{fd};
		} catch (...) {
			// not a number? shouldn't happen.
			LOG_WARN(__FUNCTION__ << ": " << proc_pid_fd
					<< " non-numerical entry "
					<< entry.name() << "?!");
			continue;
		}

		try {
			auto type_info = cosmos::fs::read_symlink_at(
					dir.fd(),
					entry.name());

			if (!parse_type_info(type_info, info)) {
				LOG_WARN(__FUNCTION__ << ": " << proc_pid_fd
						<< " failed to parse type info \""
						<< type_info << "\"");
				continue;
			}
		} catch (const std::exception &ex) {
			LOG_WARN(__FUNCTION__ << ": " << proc_pid_fd
					<< " failed to read symlink: "
					<< ex.what());
		}

		try {
			parse_fd_info(pid, info);
		} catch (const std::exception &ex) {
			LOG_WARN(__FUNCTION__ << ": " << proc_pid_fd
					<< " failed to read fdinfo: "
					<< ex.what());
		}

		ret.push_back(info);
	}

	return ret;
}

} // end ns
