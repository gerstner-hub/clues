// C++
#include <iostream>

// clues
#include <clues/utils.hxx>

// generated
#include <clues/errnodb.hxx>
#include <clues/logger.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/DirStream.hxx>
#include <cosmos/io/ILogger.hxx>
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

} // end ns
