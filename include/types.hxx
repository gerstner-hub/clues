#pragma once

// Linux
#include <sys/procfs.h> // the elf_greg_t & friends are in here

// C++
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

// cosmos
#include <cosmos/utils.hxx>
#include <cosmos/fs/types.hxx>

namespace clues {

/*
 * some general types used across Clues
 */

/// A strong boolean type denoting whether to automatically attach to newly created child processes.
using FollowChildren = cosmos::NamedBool<struct follow_children_t, true>;

/// A strong boolean type denoting whether to automatically all other threads of a process.
using AttachThreads = cosmos::NamedBool<struct attach_threads_t, true>;

class Tracee;

using TraceePtr = std::shared_ptr<Tracee>;

class ProcessData;

using ProcessDataPtr = std::shared_ptr<ProcessData>;

/// An integer that is able to hold a word for the current architecture.
enum class Word : elf_greg_t {
	ZERO = 0
};

/// Errno values that can appear in tracing context.
/**
 * these errno values can appear for interrupted system calls and are not
 * usually visible in user space, but can be observed when tracing a process.
 * There is currently no user space header for these constants, they are found
 * in the kernel header linux/errno.h.
 **/
enum class KernelErrno : int {
	RESTART_SYS          = 512, /* transparent restart if SA_RESTART is set, otherwise EINTR return */
	RESTART_NOINTR       = 513, /* always transparent restart */
	RESTART_NOHAND       = 514, /* restart if no handler.. */
	RESTART_RESTARTBLOCK = 516, /* restart by calling sys_restart_syscall */
};

/// System Call ABI
/**
 * This is mostly similar to cosmos::ptrace::Arch, but contains some extra
 * differentiation. E.g. on Arch::X86_64 there is also the X32 ABI, which can
 * only be detected by querying a special bit set in the system call nr.
 **/
enum class ABI {
	UNKNOWN,
	X86_64,
	I386,
	X32,    ///< X86_64 with 32-bit pointers
	AARCH64
};

/// Contextual information about a file descriptor in a Tracee.
/**
 * \todo For a fully-fledged implementation we will likely need specialized
 * types e.g. for sockets, carrying additional context-sensitive data.
 **/
struct FDInfo {
public: // types

	/// Different types of file descriptors.
	/**
	 * This distinguishes file types found in /proc/<pid>/fd. These are
	 * types more from a kernel point of view, i.e. the different kernel
	 * facilities that offer file descriptors, not the types from a
	 * stat(2) point of view. Directories, regular files and device files
	 * are all of Type::FS_PATH, for example.
	 **/
	enum class Type {
		INVALID,
		FS_PATH, ///< a path opened on the file system (this can still be a device special file, named pipe, directory etc.)
		EVENT_FD, ///< created by `eventfd()`
		TIMER_FD, ///< created by `timerfd()`
		SIGNAL_FD, ///< created by `signalfd()`
		SOCKET, ///< created by `socket()`
		EPOLL, ///< an epoll() file descriptor
		PIPE, ///< created by `pipe()`
		INOTIFY, ///< created by `inotify_init()`
		PID_FD, ///< created by `pidfd_open()`, `clone()`, ...
		BPF_MAP, ///< refers to a BPF type map
		BPF_PROG, ///< refers to a BPF program validated and loaded
		PERF_EVENT,
		UNKNOWN
	};

public: // functions

	FDInfo() = default;

	explicit FDInfo(const Type _type, const cosmos::FileNum _fd) :
		type{_type}, fd{_fd} {
	}

	bool valid() const {
		return type != Type::INVALID;
	}

public: // data

	Type type = Type::INVALID;
	cosmos::FileNum fd = cosmos::FileNum::INVALID; ///< the actual file descriptor number.
	std::string path; ///< path to the file, if applicable
	std::optional<cosmos::OpenMode> mode;
	std::optional<cosmos::OpenFlags> flags;
	std::optional<cosmos::Inode> inode; ///< inode of the file, only filled by utils::get_fd_infos().
};

/// A mapping of file descriptor numbers to their file system paths or other human readable description of the descriptor.
using FDInfoMap = std::map<cosmos::FileNum, FDInfo>;

/// Integer number display base for formatting purposes.
enum class Base {
	OCT,
	DEC,
	HEX
};

/// Strongly typed opaque pointer to tracee memory.
/**
 * This type is used to prevent pointers related to tracee memory from being
 * mistaken for proper pointers in tracer context.
 **/
enum class ForeignPtr : uintptr_t {
	NO_POINTER = 0
};

} // end ns
