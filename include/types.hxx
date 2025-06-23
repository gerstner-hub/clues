#pragma once

// Linux
#include <sys/procfs.h> // the elf_greg_t & friends are in here

// C++
#include <cstdint>
#include <map>
#include <memory>
#include <string>

// cosmos
#include <cosmos/utils.hxx>

namespace clues {

/*
 * some general types used across Clues
 */

/// A strong boolean type denoting whether to automatically attach to newly created child processes.
using FollowChilds = cosmos::NamedBool<struct follow_childs_t, true>;

/// A strong boolean type denoting whether to automatically all other threads of a process.
using AttachThreads = cosmos::NamedBool<struct attach_threads_t, true>;

class Tracee;

using TraceePtr = std::shared_ptr<Tracee>;

/// A mapping of file descriptor numbers to their file system paths or other human readable description of the descriptor.
using DescriptorPathMapping = std::map<int, std::string>;

class ProcessData;

using ProcessDataPtr = std::shared_ptr<ProcessData>;

/// An integer that is able to hold a word for the current architecture.
enum class Word : elf_greg_t {
	ZERO = 0
};

// forward declaration
enum class SystemCallNr : uint64_t;

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

} // end ns
