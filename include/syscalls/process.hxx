#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/fs/types.hxx>

// clues
#include <clues/dso_export.h>
#include <clues/items/clone.hxx>
#include <clues/items/creds.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/items.hxx>
#include <clues/items/process.hxx>
#include <clues/items/strings.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

/// Wrapper for the clone() and clone2() system calls.
/**
 * For clone3() a separate wrapper type is used, since the two variants of
 * clone system calls differ too much from each other.
 **/
struct CloneSystemCall :
		public SystemCall {

	CloneSystemCall() :
			SystemCall{SystemCallNr::CLONE},
			stack{"stack", "stack address"},
			new_pid{ItemType::RETVAL, "child pid"} {
		setReturnItem(new_pid);
		setParameters(flags, stack);
	}

	/* fixed parameters */
	item::CloneFlagsValue flags;
	item::GenericPointerValue stack;

	/* optional parameters */

	/* the following two are based on the same `parent_tid` pointer argument */

	/// TID of the new child written out to a pid_t* in the parent.
	/**
	 * This is only filled in if CLONE_PARENT_SETTID is set.
	 **/
	std::optional<item::PointerToScalar<cosmos::ProcessID>> parent_tid;
	/// PID file descriptor referring to the new child.
	/**
	 * This is only filled in if CLONE_PIDFD is set.
	 **/
	std::optional<item::PointerToScalar<cosmos::FileNum>> pidfd;

	/// TID of the new child written out to a pid_* in the child.
	/**
	 * This is only filled in if CLONE_CHILD_SETTID is set.
	 *
	 * This is only placed into the child's memory, not to the parent's.
	 * Thus we have no reliable way of retrieving the value, which is why
	 * we're not using `PointerToScalar` here.
	 **/
	std::optional<item::GenericPointerValue> child_tid;
	/// Thread-local-storage data for the new child.
	/**
	 * This is only filled in if CLONE_SETTLS is set.
	 *
	 * The interpretation is highly ABI-specific, which is why we
	 * currently model it generically as a pointer.
	 **/
	std::optional<item::GenericPointerValue> tls;

	/* return value */

	/// The new child's PID.
	item::ProcessID new_pid;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

struct Clone3SystemCall :
		public SystemCall {
	Clone3SystemCall() :
			SystemCall{SystemCallNr::CLONE3},
       			size{"size", "cl_args structure size"},
			pid{ItemType::RETVAL, "child pid"} {
		setParameters(cl_args, size);
		setReturnItem(pid);
	}

	/// Combined clone arguments.
	item::CloneArgs cl_args;
	/// Size of the CloneArgs structure argument in `cl_args`.
	item::SizeValue size;
	/// New child's PID or zero if executing in child context.
	item::ProcessID pid;

protected: // functions

	void updateFDTracking(const Tracee &proc) override;
};

struct ForkSystemCall :
		public SystemCall {

	ForkSystemCall() :
			SystemCall{SystemCallNr::FORK},
			pid{ItemType::RETVAL, "child pid"} {
		setReturnItem(pid);
	}

	item::ProcessID pid;
};

struct ExecveSystemCall :
		public SystemCall {

	ExecveSystemCall() :
			SystemCall{SystemCallNr::EXECVE},
			pathname{"filename"},
			argv{"argv", "argument vector"},
			envp{"envp", "environment block pointer"} {
		setReturnItem(result);
		setParameters(pathname, argv, envp);
	}

	item::StringData pathname;
	item::StringArrayData argv;
	item::StringArrayData envp;
	item::SuccessResult result;
};

struct ExecveAtSystemCall :
		public SystemCall {

	ExecveAtSystemCall() :
			SystemCall{SystemCallNr::EXECVEAT},
			dirfd{ItemType::PARAM_IN, item::AtSemantics{true}},
			pathname{"filename"},
			argv{"argv", "argument vector"},
			envp{"envp", "environment block pointer"} {
		setReturnItem(result);
		setParameters(dirfd, pathname, argv, envp, flags);
	}

	item::FileDescriptor dirfd;
	item::StringData pathname;
	item::StringArrayData argv;
	item::StringArrayData envp;
	item::AtFlagsValue flags;
	item::SuccessResult result;
};

template <typename ID_T>
/// Template for get*id() system calls returning user/group/process/thread IDs.
/**
 * This template is used generally for system calls taking no argument and
 * returning an identifier related to the caller's context like the
 * real/effective user/group ID, the process ID, the process group ID, the
 * thread ID etc.
 *
 * `using` declarations for concrete types are provided like GetUIDSystemCall
 * and so on.
 **/
struct GetXIDSystemCall :
		public SystemCall {

	GetXIDSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			id{ItemType::RETVAL, getShortLabel(), getLongLabel()} {
		setReturnItem(id);
	}

	/// the UserID or GroupID
	ID_T id;

protected:

	const char* getShortLabel() {
		switch (callNr()) {
			case SystemCallNr::GETUID32:  [[fallthrough]];
			case SystemCallNr::GETUID:    return "uid";
			case SystemCallNr::GETEUID32: [[fallthrough]];
			case SystemCallNr::GETEUID:   return "euid";
			case SystemCallNr::GETGID32:  [[fallthrough]];
			case SystemCallNr::GETGID:    return "gid";
			case SystemCallNr::GETEGID32: [[fallthrough]];
			case SystemCallNr::GETEGID:   return "egid";
			case SystemCallNr::GETPID:    return "pid";
			case SystemCallNr::GETPPID:   return "pid";
			case SystemCallNr::GETTID:    return "tid";
			case SystemCallNr::GETPGID:   return "pgid";
			case SystemCallNr::GETSID:    return "sid";
			default: return "???";
		}
	}

	const char* getLongLabel() {
		switch (callNr()) {
			case SystemCallNr::GETUID32:  [[fallthrough]];
			case SystemCallNr::GETUID:    return "real user ID";
			case SystemCallNr::GETEUID32: [[fallthrough]];
			case SystemCallNr::GETEUID:   return "effective user ID";
			case SystemCallNr::GETGID32:  [[fallthrough]];
			case SystemCallNr::GETGID:    return "real group ID";
			case SystemCallNr::GETEGID32: [[fallthrough]];
			case SystemCallNr::GETEGID:   return "effective group ID";
			case SystemCallNr::GETPID:    return "own process ID";
			case SystemCallNr::GETPPID:   return "parent process ID";
			case SystemCallNr::GETTID:    return "own thread ID";
			case SystemCallNr::GETPGID:   return "own process group ID";
			case SystemCallNr::GETSID:    return "own session ID";
			default: return "???";
		}
	}
};

using GetUIDSystemCall  = GetXIDSystemCall<item::UserID>;
using GetEUIDSystemCall = GetXIDSystemCall<item::UserID>;
using GetGIDSystemCall  = GetXIDSystemCall<item::GroupID>;
using GetEGIDSystemCall = GetXIDSystemCall<item::GroupID>;
using GetPIDSystemCall  = GetXIDSystemCall<item::ProcessID>;
using GetPPIDSystemCall = GetXIDSystemCall<item::ProcessID>;
using GetTIDSystemCall  = GetXIDSystemCall<item::ThreadID>;

struct GetPGIDSystemCall :
		GetXIDSystemCall<item::ProcessGroupID> {
	explicit GetPGIDSystemCall() :
			GetXIDSystemCall{SystemCallNr::GETPGID},
			pid{ItemType::PARAM_IN} {
		setParameters(pid);
	}

	item::ProcessID pid; ///< the PID to get the process group ID for.
};

struct GetSIDSystemCall :
		GetXIDSystemCall<item::SessionID> {
	explicit GetSIDSystemCall() :
			GetXIDSystemCall{SystemCallNr::GETSID},
			pid{ItemType::PARAM_IN} {
		setParameters(pid);
	}

	item::ProcessID pid; ///< the PID to get the session ID for.
};

struct SetSIDSystemCall :
		public SystemCall {
	explicit SetSIDSystemCall() :
			SystemCall{SystemCallNr::SETSID},
			new_sid{ItemType::RETVAL} {
		setReturnItem(new_sid);
	}

	item::SessionID new_sid;
};

struct Wait4SystemCall :
		public SystemCall {
	Wait4SystemCall() :
			SystemCall{SystemCallNr::WAIT4},
			pid{ItemType::PARAM_IN, "pid to wait for"},
			event_pid{ItemType::RETVAL, "pid of child with status change"} {
		setReturnItem(event_pid);
		setParameters(pid, wstatus, options, rusage);
	}

	/* parameters */
	item::ProcessID pid;
	item::WaitStatus wstatus;
	item::WaitOptions options;
	item::ResourceUsage rusage;

	/* return value */
	item::ProcessID event_pid;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
