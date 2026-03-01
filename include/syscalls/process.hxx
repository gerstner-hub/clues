#pragma once

// cosmos
#include <cosmos/fs/types.hxx>

// clues
#include <clues/items/clone.hxx>
#include <clues/items/creds.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/items.hxx>
#include <clues/items/prctl.hxx>
#include <clues/items/process.hxx>
#include <clues/items/strings.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

/// x86-specific prctl() extension.
struct ArchPrctlSystemCall :
		public SystemCall {

	ArchPrctlSystemCall() :
			SystemCall{SystemCallNr::ARCH_PRCTL} {
		setParameters(op);
		result.emplace(item::SuccessResult{});
		setReturnItem(*result);
	}

	/* parameters */
	item::ArchOpParameter op;
	/// On/off value for SET_CPUID.
	std::optional<item::ULongValue> on_off;
	/// new FS/GS base for SET_FS/SET_GS
	std::optional<item::ULongValue> set_addr;
	/// pointer to base for GET_FS/GET_GS
	std::optional<item::PointerToScalar<unsigned long>> get_addr;
	/* return values */
	std::optional<item::SuccessResult> result;
	/// On/off return for GET_CPUID.
	std::optional<item::IntValue> on_off_ret;

protected: // functions

	bool check2ndPass() override;

	void prepareNewSystemCall() override;
};

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
			new_pid{"pid", "child pid"} {
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
	item::ReturnValue new_pid;

protected: // functions

	bool check2ndPass() override;

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
	item::ValueInParameter size;
	/// New child's PID or zero if executing in child context.
	item::ProcessIDItem pid;
};

struct ForkSystemCall :
		public SystemCall {

	ForkSystemCall() :
			SystemCall{SystemCallNr::FORK},
			pid{ItemType::RETVAL, "child pid"} {
		setReturnItem(pid);
	}

	item::ProcessIDItem pid;
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

template <SystemCallNr GETXID_SYS_NR, typename ID_T>
struct GetXIdSystemCall :
		public SystemCall {

	GetXIdSystemCall() :
			SystemCall{GETXID_SYS_NR},
			id{ItemType::RETVAL, getShortLabel(), getLongLabel()} {
		setReturnItem(id);
	}


	/// the UserID or GroupID
	ID_T id;

protected:

	static const char* getShortLabel() {
		switch (GETXID_SYS_NR) {
			case SystemCallNr::GETUID: return "uid";
			case SystemCallNr::GETEUID: return "euid";
			case SystemCallNr::GETGID: return "gid";
			case SystemCallNr::GETEGID: return "egid";
			default: return "???";
		}
	}

	static const char* getLongLabel() {
		switch (GETXID_SYS_NR) {
			case SystemCallNr::GETUID: return "real user ID";
			case SystemCallNr::GETEUID: return "effective user ID";
			case SystemCallNr::GETGID: return "real group ID";
			case SystemCallNr::GETEGID: return "effective group ID";
			default: return "???";
		}
	}
};

using GetUidSystemCall = GetXIdSystemCall<SystemCallNr::GETUID, item::UserID>;
using GetEuidSystemCall = GetXIdSystemCall<SystemCallNr::GETEUID, item::UserID>;
using GetGidSystemCall = GetXIdSystemCall<SystemCallNr::GETGID, item::GroupID>;
using GetEgidSystemCall = GetXIdSystemCall<SystemCallNr::GETEGID, item::GroupID>;

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
	item::ProcessIDItem pid;
	item::WaitStatusItem wstatus;
	item::WaitOptionsItem options;
	item::ResourceUsageItem rusage;

	/* return value */
	item::ProcessIDItem event_pid;
};

} // end ns
