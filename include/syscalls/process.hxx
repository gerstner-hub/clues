#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/fs/types.hxx>

// clues
#include <clues/arch.hxx>
#include <clues/dso_export.h>
#include <clues/items/caps.hxx>
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

#ifdef CLUES_HAVE_ARCH_PRCTL

/// x86-specific prctl() extension.
struct CLUES_API ArchPrctlSystemCall :
		public SystemCall {

	ArchPrctlSystemCall() :
			SystemCall{SystemCallNr::ARCH_PRCTL} {
		setParameters(op);
		result.emplace();
		setReturnItem(*result);
	}

	/* parameters */
	item::ArchOpParameter op;
	/// On/off value for SET_CPUID.
	std::optional<item::ULongValue> on_off;
	/// new FS/GS base for SET_FS/SET_GS
	std::optional<item::GenericPointerValue> set_addr;
	/// pointer to base for GET_FS/GET_GS
	std::optional<item::PointerToScalar<unsigned long>> get_addr;
	/* return values */
	std::optional<item::SuccessResult> result;
	/// On/off return for GET_CPUID.
	std::optional<item::IntValue> on_off_ret;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

#endif

/// Wrapper for the clone() and clone2() system calls.
/**
 * For clone3() a separate wrapper type is used, since the two variants of
 * clone system calls differ too much from each other.
 **/
struct CLUES_API CloneSystemCall :
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

struct CLUES_API Clone3SystemCall :
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

struct CLUES_API ForkSystemCall :
		public SystemCall {

	ForkSystemCall() :
			SystemCall{SystemCallNr::FORK},
			pid{ItemType::RETVAL, "child pid"} {
		setReturnItem(pid);
	}

	item::ProcessID pid;
};

struct CLUES_API ExecveSystemCall :
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

struct CLUES_API ExecveAtSystemCall :
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

struct CLUES_API GetPGIDSystemCall :
		GetXIDSystemCall<item::ProcessGroupID> {
	explicit GetPGIDSystemCall() :
			GetXIDSystemCall{SystemCallNr::GETPGID},
			pid{ItemType::PARAM_IN} {
		setParameters(pid);
	}

	item::ProcessID pid; ///< the PID to get the process group ID for.
};

struct CLUES_API GetSIDSystemCall :
		GetXIDSystemCall<item::SessionID> {
	explicit GetSIDSystemCall() :
			GetXIDSystemCall{SystemCallNr::GETSID},
			pid{ItemType::PARAM_IN} {
		setParameters(pid);
	}

	item::ProcessID pid; ///< the PID to get the session ID for.
};

struct CLUES_API SetSIDSystemCall :
		public SystemCall {
	explicit SetSIDSystemCall() :
			SystemCall{SystemCallNr::SETSID},
			new_sid{ItemType::RETVAL} {
		setReturnItem(new_sid);
	}

	item::SessionID new_sid;
};

struct CLUES_API Wait4SystemCall :
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

/// Base type for prctl() system calls.
/**
 * prctl() is a varargs system call similar to ioctl(). Due to the many
 * different types of parameters and return values specializations of this
 * type exist for the more exotic instances.
 *
 * The only common parameter is the first integer argument which specifies the
 * operation to be carrier out and on which the interpretation of the rest of
 * the parameters and the return value depend.
 **/
struct CLUES_API PrCtlSystemCall :
		public SystemCall {

	explicit PrCtlSystemCall() :
			SystemCall{SystemCallNr::PRCTL} {
		setParameters(op);
	}

	/* fixed parameters */

	/// The only fixed parameter: the type of process operation.
	item::ProcessOp op;

	/* vararg parameters */

	/// Capability to operate on.
	/**
	 * This is available for the following Operation values:
	 *
	 * - CAPBSET_READ
	 * - CAPBSET_DROP
	 **/
	std::optional<item::Capability> cap;
	/// sub-operation for Operation::CAP_AMBIENT.
	std::optional<item::AmbientCapOp> ambient_op;
	/// sub-operation for Operation::MCE_KILL.
	std::optional<item::MachineCheckOp> mce_op;
	/// policy for Operation::MCE_KILL sub-op MachineCheckOp::MCE_KILL_SET.
	std::optional<item::MachineCheckPolicy> mce_policy;
	/// sub-operation for Operation::SET_MM.
	std::optional<item::MemoryMapOp> mm_op;
	/// current child-subreaper setting for Operation::GET_CHILD_SUBREAPER.
	std::optional<item::PointerToScalar<long>> is_subreaper;
	/// new boolean value for attribute.
	/**
	 * This is available for the following Operation values:
	 *
	 * - SET_CHILD_SUBREAPER
	 * - SET_DUMPABLE
	 * - GET_IO_FLUSHER
	 * - SET_KEEPCAPS
	 **/
	std::optional<item::BoolValue> bool_setting;
	/// memory map setting for most of the MemoryMapOp sub-operations.
	std::optional<item::GenericPointerValue> mm_addr;
	/// out pointer for MemoryMapOp::MAP_SIZE.
	std::optional<item::PointerToScalar<unsigned int>> map_size;
	/// file descriptor for MemoryMapOp::EXE_FILE.
	std::optional<item::FileDescriptor> exe_fd;
	/// pointer to prctl_mm_map* for MemoryMapOp::MAP.
	std::optional<item::MemoryMapStruct> mm_struct;
	/// size of area pointed to by `map_struct`.
	std::optional<item::ULongValue> mm_struct_size;

	/* return values */

	/// Regular success status result.
	/**
	 * This is used (on success) for the following Operation values:
	 *
	 * - CAPBSET_DROP
	 * - SET_CHILD_SUBREAPER
	 * - GET_CHILD_SUBREAPER
	 * - CAP_AMBIENT (except for sub-operation CAP_AMBIENT_IS_SET)
	 **/
	std::optional<item::SuccessResult> res;
	/// Boolean indicator.
	/**
	 * This is available for the following Operation values:
	 *
	 * - CAPBSET_READ
	 * - GET_DUMPABLE
	 * - SET_DUMPABLE
	 * - GET_IO_FLUSHER
	 * - SET_IO_FLUSHER
	 * - SET_CHILD_SUBREAPER
	 * - MCE_KILL
	 * - CAP_AMBIENT (only for sub-operation CAP_AMBIENT_IS_SET)
	 **/
	std::optional<item::BoolValue> bool_res;
	/// Machine check exception policy return for Operation::MCE_KILL_GET.
	std::optional<item::MachineCheckPolicy> mce_policy_res;


protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

} // end ns
