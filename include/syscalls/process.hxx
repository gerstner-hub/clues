#pragma once

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

/*
 * TODO: the order of parameters for clone differs between
 * architectures. This is currently for x86-64 and some other ABIs only.
 * We need something like a per-ABI system call set to cover this.
 */
struct CloneSystemCall :
		public SystemCall {

	CloneSystemCall() :
			SystemCall{SystemCallNr::CLONE},
			stack{"stack", "stack address"},
			parent_tid{"parent tid", "parent thread ID"},
			child_tid{"child tid", "child thread ID"},
			tls{"tls", "thread local storage"},
			new_pid{"pid", "child pid"} {
		setReturnItem(new_pid);
		setParameters(flags, stack, parent_tid, child_tid, tls);
	}

	item::CloneFlagsValue flags;
	item::GenericPointerValue stack;
	item::GenericPointerValue parent_tid;
	item::GenericPointerValue child_tid;
	item::GenericPointerValue tls;
	item::ReturnValue new_pid;
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

// TODO: properly implement options, rusage
struct Wait4SystemCall :
		public SystemCall {
	Wait4SystemCall() :
			SystemCall{SystemCallNr::WAIT4},
			pid{"pid", "pid to wait for"},
			wstatus{"status", "pointer to status result"},
			options{"options", "wait options"},
			rusage{"rusage", "resource usage"},
			event_pid{"pid", "pid of child with status change"} {
		setReturnItem(event_pid);
		setParameters(pid, wstatus, options, rusage);
	}

	item::ValueInParameter pid;
	item::GenericPointerValue wstatus;
	item::ValueInParameter options;
	item::GenericPointerValue rusage;
	item::ReturnValue event_pid;
};

} // end ns
