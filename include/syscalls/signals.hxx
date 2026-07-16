#pragma once

// clues
#include <clues/items/fs.hxx>
#include <clues/items/process.hxx>
#include <clues/items/signal.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

struct AlarmSystemCall :
		public SystemCall {

	AlarmSystemCall() :
			SystemCall{SystemCallNr::ALARM},
			seconds{ItemCfg{.label = "seconds"}},
			old_seconds{ItemCfg{ItemType::RETVAL, "old_seconds",
				"remaining seconds from previous timer"}} {
		setReturnItem(old_seconds);
		setParameters(seconds);
	}

	item::UintValue seconds;
	item::UintValue old_seconds;
};

/// Type for and old sigaction().
struct SigActionSystemCall :
		public SystemCall {

	explicit SigActionSystemCall(const SystemCallNr nr = SystemCallNr::SIGACTION) :
			SystemCall{nr},
			old_action{ItemCfg{ItemType::PARAM_OUT, "old_action", "struct sigaction"}} {
		setReturnItem(result);
		setParameters(signum, action, old_action);
	}

	/* parameters */
	item::SignalNumber signum;
	item::SigActionParameter action;
	item::SigActionParameter old_action;

	/* return value */
	item::SuccessResult result;
};

/// Type for the current rt_sigaction() system call.
struct RtSigActionSystemCall :
		public SigActionSystemCall {

	explicit RtSigActionSystemCall() :
			SigActionSystemCall{SystemCallNr::RT_SIGACTION},
			sigset_size{make_item_cfg("sigset_size", "sizeof(sigset_t)")} {
		addParameters(sigset_size);
	}

	/// Provides `sizeof(sigset_t)` as found in the sigaction struct.
	/**
	 * Actually this is even more confusing, it is not the actual
	 * `sizeof()`, it is rather the amount of bytes in `sigset_t` actually
	 * used for signals, which is 8, hard-codedly, at the moment.
	 **/
	item::SizeValue sigset_size;
};

/// Type for old sigprocmask().
struct SigProcMaskSystemCall :
		public SystemCall {

	explicit SigProcMaskSystemCall(const SystemCallNr nr = SystemCallNr::SIGPROCMASK) :
			SystemCall{nr},
			new_mask{ItemCfg{ItemType::PARAM_IN, "new mask"}},
			old_mask{ItemCfg{ItemType::PARAM_OUT, "old mask"}} {
		setReturnItem(result);
		setParameters(operation, new_mask, old_mask);
	}

	/* parameters */
	item::SigSetOperation operation;
	item::SigSetParameter new_mask;
	item::SigSetParameter old_mask;

	/* return value */
	item::SuccessResult result;
};

/// Type for the current rt_sigprocmask().
struct RtSigProcMaskSystemCall :
		public SigProcMaskSystemCall {

	explicit RtSigProcMaskSystemCall() :
			SigProcMaskSystemCall{SystemCallNr::RT_SIGPROCMASK},
			sigset_size{make_item_cfg("sigset_size", "sizeof(sigset_t)")} {
		addParameters(sigset_size);
	}

	/// size of sigset_t, fixed to "8".
	item::SizeValue sigset_size;
};

struct TgKillSystemCall :
		public SystemCall {

	TgKillSystemCall() :
			SystemCall{SystemCallNr::TGKILL},
			thread_group{ItemCfg{.desc = "thread group id"}},
			thread_id{} {
		setReturnItem(result);
		setParameters(thread_group, thread_id, signum);
	}

	/* parameters */
	item::ProcessID thread_group;
	item::ThreadID thread_id;
	item::SignalNumber signum;

	/* return value */
	item::SuccessResult result;
};

struct SignalFDSystemCall :
		public SystemCall {

	explicit SignalFDSystemCall(const SystemCallNr nr = SystemCallNr::SIGNALFD) :
			SystemCall{nr},
			mask{ItemCfg{ItemType::PARAM_IN, "mask", "signals to process"}},
			sigset_size{make_item_cfg("sigset_size", "sizeof(sigset_t)")},
			new_fd{ItemCfg{.type = ItemType::RETVAL}} {
		addParameters(fd, mask, sigset_size);
		setReturnItem(new_fd);
	}

	item::FileDescriptor fd;
	item::SigSetParameter mask;
	// currently hard-coded to be 8
	item::SizeValue sigset_size;

	item::FileDescriptor new_fd;

protected: // functions

	void updateFDTracking(const Tracee &) override;
};

/// Newer variant of signalfd() accepting additional creation flags.
struct SignalFD4SystemCall :
		public SignalFDSystemCall {

	SignalFD4SystemCall() :
			SignalFDSystemCall{SystemCallNr::SIGNALFD4} {
		addParameters(flags);
	}


	item::SignalFDFlags flags;

protected: // functions

	void updateFDTracking(const Tracee &) override;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
