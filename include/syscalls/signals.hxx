#pragma once

// clues
#include <clues/items/signal.hxx>
#include <clues/items/process.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct CLUES_API AlarmSystemCall :
		public SystemCall {

	AlarmSystemCall() :
			SystemCall{SystemCallNr::ALARM},
			seconds{"seconds"},
			old_seconds{"old_seconds", "remaining seconds from previous timer", ItemType::RETVAL} {
		setReturnItem(old_seconds);
		setParameters(seconds);
	}

	item::UintValue seconds;
	item::UintValue old_seconds;
};

/// Type for and old sigaction().
struct CLUES_API SigActionSystemCall :
		public SystemCall {

	explicit SigActionSystemCall(const SystemCallNr nr = SystemCallNr::SIGACTION) :
			SystemCall{nr},
			old_action{"old_action", "struct sigaction", ItemType::PARAM_OUT} {
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
struct CLUES_API RtSigActionSystemCall :
		public SigActionSystemCall {

	explicit RtSigActionSystemCall() :
			SigActionSystemCall{SystemCallNr::RT_SIGACTION},
			sigset_size{"sigset_size", "sizeof(sigset_t)"} {
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
struct CLUES_API SigProcMaskSystemCall :
		public SystemCall {

	explicit SigProcMaskSystemCall(const SystemCallNr nr = SystemCallNr::SIGPROCMASK) :
			SystemCall{nr},
			new_mask{ItemType::PARAM_IN, "new mask"},
			old_mask{ItemType::PARAM_OUT, "old mask"} {
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
struct CLUES_API RtSigProcMaskSystemCall :
		public SigProcMaskSystemCall {

	explicit RtSigProcMaskSystemCall() :
			SigProcMaskSystemCall{SystemCallNr::RT_SIGPROCMASK},
			sigset_size{"sigset_size", "sizeof(sigset_t)"} {
		addParameters(sigset_size);
	}

	/// size of sigset_t, fixed to "8".
	item::SizeValue sigset_size;
};

struct CLUES_API TgKillSystemCall :
		public SystemCall {

	TgKillSystemCall() :
			SystemCall{SystemCallNr::TGKILL},
			thread_group{ItemType::PARAM_IN, "thread group id"},
			thread_id{ItemType::PARAM_IN} {
		setReturnItem(result);
		setParameters(thread_group, thread_id, signum);
	}

	/* parameters */
	item::ProcessIDItem thread_group;
	item::ThreadIDItem thread_id;
	item::SignalNumber signum;

	/* return value */
	item::SuccessResult result;
};

} // end ns
