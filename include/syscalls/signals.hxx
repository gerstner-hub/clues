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

struct CLUES_API SigActionSystemCall :
		public SystemCall {

	SigActionSystemCall() :
			SystemCall{SystemCallNr::RT_SIGACTION},
			old_action{"old_action", "struct sigaction", ItemType::PARAM_OUT},
			sigset_size{"sigset_size", "sizeof(sigset_t)"} {
		setReturnItem(result);
		setParameters(signum, action, old_action, sigset_size);
	}

	/* parameters */
	item::SignalNumber signum;
	item::SigActionParameter action;
	item::SigActionParameter old_action;
	/// Provides `sizeof(sigset_t)` as found in the sigaction struct.
	/**
	 * Actually this is even more confusing, it is not the actual
	 * `sizeof()`, it is rather the amount of bytes in `sigset_t` actually
	 * used for signals, which is 8, hard-codedly, at the moment.
	 **/
	item::SizeValue sigset_size;

	/* return value */
	item::SuccessResult result;
};

struct CLUES_API SigProcMaskSystemCall :
		public SystemCall {

	SigProcMaskSystemCall() :
			SystemCall{SystemCallNr::RT_SIGPROCMASK},
			new_mask{ItemType::PARAM_IN, "new mask"},
			old_mask{ItemType::PARAM_OUT, "old mask"},
			size{"size", "size of signal sets in bytes"} {
		setReturnItem(result);
		setParameters(operation, new_mask, old_mask, size);
	}

	/* parameters */
	item::SigSetOperation operation;
	item::SigSetParameter new_mask;
	item::SigSetParameter old_mask;
	item::ValueInParameter size;

	/* return value */
	item::SuccessResult result;
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
