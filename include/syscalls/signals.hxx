#pragma once

// clues
#include <clues/items/signal.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct AlarmSystemCall :
		public SystemCall {

	AlarmSystemCall() :
			SystemCall{SystemCallNr::ALARM},
			seconds{"seconds"},
			old_seconds{"old_seconds", "remaining seconds from previous timer"} {
		setReturnItem(old_seconds);
		setParameters(seconds);
	}

	item::ValueInParameter seconds;
	item::ReturnValue old_seconds;
};

struct SigactionSystemCall :
		public SystemCall {

	SigactionSystemCall() :
			SystemCall{SystemCallNr::RT_SIGACTION},
			old_action{"old_action"} {
		setReturnItem(result);
		setParameters(signum, action, old_action);
	}

	item::SignalNumber signum;
	item::SigactionParameter action;
	item::SigactionParameter old_action;
	item::SuccessResult result;
};

struct SigprocmaskSystemCall :
		public SystemCall {

	SigprocmaskSystemCall() :
			SystemCall{SystemCallNr::RT_SIGPROCMASK},
			new_mask{"new mask"},
			old_mask{"old mask"},
			size{"size", "size of signal sets in bytes"} {
		setReturnItem(result);
		setParameters(operation, new_mask, old_mask, size);
	}

	item::SigSetOperation operation;
	item::SigSetParameter new_mask;
	item::SigSetParameter old_mask;
	item::ValueInParameter size;
	item::SuccessResult result;
};

struct TgKillSystemCall :
		public SystemCall {

	TgKillSystemCall() :
			SystemCall{SystemCallNr::TGKILL},
			thread_group{"tgid", "thread group id"},
			thread_id{"tid", "thread id"} {
		setReturnItem(result);
		setParameters(thread_group, thread_id, signum);
	}

	item::ValueInParameter thread_group;
	item::ValueInParameter thread_id;
	item::SignalNumber signum;
	item::SuccessResult result;
};

} // end ns
