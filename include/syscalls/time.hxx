#pragma once

// clues
#include <clues/items/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct CLUES_API NanoSleepSystemCall :
		public SystemCall {

	NanoSleepSystemCall() :
			SystemCall{SystemCallNr::NANOSLEEP},
			req_time{"req_time", "requested time"},
			rem_time{"rem_time", "remaining time"} {
		setReturnItem(result);
		setParameters(req_time, rem_time);
	}

	/* parameters */
	item::TimeSpecParameter req_time;
	item::RemainingTimeSpec rem_time;

	/* return value */
	item::SuccessResult result;
};

struct CLUES_API ClockNanoSleepSystemCall :
		public SystemCall {

	ClockNanoSleepSystemCall() :
			SystemCall{SystemCallNr::CLOCK_NANOSLEEP},
			time{"time", "requested sleep time"},
			remaining{"rem", "remaining sleep time"} {
		setReturnItem(result);
		setParameters(clockid, flags, time, remaining);
	}

	/* parameters */
	item::ClockID clockid;
	item::ClockNanoSleepFlags flags;
	item::TimeSpecParameter time;
	item::RemainingTimeSpec remaining;

	/* return value */
	item::SuccessResult result;
};

} // end ns
