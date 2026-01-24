#pragma once

// clues
#include <clues/items/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct NanosleepSystemCall :
		public SystemCall {

	NanosleepSystemCall() :
			SystemCall{SystemCallNr::NANOSLEEP},
			req_time{"req_time", "requested time"},
			rem_time{"rem_time", "remaining time", ItemType::PARAM_OUT} {
		setReturnItem(result);
		setParameters(req_time, rem_time);
	}

	/* parameters */
	item::TimespecParameter req_time;
	item::TimespecParameter rem_time;

	/* return value */
	item::SuccessResult result;
};

struct ClockNanosleepSystemCall :
		public SystemCall {

	ClockNanosleepSystemCall() :
			SystemCall{SystemCallNr::CLOCK_NANOSLEEP},
			time{"time", "requested sleep time"},
			remaining{"rem", "remaining sleep time", ItemType::PARAM_OUT} {
		setReturnItem(result);
		setParameters(clockid, flags, time, remaining);
	}

	/* parameters */
	item::ClockID clockid;
	item::ClockNanoSleepFlags flags;
	item::TimespecParameter time;
	item::TimespecParameter remaining;

	/* return value */
	item::SuccessResult result;
};

} // end ns
