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
			req_time{make_item_cfg("req_time", "requested time")},
			rem_time{make_item_cfg("rem_time", "remaining time")} {
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

	ClockNanoSleepSystemCall(const SystemCallNr nr = SystemCallNr::CLOCK_NANOSLEEP) :
			SystemCall{nr},
			time{make_item_cfg("time", "requested sleep time")},
			remaining{make_item_cfg("rem", "remaining sleep time")} {
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
