// Linux
#include <time.h>

// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/time.hxx>
#include <clues/macros.h>
#include <clues/Tracee.hxx>

namespace clues::item {

void TimespecParameter::fetch(const Tracee &proc) {
	if (!m_timespec) {
		m_timespec = timespec{};
	}

	if (!proc.readStruct(m_val, *m_timespec)) {
		m_timespec.reset();
	}
}

std::string TimespecParameter::str() const {
	if (!m_timespec)
		return "NULL";

	return format::timespec(*m_timespec);
}

std::string ClockID::str() const {
	switch (valueAs<clockid_t>()) {
		CASE_ENUM_TO_STR(CLOCK_REALTIME);
		CASE_ENUM_TO_STR(CLOCK_REALTIME_COARSE);
		CASE_ENUM_TO_STR(CLOCK_TAI);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC_RAW);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC_COARSE);
		CASE_ENUM_TO_STR(CLOCK_BOOTTIME);
		CASE_ENUM_TO_STR(CLOCK_PROCESS_CPUTIME_ID);
		CASE_ENUM_TO_STR(CLOCK_THREAD_CPUTIME_ID);
		default: return cosmos::sprintf("unknown (%d)", valueAs<clockid_t>());
	}
}

std::string ClockNanoSleepFlags::str() const {
	switch (valueAs<int>()) {
		CASE_ENUM_TO_STR(TIMER_ABSTIME);
		case 0: return "<relative-time>";
		default: return cosmos::sprintf("unknown (%d)", valueAs<clockid_t>());
	}
}

} // end ns
