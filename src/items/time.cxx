// Linux
#include <time.h>

// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/time.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

namespace clues::item {

void TimeSpecParameter::updateData(const Tracee &proc) {
	if (m_remain_semantics) {
		/*
		 * special logic for clock_nanosleep remain semantics &
		 * similar cases:
		 *
		 * - on success, remaining time is not updated
		 * - on special kernel error code, transparent restart will
		 *   happen
		 * - otherwise only if EINTR is observed will the time be
		 *   updated
		 */
		if (m_call->hasResultValue())
		       return;

		const auto error = *m_call->error();

		if (!error.hasErrorCode() || error.errorCode() != cosmos::Errno::INTERRUPTED) {
			return;
		}
	}

	fetch(proc);
}

bool TimeSpecParameter::needTime32Conversion() const {
	/*
	 * currently we only cover 32-bit emulation binaries on X86-64.
	 */

	if (!m_call->is32BitEmulationABI()) {
		return false;
	}

	/* now we need to check which system call we're on */
	return cosmos::in_list(m_call->callNr(), {SystemCallNr::CLOCK_NANOSLEEP, SystemCallNr::FUTEX});
}

void TimeSpecParameter::fetch(const Tracee &proc) {
	if (!m_timespec) {
		m_timespec = timespec{};
	}

	if (needTime32Conversion()) {
		struct timespec32 ts32;
		if (!proc.readStruct(m_val, ts32)) {
			m_timespec.reset();
			return;
		}

		m_timespec->tv_sec = ts32.tv_sec;
		m_timespec->tv_nsec = ts32.tv_nsec;
	} else if (!proc.readStruct(m_val, *m_timespec)) {
		m_timespec.reset();
	}
}

std::string TimeSpecParameter::str() const {
	if (!m_timespec) {
		if (m_remain_semantics) {
			/* still show that a pointer was passed */
			return format::pointer(valueAs<void*>());
		} else {
			return "NULL";
		}
	}

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
