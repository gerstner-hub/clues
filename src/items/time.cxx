// Linux
#include <time.h>

// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/time.hxx>
#include <clues/items/net.hxx>
#include <clues/macros.h>
#include <clues/private/kernel/time.hxx>
#include <clues/syscalls/socketcall.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

namespace clues::item {

static_assert(sizeof(struct timespec) == 16, "unexpected struct timespec size");
static_assert(sizeof(struct timeval) == 16, "unexpected struct timespec size");

void TimeSpecParameter::processData(const Tracee &proc) {
	if (this->isOut())
		m_timespec.reset();
	else
		fetch(proc, m_timespec);
}

void TimeSpecParameter::updateData(const Tracee &proc) {
	if (m_call->hasResultValue()) {
		fetch(proc, m_timespec);
	}
}

bool TimeSpecParameter::needTime32Conversion() const {
	if (!usesTime32())
		return false;

	auto call_nr = m_call->callNr();

	if (call_nr == SystemCallNr::SOCKETCALL) {
		auto socketcall = dynamic_cast<const SocketCallCommon*>(m_call);
		if (auto mapped_call = socketcall->translatedSysCallNr(); mapped_call) {
			call_nr = *mapped_call;
		} else {
			/* RECV, SENDTO */
			return false;
		}
	}

	/* now we need to check which system call we're on */
	return cosmos::in_list(call_nr, {
			SystemCallNr::CLOCK_NANOSLEEP,
			SystemCallNr::FUTEX,
			SystemCallNr::NANOSLEEP,
			SystemCallNr::PSELECT6,
			SystemCallNr::PPOLL,
			SystemCallNr::RECVMMSG,
	});
}

void TimeSpecParameter::fetch(const Tracee &proc,
		std::optional<struct timespec> &spec) {
	if (needTime32Conversion()) {
		struct timespec32 ts32;
		if (!proc.readStruct(asPtr(), ts32)) {
			spec.reset();
			return;
		}

		spec.emplace();
		spec->tv_sec = ts32.tv_sec;
		spec->tv_nsec = ts32.tv_nsec;
	} else {
		proc.readStructIntoOptional(asPtr(), spec);
	}
}

std::string TimeSpecParameter::str() const {
	if (!m_timespec) {
		return formatBadPointer();
	}

	return format::timespec(*m_timespec);
}

size_t TimeSpecParameter::traceeStructSize() const {
	if (needTime32Conversion()) {
		return sizeof(struct timespec32);
	} else {
		return sizeof(struct timespec);
	}
}

void TimeSpecInOutParameter::processData(const Tracee &proc) {
	m_remaining.reset();
	TimeSpecParameter::processData(proc);
}

void TimeSpecInOutParameter::updateData(const Tracee &proc) {
	fetch(proc, m_remaining);
}

std::string TimeSpecInOutParameter::str() const {
	auto ret = TimeSpecParameter::str();

	if (!m_timespec || !m_remaining) {
		return ret;
	}

	ret += std::format(" → left: {}", format::timespec(*m_remaining));

	return ret;
}

std::string RemainingTimeSpec::str() const {
	if (!m_timespec) {
		return format::pointer(this->ptr());
	}

	return TimeSpecParameter::str();
}

void RemainingTimeSpec::updateData(const Tracee &proc) {
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

	if (!error.hasErrorCode() ||
			error.errorCode() != cosmos::Errno::INTERRUPTED) {
		return;
	}

	TimeSpecParameter::updateData(proc);
}

void TimeValParameter::processData(const Tracee &proc) {
	if (this->isOut())
		m_timeval.reset();
	else
		fetch(proc, m_timeval);
}

void TimeValParameter::updateData(const Tracee &proc) {
	if (m_call->hasResultValue()) {
		fetch(proc, m_timeval);
	}
}

namespace {

/*
 * checking out socket options is quite the pain, if this is needed elsewhere
 * then we need to make it a general purpose API in the lib.
 */

struct SockOptInfo {
	bool is_set;
	SockOptLevel::Level level;
	SockOptName::OptVariant name_variant;
};

std::optional<SockOptInfo> lookup_sock_opt(const SystemCall &sc) {
	switch (sc.callNr()) {
		case SystemCallNr::SOCKETCALL:
		case SystemCallNr::SETSOCKOPT:
		case SystemCallNr::GETSOCKOPT:
			break;
		default: return std::nullopt;
	}

	const auto getoptsc = dynamic_cast<const GetSockOptSystemCall*>(&sc);
	const auto setoptsc = dynamic_cast<const SetSockOptSystemCall*>(&sc);

	SockOptInfo ret;

	if (getoptsc) {
		return SockOptInfo {
			.is_set = false,
			.level = getoptsc->level.level(),
			.name_variant = getoptsc->name.option()
		};
	} else if (setoptsc) {
		return SockOptInfo {
			.is_set = true,
			.level = setoptsc->level.level(),
			.name_variant = setoptsc->name.option()
		};
	}

	return std::nullopt;
}

} // end ns

bool TimeValParameter::needTime32Conversion() const {

	if (!usesTime32()) {
		return false;
	}

	if (const auto sockopt_info = lookup_sock_opt(*m_call); sockopt_info) {
		if (sockopt_info->level == SockOptLevel::SOCKET) {
			const auto opt = std::get<SockOptName::SocketOption>(sockopt_info->name_variant);

			if (cosmos::in_list(opt, {
				SockOptName::SocketOption::RCVTIMEO_NEW,
				SockOptName::SocketOption::RCVTIMEO_OLD})) {
				return true;
			}
		}

		return false;
	} else {
		/* now we need to check which system call we're on */
		return cosmos::in_list(m_call->callNr(), {
			SystemCallNr::SELECT,
			SystemCallNr::NEWSELECT,
			SystemCallNr::PSELECT6
		});
	}
}

void TimeValParameter::fetch(const Tracee &proc,
		std::optional<struct timeval> &val) {
	if (needTime32Conversion()) {
		struct timeval32 tv32;
		if (!proc.readStruct(asPtr(), tv32)) {
			val.reset();
			return;
		}

		val.emplace();
		val->tv_sec = tv32.tv_sec;
		val->tv_usec = tv32.tv_usec;
	} else {
		proc.readStructIntoOptional(asPtr(), val);
	}
}

size_t TimeValParameter::traceeStructSize() const {
	if (needTime32Conversion()) {
		return sizeof(struct timeval32);
	} else {
		return sizeof(struct timeval);
	}
}

std::string TimeValParameter::str() const {
	if (!m_timeval) {
		return formatBadPointer();
	}

	return format::timeval(*m_timeval);
}

void TimeValInOutParameter::processData(const Tracee &proc) {
	m_remaining.reset();
	TimeValParameter::processData(proc);
}

void TimeValInOutParameter::updateData(const Tracee &proc) {
	fetch(proc, m_remaining);
}

std::string TimeValInOutParameter::str() const {
	auto ret = TimeValParameter::str();

	if (!m_timeval || !m_remaining) {
		return ret;
	}

	ret += std::format(" → left: {}", format::timeval(*m_remaining));

	return ret;
}

std::string ClockID::label(const cosmos::ClockType clock) {
	const auto raw = cosmos::to_integral(clock);
	switch (raw) {
		CASE_ENUM_TO_STR(CLOCK_REALTIME);
		CASE_ENUM_TO_STR(CLOCK_REALTIME_COARSE);
		CASE_ENUM_TO_STR(CLOCK_TAI);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC_RAW);
		CASE_ENUM_TO_STR(CLOCK_MONOTONIC_COARSE);
		CASE_ENUM_TO_STR(CLOCK_BOOTTIME);
		CASE_ENUM_TO_STR(CLOCK_PROCESS_CPUTIME_ID);
		CASE_ENUM_TO_STR(CLOCK_THREAD_CPUTIME_ID);
		default: return cosmos::sprintf("unknown (%d)", raw);
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
