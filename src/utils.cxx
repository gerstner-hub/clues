// C++
#include <iostream>

// Clues
#include <clues/utils.hxx>
#include <clues/errnodb.h> // generated

// cosmos
#include <cosmos/utils.hxx>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || num >= ERRNO_NAMES_MAX)
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

const char* get_state_label(const TraceState state) {
	switch (state) {
		case TraceState::UNKNOWN:              return "UNKNOWN";
		case TraceState::RUNNING:              return "RUNNING";
		case TraceState::SYSCALL_ENTER_STOP:   return "SYSCALL_ENTER_STOP";
		case TraceState::SYSCALL_EXIT_STOP:    return "SYSCALL_EXIT_STOP";
		case TraceState::SIGNAL_DELIVERY_STOP: return "SIGNAL_DELIVERY_STOP";
		case TraceState::GROUP_STOP:           return "GROUP_STOP";
		case TraceState::EVENT_STOP:           return "EVENT_STOP";
		case TraceState::DEAD:                 return "DEAD";
		default:                                return "???";
	}
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::TraceState &state) {
	o << get_state_label(state);
	return o;
}
