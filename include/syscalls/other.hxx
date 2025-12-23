#pragma once

// clues
#include <clues/items/items.hxx>
#include <clues/items/limits.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct UnknownSystemCall :
		public SystemCall {
	explicit UnknownSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			result{"result", ""} {
		setReturnItem(result);
	}

	item::ValueOutParameter result;
};

// This covers both getrlimit() and setrlimit() which use the same data structures
template <SystemCallNr LIMIT_SYS_NR>
struct LimitSystemCallT :
		public SystemCall {

	LimitSystemCallT() :
			SystemCall{LIMIT_SYS_NR},
			limit{LIMIT_SYS_NR == SystemCallNr::GETRLIMIT ?
				ItemType::PARAM_OUT : ItemType::PARAM_IN} {
		setReturnItem(result);
		setParameters(type, limit);
	}

	item::ResourceType type;
	item::ResourceLimit limit;
	item::SuccessResult result;
};

using GetrlimitSystemCall = LimitSystemCallT<SystemCallNr::GETRLIMIT>;
using SetrlimitSystemCall = LimitSystemCallT<SystemCallNr::SETRLIMIT>;

struct RestartSystemCall :
		public SystemCall {

	RestartSystemCall() :
			SystemCall{SystemCallNr::RESTART_SYSCALL} {
		setReturnItem(result);
	}

	item::SuccessResult result;
};

struct ExitGroupSystemCall :
		public SystemCall {

	ExitGroupSystemCall() :
			SystemCall{SystemCallNr::EXIT_GROUP},
			status{"status", "exit code"} {
		setReturnItem(result);
		setParameters(status);
	}

	item::ValueInParameter status;
	item::SuccessResult result; // actually it never returns
};

} // end ns
