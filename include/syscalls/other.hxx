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

struct GetrlimitSystemCall :
		public SystemCall {

	GetrlimitSystemCall() :
			SystemCall{SystemCallNr::GETRLIMIT} {
		setReturnItem(result);
		setParameters(type, limit);
	}

	item::ResourceType type;
	item::ResourceLimit limit;
	item::SuccessResult result;
};

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
