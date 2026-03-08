#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/items.hxx>
#include <clues/items/limits.hxx>
#include <clues/items/process.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

struct CLUES_API UnknownSystemCall :
		public SystemCall {
	explicit UnknownSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			result{"result", ""} {
		setReturnItem(result);
		addParameters(item);
	}

	item::ReturnValue result;
	item::UnknownItem item;
};

// This covers both getrlimit() and setrlimit() which use the same data structures
template <SystemCallNr LIMIT_SYS_NR>
struct CLUES_API LimitSystemCallT :
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

using GetRlimitSystemCall = LimitSystemCallT<SystemCallNr::GETRLIMIT>;
using SetRlimitSystemCall = LimitSystemCallT<SystemCallNr::SETRLIMIT>;

struct CLUES_API Prlimit64SystemCall :
		public SystemCall {

	Prlimit64SystemCall() :
			SystemCall{SystemCallNr::PRLIMIT64},
			pid{ItemType::PARAM_IN, "target process"},
			limit{ItemType::PARAM_IN},
			old_limit{ItemType::PARAM_OUT, "old_limit"} {
		setReturnItem(result);
		setParameters(pid, type, limit, old_limit);
	}

	item::ProcessIDItem pid;
	item::ResourceType type;
	item::ResourceLimit limit;
	item::ResourceLimit old_limit;
	item::SuccessResult result;
};

struct CLUES_API RestartSystemCall :
		public SystemCall {

	RestartSystemCall() :
			SystemCall{SystemCallNr::RESTART_SYSCALL} {
		setReturnItem(result);
	}

	item::SuccessResult result;
};

struct CLUES_API ExitGroupSystemCall :
		public SystemCall {

	ExitGroupSystemCall() :
			SystemCall{SystemCallNr::EXIT_GROUP},
			status{ItemType::PARAM_IN, "exit code"} {
		setReturnItem(result);
		setParameters(status);
	}

	item::ExitStatusItem status;
	item::SuccessResult result; // actually it never returns
};

} // end ns
