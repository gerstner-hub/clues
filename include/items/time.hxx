#pragma once

// C++
#include <optional>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// The struct timespec used for various timing and timeout operations in system calls.
class CLUES_API TimespecParameter :
		public SystemCallItem {
public: // functions
	explicit TimespecParameter(
		const char *short_name,
		const char *long_name = nullptr,
		const Type type = Type::PARAM_IN) :
			SystemCallItem{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override {
		if (!this->isOut())
			fetch(proc);
	}

	void updateData(const Tracee &proc) override {
		fetch(proc);
	}

	void fetch(const Tracee &proc);

protected: // data

	std::optional<struct timespec> m_timespec;
};

class CLUES_API ClockID :
		public ValueInParameter {
public: // functions
	explicit ClockID() :
			ValueInParameter{"clockid", "clock identifier"} {
	}

	std::string str() const override;
};

class CLUES_API ClockNanoSleepFlags :
		public ValueInParameter {
public: // functions
	explicit ClockNanoSleepFlags() :
			ValueInParameter{"flags", "clock sleep flags"} {
	}

	std::string str() const override;
};

} // end ns
