#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/time/types.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// The struct timespec used for various timing and timeout operations in system calls.
class CLUES_API TimespecParameter :
		public SystemCallItem {
public: // functions
	explicit TimespecParameter(
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_IN,
		const bool remain_semantics = false) :
			SystemCallItem{type, short_name, long_name},
			m_remain_semantics{remain_semantics} {
	}

	std::string str() const override;

	const std::optional<struct timespec>& spec() const {
		return m_timespec;
	}

protected: // functions

	void processValue(const Tracee &proc) override {
		if (this->isOut())
			m_timespec.reset();
		else
			fetch(proc);
	}

	void updateData(const Tracee &proc) override;

	void fetch(const Tracee &proc);

protected: // data

	std::optional<struct timespec> m_timespec;
	bool m_remain_semantics = false;
};

class CLUES_API ClockID :
		public ValueInParameter {
public: // functions
	explicit ClockID() :
			ValueInParameter{"clockid", "clock identifier"} {
	}

	std::string str() const override;

	auto type() const { return m_type; }

protected: // functions

	void processValue(const Tracee&) override {
		m_type = valueAs<cosmos::ClockType>();
	}

protected: // data

	cosmos::ClockType m_type = cosmos::ClockType::INVALID;
};

class CLUES_API ClockNanoSleepFlags :
		public ValueInParameter {
public: // types

	enum class Flag : int {
		ABSTIME = TIMER_ABSTIME
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit ClockNanoSleepFlags() :
			ValueInParameter{"flags", "clock sleep flags"} {
	}

	std::string str() const override;

	auto flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_flags = Flags{valueAs<int>()};
	}

protected: // data

	Flags m_flags;
};

} // end ns
