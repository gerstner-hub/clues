#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/time/types.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

/// The struct timespec used for various timing and timeout operations in system calls.
class TimeSpecParameter :
		public PointerValue {
public: // functions
	explicit TimeSpecParameter(const ItemCfg &cfg = {}) :
			PointerValue{cfg.applyDefaults(ItemCfg{
				.type = ItemType::PARAM_IN,
				.desc = ""})} {
	}

	std::string str() const override;

	const std::optional<struct timespec>& spec() const {
		return m_timespec;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

	void fetch(const Tracee &proc, std::optional<struct timespec> &spec);

	/// Checks whether the current ABI context requires conversion of 32 bit to 64 bit.
	bool needTime32Conversion() const;

protected: // data

	std::optional<struct timespec> m_timespec;
};

/// TimeSpecParameter which is updated with remaining sleep time on syscall exit.
/**
 * This specialization of TimeSpecParameter keeps a separate remaining timeout
 * member which will be updated on system call exit. It is used for system
 * calls that update the struct timespec upon system call exit to reflect the
 * time not slept in timeout operations.
 **/
class TimeSpecInOutParameter :
		public TimeSpecParameter {
public: // functions

	explicit TimeSpecInOutParameter(const ItemCfg &cfg = {}) :
			TimeSpecParameter{cfg.applyDefaults(ItemCfg{ItemType::PARAM_IN_OUT})} {

	}

	const std::optional<struct timespec>& remaining() const {
		return m_remaining;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct timespec> m_remaining;
};

/// Specialization of TimeSpecParameter for "remaining sleep time" out pointers.
/**
 * This variant of TimeSpecParameter is used for "remaining sleep time"
 * contexts where the kernel writes out the remaining time to sleep only
 * during special system call interrupt contexts.
 **/
class RemainingTimeSpec :
		public TimeSpecParameter {
public: // functions

	explicit RemainingTimeSpec(const ItemCfg &cfg = {}) :
			TimeSpecParameter{cfg.applyDefaults(ItemCfg{ItemType::PARAM_OUT})} {
	}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;
};

/// The struct timeval used with older time-related system calls like select().
class TimeValParameter :
		public PointerValue {
public: // functions
	explicit TimeValParameter(const ItemCfg &cfg = {}) :
			PointerValue{cfg.applyDefaults(ItemCfg{
				.type = ItemType::PARAM_IN,
				.desc = ""})} {
	}

	std::string str() const override;

	const std::optional<struct timeval>& val() const {
		return m_timeval;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

	void fetch(const Tracee &proc, std::optional<struct timeval> &val);

	/// Checks whether the current ABI context requires conversion of 32 bit to 64 bit.
	bool needTime32Conversion() const;

protected: // data

	std::optional<struct timeval> m_timeval;
};

/// TimeValParameter which is updated with remaining sleep time on syscall exit.
/**
 * This specialization of TimeValParameter keeps a separate remaining timeout
 * member which will be updated on system call exit. It is used for system
 * calls that update the struct timeval upon system call exit to reflect the
 * time not slept in timeout operations.
 **/
class TimeValInOutParameter :
		public TimeValParameter {
public: // functions

	explicit TimeValInOutParameter(const ItemCfg &cfg = {}) :
			TimeValParameter{cfg.applyDefaults(ItemCfg{ItemType::PARAM_IN_OUT})} {
	}

	const std::optional<struct timeval>& remaining() const {
		return m_remaining;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct timeval> m_remaining;
};

class ClockID :
		public ValueInParameter {
public: // functions
	explicit ClockID() :
			ValueInParameter{make_item_cfg("clockid", "clock identifier")} {
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

class ClockNanoSleepFlags :
		public ValueInParameter {
public: // types

	enum class Flag : int {
		ABSTIME = TIMER_ABSTIME
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit ClockNanoSleepFlags() :
			ValueInParameter{make_item_cfg("flags", "clock sleep flags")} {
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

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
