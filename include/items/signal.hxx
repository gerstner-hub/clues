#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/proc/types.hxx>
#include <cosmos/proc/SigAction.hxx>
#include <cosmos/proc/SigInfo.hxx>
#include <cosmos/proc/SignalFD.hxx>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

/// The operation to performed on a signal set.
class SigSetOperation :
		public ValueInParameter {
public: // types

	enum class Op : int {
		BLOCK   = SIG_BLOCK,   ///< additionally block.
		UNBLOCK = SIG_UNBLOCK, ///< unblock the given signals.
		SETMASK = SIG_SETMASK, ///< replace the whole mask.
		INVALID
	};

public:
	explicit SigSetOperation() :
			ValueInParameter{"sigsetop", "signal set operation"} {
	}

	std::string str() const override;

	auto op() const {
		return m_op;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_op = valueAs<Op>();
	}

protected: // data

	Op m_op = Op::INVALID;
};

/// A signal number specification.
class SignalNumber :
		public ValueParameter {
public: // functions
	explicit SignalNumber(const ItemType type = ItemType::PARAM_IN) :
		ValueParameter{type, "signum", "signal number"} {
	}

	std::string str() const override;

	auto nr() const {
		return m_nr;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_nr = valueAs<cosmos::SignalNr>();
	}

protected: // data

	cosmos::SignalNr m_nr = cosmos::SignalNr::NONE;
};

/// The struct sigaction used in various signal related system calls.
class SigActionParameter :
		public PointerValue {
public: // functions
	explicit SigActionParameter(
		const std::string_view short_name = "sigaction",
		const std::string_view long_name = "struct sigaction",
		const ItemType type = ItemType::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

	const std::optional<cosmos::SigAction>& action() const {
		return m_sigaction;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::SigAction> m_sigaction;
};

/// A set of POSIX signals for setting or masking in the context of various system calls.
class SigSetParameter :
		public PointerValue {
public: // functions

	explicit SigSetParameter(
		const ItemType type = ItemType::PARAM_IN,
		const std::string_view short_name = "sigset", const std::string_view name = "signal set") :
			PointerValue{type, short_name, name} {
	}

	std::string str() const override;

	const std::optional<cosmos::SigSet>& sigset() const {
		return m_sigset;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	bool usesArgPack() const;

protected: // data

	std::optional<cosmos::SigSet> m_sigset;
	/*
	 * used for pselect6() where sigset and its size are combined in a
	 * struct "argument pack".
	 */
	std::optional<size_t> m_sigset_size;
};

/// Signal information struct.
/**
 * This is currently used with WaitIDSystemCall.
 **/
class SigInfo :
		public PointerOutValue {
public: // functions

	explicit SigInfo() :
		PointerOutValue{"infop", "struct siginfo_t*"} {

	}

	std::string str() const override;

	/// Provides access to the SigInfo data.
	/**
	 * This can be std::nullopt in case the system call or reading
	 * Tracee memory failed.
	 **/
	const std::optional<cosmos::SigInfo>& info() const{
		return m_info;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_info.reset();
	}

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::SigInfo> m_info;
};

class SignalFDFlags :
		public ValueInParameter {
public: // types

	using enum cosmos::SignalFD::Flag;

	using Flags = cosmos::SignalFD::Flags;

public: // functions

	explicit SignalFDFlags() :
			ValueInParameter{"flags", "signalfd() creation flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override;

protected: // data

	Flags m_flags{};
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
