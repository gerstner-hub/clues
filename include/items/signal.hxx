#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/proc/types.hxx>

// clues
#include <clues/kernel_structs.hxx>
#include <clues/items/items.hxx>

namespace clues::item {

/// The operation to performed on a signal set.
class CLUES_API SigSetOperation :
		public ValueInParameter {
public: // types

	enum class Op : int {
		BLOCK   = SIG_BLOCK,   ///< additionally block.
		UNBLOCK = SIG_UNBLOCK, ///< unblock the given signals.
		SETMASK = SIG_SETMASK  ///< replace the whole mask.
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

	Op m_op;
};

/// A signal number specification.
class CLUES_API SignalNumber :
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
class CLUES_API SigactionParameter :
		public PointerInValue {
public: // functions
	explicit SigactionParameter(
		const std::string_view short_name = "sigaction",
		const std::string_view long_name = "struct sigaction") :
			PointerInValue{short_name, long_name} {
	}

	std::string str() const override;

	auto& action() const {
		return m_sigaction;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<struct kernel_sigaction> m_sigaction;
};

/// A set of POSIX signals for setting or masking in the context of various system calls.
class CLUES_API SigSetParameter :
		public PointerValue {
public: // functions
	explicit SigSetParameter(
		const ItemType type = ItemType::PARAM_IN,
		const std::string_view short_name = "sigset", const std::string_view name = "signal set") :
			PointerValue{type, short_name, name} {
	}

	std::string str() const override;

	auto& sigset() const {
		return m_sigset;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<sigset_t> m_sigset;
};

} // end ns
