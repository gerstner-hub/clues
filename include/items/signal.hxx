#pragma once

// C++
#include <optional>

// clues
#include <clues/kernel_structs.hxx>
#include <clues/items/items.hxx>

namespace clues::item {

/// The operation to performed on a signal set.
class CLUES_API SigSetOperation :
		public ValueInParameter {
public:
	explicit SigSetOperation() :
			ValueInParameter{"sigsetop", "signal set operation"} {
	}

	std::string str() const override;
};

/// A signal number specification.
class CLUES_API SignalNumber :
		public ValueParameter {
public: // functions
	explicit SignalNumber(const ItemType type = ItemType::PARAM_IN) :
		ValueParameter{type, "signum", "signal number"} {
	}

	std::string str() const override;
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

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<struct kernel_sigaction> m_sigaction;
};

/// A set of POSIX signals for setting or masking in the context of various system calls.
class CLUES_API SigSetParameter :
		public PointerInValue {
public: // functions
	explicit SigSetParameter(
		const std::string_view short_name = "sigset", const std::string_view name = "signal set") :
			PointerInValue{short_name, name} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<sigset_t> m_sigset;
};

} // end ns
