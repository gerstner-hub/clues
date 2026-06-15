#pragma once

// C++
#include <optional>

// clues
#include <clues/items/items.hxx>

// cosmos
#include <cosmos/proc/caps.hxx>

namespace clues::item {

/// Specification of a single capability.
/**
 * This is currently used in PrCtlSystemCall to specify a single capability
 * value.
 **/
class CLUES_API Capability :
		public ValueInParameter {
public: // functions

	explicit Capability() :
			ValueInParameter{"cap", "capability"} {
	}

	cosmos::Capability cap() const {
		return m_cap;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::Capability m_cap{};
};

} // end ns
