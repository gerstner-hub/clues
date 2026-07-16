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
			ValueInParameter{make_item_cfg("cap", "capability")} {
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

/// Specification of a secure bits mask.
/**
 * This is currently used with prctl::GetSecureBitsSystemCall and
 * prctl::SetSecCompSystemCall.
 **/
class CLUES_API SecureBits :
		public SystemCallItem {
public: // functions

	explicit SecureBits(const ItemType type) :
			SystemCallItem{ItemCfg{type, "bits", "secure bits mask"}} {
	}

	cosmos::SecureBits mask() const {
		return m_mask;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::SecureBits m_mask;
};

} // end ns
