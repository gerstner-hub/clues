#pragma once

// cosmos
#include <cosmos/proc/mman.hxx>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// Memory protection used e.g. in mprotect().
class CLUES_API MemoryProtectionParameter :
		public ValueInParameter {
public: // functions

	explicit MemoryProtectionParameter() :
			ValueInParameter{"prot", "protection"} {
	}

	std::string str() const override;

	auto prot() const {
		return m_prot;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_prot = cosmos::mem::AccessFlags{valueAs<int>()};
	}

protected: // data

	cosmos::mem::AccessFlags m_prot;
};

/// mmap() bitmask.
class CLUES_API MapFlagsParameter :
		public ValueInParameter {
public: // functions

	explicit MapFlagsParameter() :
			ValueInParameter{"flags", "memory mapping flags"} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override {
		/*
		 * the lower three bits comprise the map type (a value, not a
		 * bit mask), the rest is a bit mask.
		 */
		const auto raw = valueAs<int>();
		m_flags = cosmos::mem::MapFlags{raw & ~0x3};
		m_type = cosmos::mem::MapType{raw & 0x3};
	}

protected: // data

	cosmos::mem::MapType m_type = cosmos::mem::MapType{0};
	cosmos::mem::MapFlags m_flags;
};

} // end ns
