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

	cosmos::mem::MapType type() const {
		return m_type;
	}

	cosmos::mem::MapFlags flags() const {
		return m_flags;
	}

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

/// Combined mmap() arguments for the old variant of mmap() on 32-bit ABIs like I386.
class CLUES_API OldMmapArgs :
		public PointerInValue {
public:

	explicit OldMmapArgs() :
			PointerInValue{"args"} {
	}

	bool valid() const {
		return m_valid;
	}

	ForeignPtr addr() const {
		return m_addr;
	}

	size_t length() const {
		return m_length;
	}

	size_t offset() const {
		return m_offset;
	}

	cosmos::mem::MapType type() const {
		return m_type;
	}

	cosmos::mem::MapFlags flags() const {
		return m_flags;
	}

	cosmos::mem::AccessFlags prot() const {
		return m_prot;
	}

	cosmos::FileNum fd() const {
		return m_fd;
	}

protected: // functions

	void processValue(const Tracee&) override;

	std::string str() const override;

protected: // data

	bool m_valid = false;
	ForeignPtr m_addr = ForeignPtr::NO_POINTER;
	size_t m_length = 0;
	size_t m_offset = 0;
	cosmos::mem::MapType m_type{0};
	cosmos::mem::MapFlags m_flags;
	cosmos::mem::AccessFlags m_prot;
	cosmos::FileNum m_fd;
};

} // end ns
