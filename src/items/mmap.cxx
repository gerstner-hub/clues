// C++
#include <sstream>

// cosmos
#include <cosmos/proc/mman.hxx>

// clues
#include <clues/items/mmap.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

std::string MemoryProtectionParameter::str() const {
	if (m_prot.none())
		// this is just zero
		return "PROT_NONE";

	BITFLAGS_FORMAT_START(m_prot);

	BITFLAGS_ADD(PROT_READ);
	BITFLAGS_ADD(PROT_WRITE);
	BITFLAGS_ADD(PROT_EXEC);
	BITFLAGS_ADD(PROT_SEM);
	BITFLAGS_ADD(PROT_SAO);

	return BITFLAGS_STR();
}

std::string MapFlagsParameter::str() const {
	const auto raw = valueAs<int>();
	BITFLAGS_FORMAT_START_COMBINED(m_flags, raw);

	using enum cosmos::mem::MapType;

	switch (m_type) {
		default:              BITFLAGS_STREAM() << "MAP_???"; break;
		case SHARED:          BITFLAGS_STREAM() << "MAP_SHARED"; break;
		case SHARED_VALIDATE: BITFLAGS_STREAM() << "MAP_SHARED_VALIDATE"; break;
		case PRIVATE:         BITFLAGS_STREAM() << "MAP_PRIVATE"; break;
	}

	BITFLAGS_STREAM() << '|';

	BITFLAGS_ADD(MAP_32BIT);
	BITFLAGS_ADD(MAP_ANONYMOUS);
	BITFLAGS_ADD(MAP_FIXED);
	BITFLAGS_ADD(MAP_FIXED_NOREPLACE);
	BITFLAGS_ADD(MAP_GROWSDOWN);
	BITFLAGS_ADD(MAP_HUGETLB);
	BITFLAGS_ADD(MAP_LOCKED);
	BITFLAGS_ADD(MAP_NONBLOCK);
	BITFLAGS_ADD(MAP_NORESERVE);
	BITFLAGS_ADD(MAP_POPULATE);
	BITFLAGS_ADD(MAP_STACK);
	BITFLAGS_ADD(MAP_SYNC);
	BITFLAGS_ADD(MAP_UNINITIALIZED);

	const auto huge_shift = (raw >> MAP_HUGE_SHIFT) & 0x3f;

	if (huge_shift != 0) {
		/* there's also the TLB page size encoded into the bit mask */
		BITFLAGS_STREAM() << huge_shift << "<<MAP_HUGE_SHIFT|";
	}

	return BITFLAGS_STR();
}

} // end ns
