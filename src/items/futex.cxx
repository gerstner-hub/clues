// Linux
#include <linux/futex.h> // futex(2)

// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/macros.h>
#include <clues/items/futex.hxx>

namespace clues::item {

std::string FutexOperation::str() const {
	/*
	 * there are a number of undocumented constants and some flags can be
	 * or'd in like FUTEX_PRIVATE_FLAG. Without exactly understanding that
	 * we can't sensibly trace this ...
	 * it seems the man page doesn't tell the complete story, strace
	 * understands all the "private" stuff that can also be found in the
	 * header.
	 */
	switch (valueAs<int>() & FUTEX_CMD_MASK) {
		CASE_ENUM_TO_STR(FUTEX_WAIT);
		CASE_ENUM_TO_STR(FUTEX_WAIT_BITSET);
		CASE_ENUM_TO_STR(FUTEX_WAKE);
		CASE_ENUM_TO_STR(FUTEX_WAKE_BITSET);
		CASE_ENUM_TO_STR(FUTEX_FD);
		CASE_ENUM_TO_STR(FUTEX_REQUEUE);
		CASE_ENUM_TO_STR(FUTEX_CMP_REQUEUE);
		default: return cosmos::sprintf("unknown (%d)", valueAs<int>());
	}
}

} // end ns
