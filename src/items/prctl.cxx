// cosmos
#include <cosmos/compiler.hxx>

// Linux
#ifdef COSMOS_X86_64
#	include <asm/prctl.h> // arch_prctl constants
#	include <sys/prctl.h>
#endif

// clues
#include <clues/items/prctl.hxx>
#include <clues/macros.h>

namespace clues::item {

#ifdef COSMOS_X86_64
std::string ArchCodeParameter::str() const {
	switch (valueAs<int>()) {
		CASE_ENUM_TO_STR(ARCH_SET_FS);
		CASE_ENUM_TO_STR(ARCH_GET_FS);
		CASE_ENUM_TO_STR(ARCH_SET_GS);
		CASE_ENUM_TO_STR(ARCH_GET_GS);
		default: return "unknown";
	}
}
#endif // COSMOS_X86_64

} // end ns
