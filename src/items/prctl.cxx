// cosmos
#include <cosmos/compiler.hxx>

// Linux
#ifdef COSMOS_X86
#	include <asm/prctl.h> // arch_prctl constants
#	include <sys/prctl.h>
#endif

// clues
#include <clues/items/prctl.hxx>
#include <clues/macros.h>

namespace clues::item {

std::string ArchOpParameter::str() const {
	switch (valueAs<int>()) {
#ifdef COSMOS_X86
		CASE_ENUM_TO_STR(ARCH_SET_CPUID);
		CASE_ENUM_TO_STR(ARCH_GET_CPUID);
#ifdef COSMOS_X86_64
		CASE_ENUM_TO_STR(ARCH_SET_FS);
		CASE_ENUM_TO_STR(ARCH_GET_FS);
		CASE_ENUM_TO_STR(ARCH_SET_GS);
		CASE_ENUM_TO_STR(ARCH_GET_GS);
#endif // COSMOS_X86_64
#endif // COSMOS_X86
		default: return "unknown";
	}
}

} // end ns
