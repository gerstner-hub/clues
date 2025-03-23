// Linux
#ifdef __x86_64__
#	include <sys/prctl.h> // arch_prctl constants
#	include <asm/prctl.h> // "	"
#endif

// clues
#include <clues/items/prctl.hxx>

namespace clues::item {

#ifdef __x86_64__

std::string ArchCodeParameter::str() const {
#	define chk_arch_case(MODE) case MODE: return #MODE;
	switch (valueAs<int>()) {
		chk_arch_case(ARCH_SET_FS)
		chk_arch_case(ARCH_GET_FS)
		chk_arch_case(ARCH_SET_GS)
		chk_arch_case(ARCH_GET_GS)
		default: return "unknown";
	}
}
#endif // __x86_64__

} // end ns
