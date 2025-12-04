// C++
#include <ostream>

// Clues
#include <clues/RegisterSet.hxx>
#include <clues/dso_export.h>

namespace clues {

template class RegisterSet<ABI::I386>;
template class RegisterSet<ABI::X86_64>;
template class RegisterSet<ABI::X32>;

} // end ns

template <clues::ABI abi>
std::ostream& operator<<(std::ostream &o, const clues::RegisterSet<abi> &rs) {
	auto &data = rs.raw();
	auto names = data.registerNames();
	auto values = data.array();

	for (size_t i = 0; i < data.NUM_REGS; i++) {
		if (i)
			o << "\n";
		o << names[i] << " = " << values[i];
	}

	return o;
}

template CLUES_API std::ostream& operator<<(std::ostream&, const clues::RegisterSet<clues::ABI::X86_64>&);
template CLUES_API std::ostream& operator<<(std::ostream&, const clues::RegisterSet<clues::ABI::X32>&);
template CLUES_API std::ostream& operator<<(std::ostream&, const clues::RegisterSet<clues::ABI::I386>&);
