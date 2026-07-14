// C++
#include <ostream>

// clues
#include <clues/SystemCallItem.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

void SystemCallItem::fill(const Tracee &proc, const Word word) {
	m_val = word;

	if (!isUnused()) {
		processValue(proc);
	}
}

std::string SystemCallItem::str() const {
	// by default simply return the register value as a string
	return std::to_string(cosmos::to_integral(m_val));
}

bool SystemCallItem::usesTime32() const {
	/*
	 * currently we only cover 32-bit emulation on X86-64 and native I386
	 * system calls.
	 */
	return m_call->is32BitEmulationABI() || m_call->abi() == ABI::I386;
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCallItem &value) {
	o << value.longName() << " = " << value.str();
	return o;
}

