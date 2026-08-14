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

void SystemCallItem::processSubItemValue(SystemCallItem &sub_item,
		const Word word, const Tracee &proc) {
	if (!sub_item.m_call) {
		sub_item.setSystemCall(*m_call);
	}

	sub_item.fill(proc, word);
}

void SystemCallItem::updateSubItemData(SystemCallItem &sub_item,
		const Tracee &proc) {
	sub_item.updateData(proc);
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCallItem &value) {
	o << value.description() << " = " << value.str();
	return o;
}

