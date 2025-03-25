#pragma once

// clues
#include <clues/items/error.hxx>
#include <clues/items/files.hxx>
#include <clues/items/futex.hxx>
#include <clues/items/limits.hxx>
#include <clues/items/mmap.hxx>
#include <clues/items/prctl.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/items/time.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/SystemCallItem.hxx>

/*
 * Various specializations of SystemCallItem are found in this header
 */

namespace clues::item {

/*
 * TODO: support to get the length of the data area from a context-sensitive
 * sibling parameter and then print out the binary/ascii data as appropriate
 */
class CLUES_API GenericPointerValue :
		public PointerValue {
public: // functions

	explicit GenericPointerValue(
		const char *short_name,
		const char *long_name = nullptr,
		const ItemType type = ItemType::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // data

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

} // end ns
