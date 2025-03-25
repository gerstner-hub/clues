// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/error.hxx>
#include <clues/utils.hxx>

namespace clues::item {

std::string SuccessResult::str() const {
	if (valid()) {
		return "0";
	} else {
		return cosmos::sprintf("%d (\?\?\?)", valueAs<int>());
	}
}

} // end ns
