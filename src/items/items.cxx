// C++
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>

// Linux
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h> // *rlimit()

// clues
#include <clues/format.hxx>
#include <clues/items/items.hxx>
#include <clues/macros.h>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>

namespace clues::item {

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	ss << valueAs<long*>();
	return ss.str();
}

} // end ns
