#pragma once

// cosmos
#include "cosmos/types.hxx"

namespace clues {

/*
 * some general types used across Clues
 */

/// A mapping of file descriptor numbers to their file system paths or other human readable description of the descriptor.
using DescriptorPathMapping = std::map<int, std::string>;

} // end ns
