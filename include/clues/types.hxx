#ifndef CLUES_TYPES_HXX
#define CLUES_TYPES_HXX

// cosmos
#include "cosmos/types.hxx"

namespace clues
{

/*
 * some general types used across Clues
 */

//! a mapping of file descriptor numbers to their file system paths or
//! other human readable description of the descriptor
typedef std::map<int, std::string> DescriptorPathMapping;

} // end ns

#endif // inc. guard

