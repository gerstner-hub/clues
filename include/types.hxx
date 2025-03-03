#pragma once

// Linux
#include <sys/procfs.h> // the elf_greg_t & friends are in here

// C++
#include <map>
#include <string>

namespace clues {

/*
 * some general types used across Clues
 */

/// A mapping of file descriptor numbers to their file system paths or other human readable description of the descriptor.
using DescriptorPathMapping = std::map<int, std::string>;

/// An integer that is able to hold a word for the current architecture.
enum class Word : elf_greg_t {
	ZERO = 0
};

} // end ns
