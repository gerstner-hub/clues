#pragma once

// C++
#include <string>

// cosmos
#include <cosmos/string.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

/// This type contains data that is shared between tracees of the same thread group.
class ProcessData {
public: // data
	/// Path to the executable which is running (/proc/<pid>/exe).
	std::string executable;
	/// Command line used to create the process (/proc/<pid>/cmdline).
	cosmos::StringVector cmdline;
	/// Here we store our current knowledge about open file descriptors.
	FDInfoMap fd_info_map;
};

} // end ns
