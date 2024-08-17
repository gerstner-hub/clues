#pragma once

// C++
#include <string>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

class Tracee;

/// Returns a short errno label like `ENOENT` for the given errno integer.
const char* get_errno_label(const cosmos::Errno err);

/// Reads a \0 terminated C-string from the tracee.
/**
 * Read from the address space starting at \c addr of the tracee \c proc into
 * the C++ string object \c out.
 **/
void readTraceeString(
	const Tracee &proc,
	const long *addr,
	std::string &out
);

/// Reads an arbitrary binary blob of fixed length from the tracee.
void CLUES_API readTraceeBlob(
	const Tracee &proc,
	const long *addr,
	char *buffer,
	const size_t bytes
);

/// Wrapper to helper functions to implement typical exitedCall functions.
template <typename T>
bool readTraceeStruct(
		const Tracee &proc,
		const Word pointer,
		T &out) {
	// the address of the struct in the tracee's address space
	const long *addr = reinterpret_cast<long*>(pointer);

	if (!addr)
		// null address specification
		return false;

	static_assert(std::is_pod_v<T> == true);

	readTraceeBlob(proc, addr, reinterpret_cast<char*>(&out), sizeof(T));
	return true;
}

/// Reads in a zero terminated array of data items into the STL-vector like parameter \c out.
template <typename VECTOR>
void readTraceeVector(
	const Tracee &proc,
	const long *addr,
	VECTOR &out
);

} // end ns
