#ifndef CLUES_UTILS_HXX
#define CLUES_UTILS_HXX

// C++
#include <string>

namespace clues
{

class TracedProc;

/**
 * \brief
 * 	Reads a \0 terminated C-string from the tracee
 * \details
 * 	Read from the address space starting at \c addr of the tracee \c proc
 * 	into the C++ string object \c out.
 **/
void readTraceeString(
	const TracedProc &proc,
	const long *addr,
	std::string &out
);

/**
 * \brief
 * 	Reads an arbitrary binary blob of fixed length from the tracee
 **/
void readTraceeBlob(
	const TracedProc &proc,
	const long *addr,
	char *buffer,
	const size_t bytes
);

/**
 * \brief
 * 	Reads in a complete data structure STRUCT from the tracee
 **/
template <typename STRUCT>
void readTraceeStruct(
	const TracedProc &proc,
	const long *addr,
	STRUCT &out)
{
	readTraceeBlob(proc, addr, reinterpret_cast<char*>(&out), sizeof(STRUCT));
}

/**
 * \brief
 * 	Wrapper to helper functions to implement typical exitedCall functions
 **/
template <typename T>
void readStruct(
	const TracedProc &proc,
	const long pointer,
	T *&copy)
{
	// the address of the struct in the userspace address space
	const long *addr = reinterpret_cast<long*>(pointer);

	if( ! addr )
		// null address specification
		return;

	if( ! copy )
		copy = new T;

	readTraceeStruct(proc, addr, *copy);
}

/**
 * \brief
 * 	Reads in a zero terminated array of data items into the STL-vector
 * 	like parameter \c out
 **/
template <typename VECTOR>
void readTraceeVector(
	const TracedProc &proc,
	const long *addr,
	VECTOR &out
);


} // end ns

#endif // inc. guard

