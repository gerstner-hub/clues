#ifndef TUXTRACE_TYPES_HXX
#define TUXTRACE_TYPES_HXX

// C++
#include <ostream>
#include <string>
#include <vector>
#include <map>

namespace tuxtrace
{

/*
 * some general types used across tuxtrace
 */

typedef std::vector<std::string> StringVector;
typedef std::vector<const char*> CStringVector;

//! a mapping of file descriptor numbers to their file system paths or
//! other human readable description of the descriptor
typedef std::map<int, std::string> DescriptorPathMapping;

} // end ns

template <typename T>
inline std::ostream& operator<<(std::ostream &o, const std::vector<T> &sv)
{
	for( auto it = sv.begin(); it != sv.end(); it++ )
	{
		if( it != sv.begin() )
			o << ", ";
		o << *it;
	}

	return o;
}

template <typename K, typename V>
inline std::ostream& operator<<(std::ostream &o, const std::map<K,V> &m)
{
	for( auto it: m )
	{
		o << it.first << ": " << it.second << "\n";
	}

	return o;
}

#endif // inc. guard

