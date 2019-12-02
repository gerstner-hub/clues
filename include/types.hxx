#ifndef TUXTRACE_TYPES_HXX
#define TUXTRACE_TYPES_HXX

// C++
#include <iosfwd>
#include <string>
#include <vector>

namespace tuxtrace
{

/*
 * some general types used across tuxtrace
 */

typedef std::vector<std::string> StringVector;
typedef std::vector<const char*> CStringVector;

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

#endif // inc. guard

