// C++
#include <cstring>

// Linux

// tuxtrace
#include <tuxtrace/include/Parameters.hxx>
#include <tuxtrace/include/ApiError.hxx>
#include <tuxtrace/include/TracedProc.hxx>

namespace tuxtrace
{

template <typename VECTOR>
void readTraceeData(
	const TracedProc &proc,
	const long *addr,
	VECTOR &out)
{
	long word;
	const auto VALUE_SIZE = sizeof(typename VECTOR::value_type);
	typedef typename VECTOR::value_type *ptr_type;
	ptr_type unit = reinterpret_cast<ptr_type>(&word);
	out.clear();

	while( true )
	{
		word = proc.getData(addr);

		for( size_t cur = 0; cur < sizeof(word) / VALUE_SIZE; cur++ )
		{
			if( unit[cur] == 0 )
				// termination found
				return;

			out.push_back( unit[cur] );
		}

		// get the next word
		addr++;
	}

}

std::string ErrnoParameter::str() const
{
	return ApiError::msg(((int)m_val) * -1);
}

std::string FileDescriptorParameter::str() const
{
	int fd = (int)m_val;

	if( fd >= 0 )
		return std::to_string((int)m_val);
		
	return std::string("Failed: ") + ApiError::msg(fd * -1);
}

void readTraceeString(
	const TracedProc &proc,
	const long *addr,
	std::string &out)
{
	return readTraceeData(proc, addr, out);
}

void StringParameter::process(const TracedProc &proc)
{
	// the address of the string in the userspace address space
	const long *addr = reinterpret_cast<long*>(m_val);
	readTraceeString(proc, addr, m_str);
}

void StringArrayParameter::process(const TracedProc &proc)
{
	const long *array_start = reinterpret_cast<long*>(m_val);
	std::vector<long*> string_addrs;

	// first read in all start adresses of the c-strings for the string
	// array
	readTraceeData(proc, array_start, string_addrs);

	for( const auto &addr: string_addrs )
	{
		m_strs.push_back( std::string() );
		readTraceeString(proc, addr, m_strs.back() );
	}
}

std::string StringArrayParameter::str() const
{
	std::string ret;

	for( const auto &str: m_strs )
	{
		ret += str;
		ret += " ";
	}

	if( ! ret.empty() )
		ret.erase( ret.end() - 1 );

	return ret;
}

} // end ns

