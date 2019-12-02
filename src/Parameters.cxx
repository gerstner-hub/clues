// C++
#include <cstring>

// Linux

// tuxtrace
#include <tuxtrace/include/Parameters.hxx>
#include <tuxtrace/include/ApiError.hxx>
#include <tuxtrace/include/TracedProc.hxx>

namespace tuxtrace
{

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

void StringParameter::process(const TracedProc &proc)
{
	// the address of the string in the userspace address space
	const long *addr = reinterpret_cast<long*>(m_val);
	long word;
	char *bit = reinterpret_cast<char*>(&word);;
	
	m_str.clear();

	while( true )
	{
		word = proc.getData(addr);

		for( size_t byte = 0; byte < sizeof(word); byte++ )
		{
			if( bit[byte] == 0 )
				// string termination found
				return;

			m_str += bit[byte];
		}

		// get the next word
		addr++;
	}
}

} // end ns

