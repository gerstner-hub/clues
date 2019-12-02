// C++
#include <cstring>
#include <sstream>
#include <iomanip>

// Linux
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

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

std::string ErrnoResult::str() const
{
	return ApiError::msg(((int)m_val) * -1);
}

std::string PointerParameter::str() const
{
	std::stringstream ss;
	ss << (long*)m_val;
	return ss.str();
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

#define chk_open_flag(FLAG) if( m_val & FLAG ) ss << "|" << #FLAG;

std::string OpenFlagsParameter::str() const
{
	std::stringstream ss;

	ss << "0x" << std::hex << m_val << " (";

	// the access mode is made of the lower two bits
	const int access_mode = m_val & 0x3;

	if( access_mode == O_RDWR )
		ss << "O_RDWR";
	else if( access_mode == O_WRONLY )
	{
		ss << "O_WRONLY";
	}
	else if( access_mode == O_RDONLY )
	{
		ss << "O_RDONLY";
	}

	chk_open_flag(O_APPEND);
	chk_open_flag(O_ASYNC);
	chk_open_flag(O_CLOEXEC);
	chk_open_flag(O_CREAT);
	chk_open_flag(O_DIRECT);
	chk_open_flag(O_DIRECTORY);
	chk_open_flag(O_DSYNC);
	chk_open_flag(O_EXCL);
	chk_open_flag(O_LARGEFILE);
	chk_open_flag(O_NOATIME);
	chk_open_flag(O_NOCTTY);
	chk_open_flag(O_NOFOLLOW);
	chk_open_flag(O_NONBLOCK);
	chk_open_flag(O_PATH);
	chk_open_flag(O_SYNC);
	chk_open_flag(O_TMPFILE);
	chk_open_flag(O_TRUNC);

	ss << ")";

	return ss.str();
}

#define chk_mode_flag(FLAG, ch) if( m_val & FLAG) ss << ch; else ss << "-";

std::string FileModeParameter::str() const
{
	std::stringstream ss;

	ss << "0x" << std::hex << m_val << " (";

	chk_mode_flag(S_ISUID, "s");
	chk_mode_flag(S_ISGID, "S");
	chk_mode_flag(S_ISVTX, "t");
	chk_mode_flag(S_IRUSR, "r");
	chk_mode_flag(S_IWUSR, "w");
	chk_mode_flag(S_IXUSR, "x");
	chk_mode_flag(S_IRGRP, "r");
	chk_mode_flag(S_IWGRP, "w");
	chk_mode_flag(S_IXGRP, "x");
	chk_mode_flag(S_IROTH, "r");
	chk_mode_flag(S_IWOTH, "w");
	chk_mode_flag(S_IXOTH, "x");

	ss << ")";

	return ss.str();
}

std::string MemoryProtectionParameter::str() const
{
	std::stringstream ss;

	if( m_val == PROT_NONE )
		ss << "PROT_NONE";

	if( m_val & PROT_READ )
		ss << "PROT_READ";

	if( m_val & PROT_WRITE )
		ss << "|PROT_WRITE";

	if( m_val & PROT_EXEC )
		ss << "|PROT_EXEC";

	return ss.str();
}

} // end ns

