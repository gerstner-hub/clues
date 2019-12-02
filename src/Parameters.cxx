// C++
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>

// Linux
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/prctl.h> // arch_prctl constants
#include <asm/prctl.h> // "	"

// tuxtrace
#include <tuxtrace/include/Parameters.hxx>
#include <tuxtrace/include/ApiError.hxx>
#include <tuxtrace/include/TracedProc.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	reads data from the tracee and feeds it to \c eater until its
 * 	saturated
 **/
template <typename EATER>
void readTraceeData(
	const TracedProc &proc,
	const long *addr,
	EATER &eater)
{
	long word;

	do
	{
		word = proc.getData(addr);

		// get the next word
		addr++;
	}
	while( eater(word) );
}

/**
 * \brief
 * 	An EATER that fills eaten data into a vector-like container until a
 * 	terminating zero element is found
 **/
template <typename VECTOR>
class VectorEater
{
	typedef typename VECTOR::value_type *ptr_type;
public:

	VectorEater(VECTOR &vector) :
		m_vector(vector),
		VALUE_SIZE(sizeof(typename VECTOR::value_type))
	{}

	bool operator()(long word)
	{
		ptr_type unit = reinterpret_cast<ptr_type>(&word);

		for( size_t cur = 0; cur < sizeof(word) / VALUE_SIZE; cur++ )
		{
			if( unit[cur] == 0 )
				// termination found
				return false;

			m_vector.push_back( unit[cur] );
		}

		return true;
	}

protected:
	VECTOR &m_vector;
	const size_t VALUE_SIZE;
};

/**
 * \brief
 * 	Reads in an array of data items into the STL-vector like parameter \c
 * 	out
 **/
template <typename VECTOR>
void readTraceeVector(
	const TracedProc &proc,
	const long *addr,
	VECTOR &out)
{
	out.clear();

	VectorEater<VECTOR> eater(out);
	readTraceeData(proc, addr, eater);
}

template <typename STRUCT>
class StructEater
{
public:
	StructEater(STRUCT &strct) :
		m_struct(strct),
		m_left(sizeof(STRUCT))
	{}

	bool operator()(long word)
	{
		const size_t to_copy = std::min( sizeof(word), m_left );

		::memcpy(
			((char*)&m_struct) + (sizeof(STRUCT) - m_left),
			&word,
			to_copy
		);

		m_left -= to_copy;

		return m_left != 0;
	}
protected:
	STRUCT &m_struct;
	size_t m_left;
};

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
	StructEater<STRUCT> eater(out);
	readTraceeData(proc, addr, eater);
}

class BlobEater
{
public:
	BlobEater(const size_t bytes, char *buffer) :
		m_left(bytes),
		m_buffer(buffer)
	{}

	bool operator()(long word)
	{
		const size_t to_copy = std::min( sizeof(word), m_left );

		::memcpy( m_buffer, &word, to_copy );

		m_buffer += to_copy;
		m_left -= to_copy;

		return m_left != 0;
	}
	
protected:

	size_t m_left;
	char *m_buffer;
};

void readTraceeBlob(
	const TracedProc &proc,
	const long *addr,
	char *buffer,
	const size_t bytes)
{
	BlobEater eater(bytes, buffer);
	readTraceeData(proc, addr, eater);
}

std::string ErrnoResult::str() const
{
	if( (int)m_val <= 0 )
		return ApiError::msg(((int)m_val) * -1);
	else
		return "Result Value = " + std::to_string((int)m_val);
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

	if( m_at_semantics && fd == AT_FDCWD )
		return "AT_FDCWD";
	else if( fd >= 0 )
		return std::to_string((int)m_val);
		
	return std::string("Failed: ") + ApiError::msg(fd * -1);
}

void readTraceeString(
	const TracedProc &proc,
	const long *addr,
	std::string &out)
{
	return readTraceeVector(proc, addr, out);
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
	readTraceeVector(proc, array_start, string_addrs);

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

#define chk_arch_case(MODE) case MODE: return #MODE;

std::string ArchCodeParameter::str() const
{
	switch( m_val )
	{
	chk_arch_case(ARCH_SET_FS)
	chk_arch_case(ARCH_GET_FS)
	chk_arch_case(ARCH_SET_GS)
	chk_arch_case(ARCH_GET_GS)
	default:
		return "unknown";
	}
}

StatParameter::~StatParameter() { delete m_stat; }

std::string StatParameter::str() const
{
	std::stringstream ss;

	ss << "st_size = " << m_stat->st_size << ", ";
	ss << "st_dev = " << m_stat->st_dev;

	return ss.str();
}

void StatParameter::update(const TracedProc &proc)
{
	if( ! m_stat )
		m_stat = new struct stat;
	
	// the address of the struct stat in the userspace address space
	const long *addr = reinterpret_cast<long*>(m_val);

	readTraceeStruct(proc, addr, *m_stat);
}

/*
 * the man page says there's no header for this
 */
struct linux_dirent
{
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
	char pad;
	char d_type;
};

std::string DirEntries::str() const
{
	std::stringstream ss;
	const auto &respar = m_call->result();
	const int result = respar.value();

	if( result < 0 )
		ss << "undefined";
	else if( result == 0 )
		ss << "empty";
	else
	{
		ss << m_entries.size() << " entries: ";

		for( const auto &entry: m_entries )
		{
			ss << entry << ", ";
		}
	}

	return ss.str();
}

void DirEntries::update(const TracedProc &proc)
{
	m_entries.clear();

	// the amount of data store at the DirEntries location depends on the
	// system call result value
	const auto &respar = m_call->result();
	const size_t bytes = respar.value();

	if( bytes <= 0 )
		return;

	/*
	 * first copy over all the necessary data from the tracee
	 */
	char *buffer = new char[bytes];
	readTraceeBlob(
		proc,
		reinterpret_cast<long*>(this->value()),
		buffer,
		bytes);

	struct linux_dirent *cur = nullptr;
	size_t pos = 0;

	while( pos < bytes )
	{
		cur = (struct linux_dirent*)(buffer + pos);
		m_entries.push_back( cur->d_name );
		pos += cur->d_reclen;
	}

	delete[] buffer;
}

} // end ns

