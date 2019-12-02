#ifndef TUXTRACE_PARAMETERS_HXX
#define TUXTRACE_PARAMETERS_HXX

// C++

// Linux

// tuxtrace
#include <tuxtrace/include/SystemCall.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	Reads a C-string from the address space starting at \c addr of the
 * 	tracee \c proc into the C++ string object \c out
 **/
void readTraceeString(
	const TracedProc &proc,
	const long *addr,
	std::string &out);

/**
 * \brief
 * 	A file descriptor system call parameter
 **/
class FileDescriptorParameter :
	public SystemCallParameter
{
public:
	FileDescriptorParameter() :
		SystemCallParameter("file descriptor")
	{}

	std::string str() const override;

protected:

};

class PointerParameter :
	public SystemCallParameter
{
public:
	PointerParameter(const char *name) :
		SystemCallParameter(name)
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	An errno system call result
 **/
class ErrnoResult :
	public SystemCallParameter
{
public:
	ErrnoResult() :
		SystemCallParameter("errno")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A c-string system call parameter
 **/
class StringParameter :
	public SystemCallParameter
{
public:
	StringParameter(const char *name = nullptr) :
		SystemCallParameter( name ? name : "string" )
	{}

	std::string str() const override { return m_str; }

protected:

	void process(const TracedProc &proc) override;

protected:

	std::string m_str;
};

/**
 * \brief
 * 	An array of c-strings system call parameter
 * \details
 * 	This is currently only used for argv and envp of the execve system
 * 	call
 **/
class StringArrayParameter :
	public SystemCallParameter
{
public:

	StringArrayParameter(const char *name = nullptr) :
		SystemCallParameter( name ? name : "string-array" )
	{}

	std::string str() const override;

protected:

	void process(const TracedProc &proc) override;

protected:

	std::vector<std::string> m_strs;
};

/**
 * \brief
 * 	The flags passed to e.g. open()
 **/
class OpenFlagsParameter :
	public SystemCallParameter
{
public:
	OpenFlagsParameter() :
		SystemCallParameter("open-flags")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The code parameter to the arch_prctl system call
 **/
class ArchCodeParameter :
	public SystemCallParameter
{
public:
	ArchCodeParameter() :
		SystemCallParameter("subfunction")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	File access mode passed e.g. to open(), chmod()
 **/
class FileModeParameter :
	public SystemCallParameter
{
public:

	FileModeParameter() :
		SystemCallParameter("file-mode")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The stat structure used in stat() & friends
 **/
class StatParameter :
	public SystemCallParameter
{
public:
	StatParameter() :
		SystemCallParameter("struct stat"),
		m_stat()
	{}

	~StatParameter() override;

	std::string str() const override;

protected:
	void update(const TracedProc &proc) override;

protected:
	FileModeParameter m_mode;
	struct stat *m_stat;
};


/**
 * \brief
 * 	Memory protection used e.g. in mprotect()
 **/
class MemoryProtectionParameter :
	public SystemCallParameter
{
public:

	MemoryProtectionParameter() :
		SystemCallParameter("protection")
	{}

	std::string str() const override;
};

} // end ns

#endif // inc. guard

