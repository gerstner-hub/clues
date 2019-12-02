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

/**
 * \brief
 * 	An errno system call result
 **/
class ErrnoParameter :
	public SystemCallParameter
{
public:
	ErrnoParameter() :
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

} // end ns

#endif // inc. guard

