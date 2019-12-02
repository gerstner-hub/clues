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

} // end ns

#endif // inc. guard

