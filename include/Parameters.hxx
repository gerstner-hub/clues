#ifndef TUXTRACE_PARAMETERS_HXX
#define TUXTRACE_PARAMETERS_HXX

// C++
#include <list>

// Linux

// tuxtrace
#include <tuxtrace/include/SystemCall.hxx>
#include <tuxtrace/include/SystemCallParameter.hxx>
#include <tuxtrace/include/KernelStructs.hxx>

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
	/**
	 * \param[in] at_semantics
	 * 	If set then the file descriptor is considered to be part of an
	 * 	*at() type system call i.e. the special file descriptor
	 * 	AT_FDCWD can occur.
	 **/
	FileDescriptorParameter(
		const FlowType &flow = IN,
		const bool at_semantics = false) :
		SystemCallParameter("file descriptor", flow),
		m_at_semantics(at_semantics)
	{}

	std::string str() const override;

protected:
	bool m_at_semantics;
};

/**
 * \brief
 * 	Generic "some pointer" parameter that just prints the address the
 * 	pointer points to
 **/
class PointerParameter :
	public SystemCallParameter
{
public:
	PointerParameter(const char *name, const FlowType &flow = IN) :
		SystemCallParameter(name, flow)
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
	ErrnoResult(
		const int highest_errno = 0,
		const char *label = "errno") :
		SystemCallParameter(label, OUT),
		m_highest(highest_errno)
	{}

	std::string str() const override;
protected:

	int m_highest;
};

/**
 * \brief
 * 	A c-string system call parameter
 **/
class StringParameter :
	public SystemCallParameter
{
public:
	StringParameter(const char *name = nullptr, const FlowType &flow = IN) :
		SystemCallParameter( name ? name : "string", flow )
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
		SystemCallParameter( name ? name : "string-array", IN )
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
		SystemCallParameter("open-flags", IN)
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
		SystemCallParameter("subfunction", IN)
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
		SystemCallParameter("file-mode", IN)
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
		SystemCallParameter("struct stat", OUT),
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
		SystemCallParameter("protection", IN)
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A list of directory entries
 **/
class DirEntries :
	public SystemCallParameter
{
public:

	DirEntries() :
		SystemCallParameter("struct linux_dirent", OUT)
	{}

	std::string str() const override;

protected:

	void update(const TracedProc &proc) override;

protected:

	std::list<std::string> m_entries;
};

/**
 * \brief
 * 	The operation to performed on a signal set
 **/
class SigSetOperation :	
	public SystemCallParameter
{
public:
	SigSetOperation() :
		SystemCallParameter("operation")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The struct timespec used for various timing and timeout operations
 * 	in system calls
 **/
class TimespecParameter :
	public SystemCallParameter
{
public:
	TimespecParameter(const char *name, const FlowType &flow = IN) :
		SystemCallParameter(name, flow),
		m_timespec(nullptr)
	{}

	~TimespecParameter() override;

	std::string str() const override;

protected:

	void process(const TracedProc &proc) override;

protected:

	struct timespec *m_timespec;
};

/**
 * \brief
 * 	The futex operation to be performed in the context of a futex system
 * 	call
 **/
class FutexOperation :
	public SystemCallParameter
{
public:
	FutexOperation() :
		SystemCallParameter("operation")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A signal number specification
 **/
class SignalParameter :
	public SystemCallParameter
{
public:
	SignalParameter() :
		SystemCallParameter("signal_nr")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The struct sigaction used in various signal related system calls
 **/
class SigactionParameter :
	public SystemCallParameter
{
public:
	SigactionParameter(const char *name = "sigaction") :
		SystemCallParameter(name),
		m_sigaction(nullptr)
	{}

	~SigactionParameter() override;

	std::string str() const override;

protected:

	void process(const TracedProc &proc) override;

protected:

	struct kernel_sigaction *m_sigaction;
};

/**
 * \brief
 * 	A set of POSIX signals for setting or masking in the context of
 * 	various system calls
 **/
class SigSetParameter :
	public SystemCallParameter
{
public:
	SigSetParameter(const char *name = "signal_set") :
		SystemCallParameter(name),
		m_sigset(nullptr)
	{}

	~SigSetParameter() override;

	std::string str() const override;

protected:

	void process(const TracedProc &proc) override;

protected:

	sigset_t *m_sigset;
};

} // end ns

#endif // inc. guard

