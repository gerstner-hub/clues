#ifndef TUXTRACE_PARAMETERS_HXX
#define TUXTRACE_PARAMETERS_HXX

// C++
#include <list>

// Linux

// clues
#include "clues/SystemCall.hxx"
#include "clues/SystemCallParameter.hxx"
#include "clues/KernelStructs.hxx"

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
	 * \param[in] error_semantics
	 * 	If set then negative file descriptor values are interpreted as
	 * 	errno's, other as unset/undefined/invalid file descriptors.
	 **/
	FileDescriptorParameter(
		const FlowType &flow = IN,
		const bool at_semantics = false,
		const bool error_semantics = false) :
		SystemCallParameter("file descriptor", flow),
		m_at_semantics(at_semantics),
		m_error_semantics(error_semantics)
	{}

	std::string str() const override;

protected:

	void enteredCall(const TracedProc &proc) override {};

	void exitedCall(const TracedProc &proc) override {};


protected:
	bool m_at_semantics;
	bool m_error_semantics;
};

/**
 * \brief
 * 	An errno system call result
 **/
class ErrnoResult :
	public ValueOutParameter
{
public:
	ErrnoResult(
		const int highest_errno = 0,
		const char *label = "errno") :
		ValueOutParameter(label),
		m_highest(highest_errno)
	{}

	std::string str() const override;
protected:

	int m_highest;
};


/**
 *
 * 	TODO: support to get the length of the data area from a
 * 	context-sensitive sibbling parameter and the print out the
 * 	binary/ascii data as appropriate
 **/
class GenericPointerParameter :
	public PointerParameter
{
public:
	GenericPointerParameter(const char *name, const FlowType &flow = PointerParameter::IN) :
		PointerParameter(name, flow)
	{}

	std::string str() const override;

protected:

	void enteredCall(const TracedProc &proc) override {}
	void exitedCall(const TracedProc &proc) override {}
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

	void enteredCall(const TracedProc &proc) override
	{
		if( ! this->isOut() )
			fill(proc);
	}

	void exitedCall(const TracedProc &proc) override
	{
		if( ! this->isIn() )
			fill(proc);
	}


	void fill(const TracedProc &proc);

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
	public PointerInParameter
{
public:

	StringArrayParameter(const char *name = nullptr) :
		PointerInParameter( name ? name : "string-array")
	{}

	std::string str() const override;

protected:

	void enteredCall(const TracedProc &proc) override;

protected:

	std::vector<std::string> m_strs;
};

/**
 * \brief
 * 	The flags passed to e.g. open()
 **/
class OpenFlagsParameter :
	public ValueInParameter
{
public:
	OpenFlagsParameter() :
		ValueInParameter("open-flags")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The code parameter to the arch_prctl system call
 **/
class ArchCodeParameter :
	public ValueInParameter
{
public:
	ArchCodeParameter() :
		ValueInParameter("subfunction")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	File access mode passed e.g. to open(), chmod()
 **/
class FileModeParameter :
	public ValueInParameter
{
public:

	FileModeParameter() :
		ValueInParameter("file-mode")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The stat structure used in stat() & friends
 **/
class StatParameter :
	public PointerOutParameter
{
public:
	StatParameter() :
		PointerOutParameter("struct stat"),
		m_stat()
	{}

	~StatParameter() override;

	std::string str() const override;

protected:
	void exitedCall(const TracedProc &proc) override;

protected:
	FileModeParameter m_mode;
	struct stat *m_stat;
};


/**
 * \brief
 * 	Memory protection used e.g. in mprotect()
 **/
class MemoryProtectionParameter :
	public ValueInParameter
{
public:

	MemoryProtectionParameter() :
		ValueInParameter("protection")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A list of directory entries
 **/
class DirEntries :
	public PointerOutParameter
{
public:

	DirEntries() :
		PointerOutParameter("struct linux_dirent")
	{}

	std::string str() const override;

protected:

	void exitedCall(const TracedProc &proc) override;

protected:

	std::list<std::string> m_entries;
};

/**
 * \brief
 * 	The operation to performed on a signal set
 **/
class SigSetOperation :	
	public ValueInParameter
{
public:
	SigSetOperation() :
		ValueInParameter("operation")
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

	void enteredCall(const TracedProc &proc) override
	{
		if( this->isIn() )
			fill(proc);
	}

	void exitedCall(const TracedProc &proc) override
	{
		if( this->isOut() )
			fill(proc);
	}


	void fill(const TracedProc &proc);

protected:

	struct timespec *m_timespec;
};

/**
 * \brief
 * 	The futex operation to be performed in the context of a futex system
 * 	call
 **/
class FutexOperation :
	public ValueInParameter
{
public:
	FutexOperation() :
		ValueInParameter("operation")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A signal number specification
 **/
class SignalParameter :
	public ValueInParameter
{
public:
	SignalParameter() :
		ValueInParameter("signal_nr")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The struct sigaction used in various signal related system calls
 **/
class SigactionParameter :
	public PointerInParameter
{
public:
	SigactionParameter(const char *name = "sigaction") :
		PointerInParameter(name),
		m_sigaction(nullptr)
	{}

	~SigactionParameter() override;

	std::string str() const override;

protected:

	void enteredCall(const TracedProc &proc) override;

protected:

	struct kernel_sigaction *m_sigaction;
};

/**
 * \brief
 * 	A set of POSIX signals for setting or masking in the context of
 * 	various system calls
 **/
class SigSetParameter :
	public PointerInParameter
{
public:
	SigSetParameter(const char *name = "signal_set") :
		PointerInParameter(name),
		m_sigset(nullptr)
	{}

	~SigSetParameter() override;

	std::string str() const override;

protected:

	void enteredCall(const TracedProc &proc) override;

protected:

	sigset_t *m_sigset;
};

/**
 * \brief
 * 	A resource kind specification as used in getrlimit & friends
 **/
class ResourceType :
	public ValueInParameter
{
public:
	ResourceType() :
		ValueInParameter("resource")
	{}

	std::string str() const override;
};

class ResourceLimit :
	public PointerOutParameter
{
public:
	ResourceLimit() :
		PointerOutParameter("limit"),
		m_limit(nullptr)
	{}

	~ResourceLimit() override;

	std::string str() const override;

protected:

	void exitedCall(const TracedProc &proc) override;

protected:

	struct rlimit *m_limit;
};

} // end ns

#endif // inc. guard

