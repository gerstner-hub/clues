#ifndef CLUES_VALUES_HXX
#define CLUES_VALUES_HXX

// C++
#include <list>

// Linux

// clues
#include "clues/SystemCall.hxx"
#include "clues/SystemCallValue.hxx"
#include "clues/KernelStructs.hxx"

/*
 * Various specializations of SystemCallValue are found in this header
 */

namespace clues
{

/**
 * \brief
 * 	A file descriptor system call parameter
 **/
class FileDescriptor :
	public SystemCallValue
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
	explicit FileDescriptor(
		const Type &type,
		const bool at_semantics = false) :
		SystemCallValue(type, "fd", "file descriptor"),
		m_at_semantics(at_semantics)
	{}

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override {};

	void updateData(const TracedProc &proc) override {};


protected:
	bool m_at_semantics = false;
};

class FileDescriptorParameter :
	public FileDescriptor
{
public:
	explicit FileDescriptorParameter(const bool at_semantics = false) :
		FileDescriptor(Type::PARAM_IN, at_semantics)
	{}
};

/**
 * \brief
 *	A file descriptor return value with added errno semantics
 **/
class FileDescriptorReturnValue :
	public FileDescriptor
{
public:
	explicit FileDescriptorReturnValue() :
		FileDescriptor(Type::RETVAL, false)
	{}

protected:

	std::string str() const override;
};

/**
 * \brief
 * 	An errno system call result
 * \details
 * 	Often system call return values are dual natured: a negative return
 * 	value denotes an errno, a positive return value denotes some kind of
 * 	identifier like a PID, for example.
 *
 *	\c highest_errno therefore denotes the largest integer value that is
 *	still to be interpreted as an errno, while any larger value denotes
 *	some kind of successful return data item.
 **/
// TODO: maybe we should model dual natured return values like: PIDReturnValue
// that outputs an errno in case of error, and alike.
class ErrnoResult :
	public ReturnValue
{
public:
	ErrnoResult(
		const int highest_errno = 0,
		const char *short_label = "errno",
		const char *long_label = nullptr) :
		ReturnValue(short_label, long_label),
		m_highest(highest_errno)
	{}

	std::string str() const override;
protected:

	int m_highest;
};


/**
 * 	TODO: support to get the length of the data area from a
 * 	context-sensitive sibbling parameter and then print out the
 * 	binary/ascii data as appropriate
 **/
class GenericPointerValue :
	public PointerValue
{
public:
	explicit GenericPointerValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
		PointerValue(type, short_name, long_name)
	{}

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override {}
	void updateData(const TracedProc &proc) override {}
};

/**
 * \brief
 * 	c-string system call data
 **/
class StringData :
	public SystemCallValue
{
public:
	explicit StringData(
		const char *short_name = nullptr,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
		SystemCallValue( type, short_name ? short_name : "string", long_name )
	{}

	std::string str() const override { return std::string("\"") + m_str + "\""; }

protected:

	void processValue(const TracedProc &proc) override
	{
		if( ! this->isOut() )
		{
			fetch(proc);
		}
	}

	void updateData(const TracedProc &proc) override
	{
		fetch(proc);
	}


	void fetch(const TracedProc &proc);

protected:

	std::string m_str;
};

/**
 * \brief
 * 	An array of c-strings system call data
 * \details
 * 	This is currently only used for argv and envp of the execve system
 * 	call
 **/
class StringArrayData :
	public PointerInValue
{
public:

	explicit StringArrayData(
		const char *short_name = nullptr,
		const char *long_name = nullptr) :
		PointerInValue(
			short_name ? short_name : "string-array",
			long_name
		)
	{}

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override;

protected:

	std::vector<std::string> m_strs;
};

/**
 * \brief
 * 	The flags passed to e.g. open()
 **/
class OpenFlagsValue :
	public SystemCallValue
{
public:
	explicit OpenFlagsValue(const Type &type = Type::PARAM_IN) :
		SystemCallValue(type, "flags", "open flags")
	{}

	std::string str() const override;


protected: // functions

	void processValue(const TracedProc &proc) override {}
	void updateData(const TracedProc &proc) override {}
};

class AccessModeParameter :
	public ValueInParameter
{
public:
	explicit AccessModeParameter() :
		ValueInParameter("check", "access check")
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
	explicit ArchCodeParameter() :
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
		ValueInParameter("mode", "file-mode")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The stat structure used in stat() & friends
 **/
class StatParameter :
	public PointerOutValue
{
public:
	explicit StatParameter() :
		PointerOutValue("stat", "struct stat")
	{}

	~StatParameter() override;

	std::string str() const override;

protected:
	void updateData(const TracedProc &proc) override;

protected:
	FileModeParameter m_mode;
	struct stat *m_stat = nullptr;
};


/**
 * \brief
 * 	Memory protection used e.g. in mprotect()
 **/
class MemoryProtectionParameter :
	public ValueInParameter
{
public:

	explicit MemoryProtectionParameter() :
		ValueInParameter("prot", "protection")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A list of directory entries
 **/
class DirEntries :
	public PointerOutValue
{
public:

	explicit DirEntries() :
		PointerOutValue("dirent", "struct linux_dirent")
	{}

	std::string str() const override;

protected:

	void updateData(const TracedProc &proc) override;

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
	explicit SigSetOperation() :
		ValueInParameter("sigsetop", "signal set operation")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The struct timespec used for various timing and timeout operations
 * 	in system calls
 **/
class TimespecParameter :
	public SystemCallValue
{
public:
	explicit TimespecParameter(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
		SystemCallValue(type, short_name, long_name)
	{}

	~TimespecParameter() override;

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override
	{
		if( !this->isOut() )
			fetch(proc);
	}

	void updateData(const TracedProc &proc) override
	{
		fetch(proc);
	}


	void fetch(const TracedProc &proc);

protected:

	struct timespec *m_timespec = nullptr;
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
	explicit FutexOperation() :
		ValueInParameter("op", "futex operation")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	A signal number specification
 **/
class SignalNumber :
	public ValueInParameter
{
public:
	explicit SignalNumber() :
		ValueInParameter("signum", "signal number")
	{}

	std::string str() const override;
};

/**
 * \brief
 * 	The struct sigaction used in various signal related system calls
 **/
class SigactionParameter :
	public PointerInValue
{
public:
	explicit SigactionParameter(
		const char *short_name = "sigaction",
		const char *long_name = "struct sigaction") :
		PointerInValue(short_name, long_name)
	{}

	~SigactionParameter() override;

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override;

protected:

	struct kernel_sigaction *m_sigaction = nullptr;
};

/**
 * \brief
 * 	A set of POSIX signals for setting or masking in the context of
 * 	various system calls
 **/
class SigSetParameter :
	public PointerInValue
{
public:
	explicit SigSetParameter(
		const char *short_name = "sigset", const char *name = "signal set") :
		PointerInValue(name)
	{}

	~SigSetParameter() override;

	std::string str() const override;

protected:

	void processValue(const TracedProc &proc) override;

protected:

	sigset_t *m_sigset = nullptr;
};

/**
 * \brief
 * 	A resource kind specification as used in getrlimit & friends
 **/
class ResourceType :
	public ValueInParameter
{
public:
	explicit ResourceType() :
		ValueInParameter("resource", "resource type")
	{}

	std::string str() const override;
};

class ResourceLimit :
	public PointerOutValue
{
public:
	explicit ResourceLimit() :
		PointerOutValue("limit")
	{}

	~ResourceLimit() override;

	std::string str() const override;

protected:

	void updateData(const TracedProc &proc) override;

protected:

	struct rlimit *m_limit;
};

} // end ns

#endif // inc. guard

