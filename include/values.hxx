#pragma once

// C++
#include <list>

// Linux
#include <sys/stat.h>
#include <sys/resource.h>

// clues
#include <clues/SystemCall.hxx>
#include <clues/SystemCallValue.hxx>
#include <clues/KernelStructs.hxx>

/*
 * Various specializations of SystemCallValue are found in this header
 */

namespace clues {

/// A file descriptor system call parameter.
class CLUES_API FileDescriptor :
		public SystemCallValue {
public: // functions

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
			SystemCallValue{type, "fd", "file descriptor"},
			m_at_semantics{at_semantics} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override {};

	void updateData(const Tracee &) override {};

protected: // data
	bool m_at_semantics = false;
};

class FileDescriptorParameter :
		public FileDescriptor {
public: // functions
	explicit FileDescriptorParameter(const bool at_semantics = false) :
			FileDescriptor{Type::PARAM_IN, at_semantics}
	{}
};

/// A file descriptor return value with added errno semantics.
class CLUES_API FileDescriptorReturnValue :
		public FileDescriptor {
public: // functions
	explicit FileDescriptorReturnValue() :
			FileDescriptor{Type::RETVAL, false} {
	}

protected: // functions

	std::string str() const override;
};

/// An errno system call result.
/**
 * Often system call return values are dual natured: a negative return value
 * denotes an errno, a positive return value denotes some kind of identifier
 * like a PID, for example.
 * 
 * `highest_errno` therefore denotes the largest integer value that is still
 * to be interpreted as an errno, while any larger value denotes some kind of
 * successful return data item.
 **/
// TODO: maybe we should model dual natured return values like: PIDReturnValue
// that outputs an errno in case of error, and alike.
class CLUES_API ErrnoResult :
		public ReturnValue {
public: // functions
	ErrnoResult(
		const int highest_errno = 0,
		const char *short_label = "errno",
		const char *long_label = nullptr) :
			ReturnValue{short_label, long_label},
			m_highest{highest_errno} {
	}

	std::string str() const override;

protected: // data

	int m_highest;
};


/*
 * 	TODO: support to get the length of the data area from a
 * 	context-sensitive sibling parameter and then print out the
 * 	binary/ascii data as appropriate
 */
class CLUES_API GenericPointerValue :
		public PointerValue {
public: // functions

	explicit GenericPointerValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // data

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

/// c-string system call data.
class CLUES_API StringData :
		public SystemCallValue {
public: // functions
	explicit StringData(
		const char *short_name = nullptr,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
			SystemCallValue{type, short_name ? short_name : "string", long_name} {
	}

	std::string str() const override { return std::string{"\""} + m_str + "\""; }

protected: // functions

	void processValue(const Tracee &proc) override {
		if (! this->isOut()) {
			fetch(proc);
		}
	}

	void updateData(const Tracee &proc) override {
		fetch(proc);
	}


	void fetch(const Tracee &);

protected: // data

	std::string m_str;
};

/// An array of c-strings system call data.
/**
 * This is currently only used for argv and envp of the execve system call.
 **/
class CLUES_API StringArrayData :
		public PointerInValue {
public: // functions

	explicit StringArrayData(
		const char *short_name = nullptr,
		const char *long_name = nullptr) :
			PointerInValue{
				short_name ? short_name : "string-array",
				long_name
			} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // functions

	std::vector<std::string> m_strs;
};

/// The flags passed to e.g. open().
class CLUES_API OpenFlagsValue :
		public SystemCallValue {
public:
	explicit OpenFlagsValue(const Type &type = Type::PARAM_IN) :
			SystemCallValue{type, "flags", "open flags"} {
	}

	std::string str() const override;


protected: // functions

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

class AccessModeParameter :
		public ValueInParameter {
public:
	explicit AccessModeParameter() :
		ValueInParameter{"check", "access check"} {
	}

	std::string str() const override;
};

/// The code parameter to the arch_prctl system call.
class CLUES_API ArchCodeParameter :
		public ValueInParameter {
public:
	explicit ArchCodeParameter() :
			ValueInParameter{"subfunction"} {
	}

	std::string str() const override;
};

/// File access mode passed e.g. to open(), chmod().
class FileModeParameter :
		public ValueInParameter {
public:

	FileModeParameter() :
		ValueInParameter{"mode", "file-mode"} {
	}

	std::string str() const override;
};

/// The stat structure used in stat() & friends.
class CLUES_API StatParameter :
		public PointerOutValue {
public: // functions
	explicit StatParameter() :
		PointerOutValue{"stat", "struct stat"} {
	}

	~StatParameter() override;

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	FileModeParameter m_mode;
	struct ::stat *m_stat = nullptr;
};

/// Memory protection used e.g. in mprotect().
class MemoryProtectionParameter :
		public ValueInParameter {
public: // data

	explicit MemoryProtectionParameter() :
		ValueInParameter{"prot", "protection"} {
	}

	std::string str() const override;
};

/// A list of directory entries.
class CLUES_API DirEntries :
		public PointerOutValue {
public: // functions

	explicit DirEntries() :
			PointerOutValue{"dirent", "struct linux_dirent"}
	{}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::list<std::string> m_entries;
};

/// The operation to performed on a signal set.
class CLUES_API SigSetOperation :
		public ValueInParameter {
public:
	explicit SigSetOperation() :
		ValueInParameter{"sigsetop", "signal set operation"} {
	}

	std::string str() const override;
};

/// The struct timespec used for various timing and timeout operations in system calls.
class CLUES_API TimespecParameter :
		public SystemCallValue {
public: // functions
	explicit TimespecParameter(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_IN) :
			SystemCallValue{type, short_name, long_name} {
	}

	~TimespecParameter() override;

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override {
		if (!this->isOut())
			fetch(proc);
	}

	void updateData(const Tracee &proc) override {
		fetch(proc);
	}


	void fetch(const Tracee &proc);

protected: // data

	struct timespec *m_timespec = nullptr;
};

/// The futex operation to be performed in the context of a futex system call.
class CLUES_API FutexOperation :
		public ValueInParameter {
public: // functions
	explicit FutexOperation() :
		ValueInParameter{"op", "futex operation"} {
	}

	std::string str() const override;
};

/// A signal number specification.
class SignalNumber :
		public ValueInParameter {
public: // functions
	explicit SignalNumber() :
		ValueInParameter{"signum", "signal number"} {
	}

	std::string str() const override;
};

/// The struct sigaction used in various signal related system calls.
class CLUES_API SigactionParameter :
		public PointerInValue {
public: // functions
	explicit SigactionParameter(
		const char *short_name = "sigaction",
		const char *long_name = "struct sigaction") :
			PointerInValue{short_name, long_name} {
	}

	~SigactionParameter() override;

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	struct kernel_sigaction *m_sigaction = nullptr;
};

/// A set of POSIX signals for setting or masking in the context of various system calls.
class CLUES_API SigSetParameter :
		public PointerInValue {
public: // functions
	explicit SigSetParameter(
		const char *short_name = "sigset", const char *name = "signal set") :
			PointerInValue{short_name, name} {
	}

	~SigSetParameter() override;

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	sigset_t *m_sigset = nullptr;
};

/// A resource kind specification as used in getrlimit & friends.
class CLUES_API ResourceType :
		public ValueInParameter {
public: // functions
	explicit ResourceType() :
			ValueInParameter{"resource", "resource type"} {
	}

	std::string str() const override;
};

class CLUES_API ResourceLimit :
		public PointerOutValue {
public: // functions
	explicit ResourceLimit() :
			PointerOutValue{"limit"} {
	}

	~ResourceLimit() override;

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	struct rlimit *m_limit;
};

} // end ns
