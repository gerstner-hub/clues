#pragma once

// C++
#include <optional>
#include <vector>

// Linux
#include <sys/stat.h>
#include <sys/resource.h>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/items/ErrnoResult.hxx>
#include <clues/items/FileDescriptor.hxx>
#include <clues/items/strings.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/SystemCallItem.hxx>

/*
 * Various specializations of SystemCallItem are found in this header
 */

namespace clues::item {

/*
 * TODO: support to get the length of the data area from a context-sensitive
 * sibling parameter and then print out the binary/ascii data as appropriate
 */
class CLUES_API GenericPointerValue :
		public PointerValue {
public: // functions

	explicit GenericPointerValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type type = Type::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // data

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

/// The flags passed to calls like open().
class CLUES_API OpenFlagsValue :
		public SystemCallItem {
public:
	explicit OpenFlagsValue(const Type type = Type::PARAM_IN) :
			SystemCallItem{type, "flags", "open flags"} {
	}

	std::string str() const override;
};

/// The mode parameter in access().
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

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct ::stat> m_stat;
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

/// A range of directory entries from getdents().
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

	std::vector<std::string> m_entries;
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
		public SystemCallItem {
public: // functions
	explicit TimespecParameter(
		const char *short_name,
		const char *long_name = nullptr,
		const Type type = Type::PARAM_IN) :
			SystemCallItem{type, short_name, long_name} {
	}

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

	std::optional<struct timespec> m_timespec;
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

class CLUES_API ClockID :
		public ValueInParameter {
public: // functions
	explicit ClockID() :
			ValueInParameter{"clockid", "clock identifier"} {
	}

	std::string str() const override;
};

class CLUES_API ClockNanoSleepFlags :
		public ValueInParameter {
public: // functions
	explicit ClockNanoSleepFlags() :
			ValueInParameter{"flags", "clock sleep flags"} {
	}

	std::string str() const override;
};

/// A signal number specification.
class CLUES_API SignalNumber :
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

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<struct kernel_sigaction> m_sigaction;
};

/// A set of POSIX signals for setting or masking in the context of various system calls.
class CLUES_API SigSetParameter :
		public PointerInValue {
public: // functions
	explicit SigSetParameter(
		const char *short_name = "sigset", const char *name = "signal set") :
			PointerInValue{short_name, name} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<sigset_t> m_sigset;
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

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct rlimit> m_limit;
};

} // end ns
