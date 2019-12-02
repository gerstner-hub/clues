// tuxtrace
#include <tuxtrace/include/SystemCallDB.hxx>
#include <tuxtrace/include/Parameters.hxx>

// Linux
#include <sys/syscall.h> // system call nr. constants

namespace tuxtrace
{

SystemCallDB::~SystemCallDB()
{
	for( auto &pair: *this )
	{
		delete pair.second;
	}

	this->clear();
}

SystemCall& SystemCallDB::get(const SystemCallNr nr)
{
	iterator it = find(nr);

	if( it == end() )
	{
		std::pair<iterator, bool> res;
		res = insert(
			std::make_pair(
				nr,
				createSysCall(nr)
			)
		);

		it = res.first;
	}

	return *(it->second);
}
				
SystemCall* SystemCallDB::createSysCall(
	const SystemCallNr nr)
{
	typedef SystemCallParameter Par;
	typedef SystemCall Call;

	switch( nr )
	{
	case SYS_write:
		return new Call(nr, "write",
			new Par("bytes written"),
			{
				new FileDescriptorParameter(),
				new PointerParameter("source buffer"),
				new Par("buffer length")
			}
		);
	case SYS_read:
		return new Call(nr, "read",
			new Par("bytes read"),
			{
				new FileDescriptorParameter(),
				new PointerParameter("target buffer", Par::OUT),
				new Par("buffer length")
			}
		);
	case SYS_brk:
		return new Call(nr, "brk",
			new PointerParameter("actual data segment end"),
			{
				new PointerParameter("requested data segment end")
			}
		);
	case SYS_nanosleep:
		return new Call(nr, "nanosleep",
			new ErrnoResult(),
			{
				new PointerParameter("requested"),
				new PointerParameter("remaining", Par::OUT)
			}
		);
	case SYS_alarm:
		return new Call(nr, "alarm",
			new Par("prev_remaining_seconds"),
			{
				new Par("seconds")
			}
		);
	case SYS_access:
		return new Call(nr, "access",
			new ErrnoResult(),
			{
				new StringParameter("filename"),
				new Par("mode")
			}
		);
	case SYS_fcntl:
		return new Call(nr, "fcntl",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new Par("command")
			}
		);
	case SYS_fstat:
		return new Call(nr, "fstat",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new StatParameter()
			}
		);
	case SYS_lstat:
	case SYS_stat:
		return new Call(nr, nr == SYS_stat ? "stat" : "lstat",
			new ErrnoResult(),
			{
				new StringParameter("pathname"),
				new StatParameter()
			}
		);
	case SYS_mmap:
		return new Call(nr, "mmap",
			new PointerParameter("new_memory", Par::OUT),
			{
				new PointerParameter("hint"),
				new Par("length"),
				new Par("protocol"),
				new Par("flags"),
				new FileDescriptorParameter(),
				new Par("offset")
			}
		);
	case SYS_munmap:
		return new Call(nr, "munmap",
			new ErrnoResult(),
			{
				new PointerParameter("memory"),
				new Par("length")
			}
		);
	case SYS_mprotect:
		return new Call(nr, "mprotect",
			new ErrnoResult(),
			{
				new PointerParameter("addr"),
				new Par("length"),
				new MemoryProtectionParameter()
			}
		);
	case SYS_arch_prctl:
		return new Call(nr, "arch_prctl",
			new ErrnoResult(),
			{
				new ArchCodeParameter(),
				new PointerParameter("addr")
			}
		);
	case SYS_open:
		return new Call(nr, "open",
			new FileDescriptorParameter(Par::OUT),
			{
				new StringParameter("filename"),
				new OpenFlagsParameter(),
				new FileModeParameter()
			}
		);
	case SYS_openat:
		return new Call(nr, "openat",
			new FileDescriptorParameter(Par::OUT),
			{
				new FileDescriptorParameter(
					Par::IN, true /* at semantics */),
				new StringParameter("filename"),
				new OpenFlagsParameter(),
				new FileModeParameter()
			}
		);
	case SYS_close:
		return new Call(nr, "close",
			new ErrnoResult(),
			{
				new FileDescriptorParameter()
			}
		);
	case SYS_execve:
		return new Call(nr, "execve",
			new ErrnoResult(),
			{
				new StringParameter("filename"),
				new StringArrayParameter("argv"),
				new StringArrayParameter("envp")
			}
		);
	case SYS_ioctl:
		return new Call(nr, "ioctl",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new PointerParameter("request")
			}
		);
	case SYS_getdents:
		return new Call(nr, "getdents",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new DirEntries(),
				new Par("dirent_size")
			}
		);
	case SYS_getuid:
	case SYS_geteuid:
	{
		return new Call(
			nr,
			nr == SYS_getuid ? "getuid" : "geteuid",
			new Par("id"),
			{}
		);
	}
	default:
		return new Call(nr, "unknown",
			new Par("result"),
			{} );
	}
}

} // end ns

