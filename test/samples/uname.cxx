#include <sys/utsname.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils/syscall32.hxx"

int main() {
	struct utsname uts;
	uname(&uts);

	/*
	 * for the old uname system calls on I386 we can use the same struct,
	 * the older structs are just smaller, for tracing purposes this is
	 * good enough.
	 */

#ifdef COSMOS_X86_64
	auto uts32 = alloc_struct32<struct utsname>();
	syscall32(SyscallNr32::OLDUNAME, uts32);
	syscall32(SyscallNr32::OLDOLDUNAME, uts32);
#elif defined(COSMOS_I386)
	syscall(SYS_olduname, &uts);
	syscall(SYS_oldolduname, &uts);
#endif
}
