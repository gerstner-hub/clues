// Clues
#include "clues/Process.hxx"

// Linux
#include <sys/types.h>
#include <unistd.h>

namespace clues
{

ProcessID Process::cachePid() const
{
	m_own_pid = ::getpid();
	return m_own_pid;
}

ProcessID Process::cachePPid() const
{
	m_parent_pid = ::getppid();
	return m_parent_pid;
}

Process g_process;

} // end ns

