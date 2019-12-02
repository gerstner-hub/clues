#ifndef TUXTRACE_WAITRES_HXX
#define TUXTRACE_WAITRES_HXX

// C++
#include <iosfwd>

// Linux
#include <sys/types.h>
#include <sys/wait.h>

// tuxtrace
#include <tuxtrace/include/Signal.hxx>
#include <tuxtrace/include/ptrace.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	Result from a wait() call
 **/
class WaitRes
{
	friend class SubProc;
public: // functions

	WaitRes(const int status = 0) :
		m_status(status)
	{}

	bool stopped() const { return WIFSTOPPED(m_status) != 0; }

	bool exited() const { return WIFEXITED(m_status) != 0; }

	int exitStatus() const { return WEXITSTATUS(m_status); }

	/**
	 * \brief
	 * 	Returns the signal that caused the child to stop if stopped()
	 **/
	Signal stopSignal() const
	{
		return stopped() ?
			Signal(WSTOPSIG(m_status) & (~0x80)) : Signal(0);
	}

	/**
	 * \brief
	 *	returns true if the child stopped due to syscall tracing
	 * \note
	 * 	This only works if the TRACESYSGOOD option was set
	 **/
	bool syscallTrace() const
	{
		return stopped() && WSTOPSIG(m_status) == (SIGTRAP | 0x80);
	}

	/**
	 * \brief
	 * 	Checks whether the given event occured
	 * \details
	 * 	These events only occur if the corresponding TraceOpts have
	 * 	been set on the tracee
	 **/
	bool checkEvent(const TraceEvent &event)
	{
		if( ! stopped() )
			return false;

		return (m_status >> 8) == (SIGTRAP | ((int)event << 8));
	}

	int* raw() { return &m_status; }
	const int* raw() const { return &m_status; }

protected: // data

	//! the raw status
	int m_status;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const tuxtrace::WaitRes &res);

#endif // inc. guard

