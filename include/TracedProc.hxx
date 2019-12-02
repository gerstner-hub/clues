#ifndef TUXTRACE_TRACEDPROC_HXX
#define TUXTRACE_TRACEDPROC_HXX

// C++
#include <vector>

// Linux
#include <unistd.h>
#include <sys/ptrace.h>

// tuxtrace
#include <tuxtrace/include/types.hxx>
#include <tuxtrace/include/TraceState.hxx>
#include <tuxtrace/include/SubProc.hxx>
#include <tuxtrace/include/Signal.hxx>

namespace tuxtrace
{

class RegisterSet;

/**
 * \brief
 * 	Different modes to continue a tracee
 **/
enum class ContinueMode
{
	//! continues the tracee without special side-effects
	NORMAL = PTRACE_CONT,
	//! continues, but stops it at the next entry/exit to a system call
	SYSCALL = PTRACE_SYSCALL,
	//! continues, but stops after execution of a single instruction
	SINGLESTEP = PTRACE_SINGLESTEP
};

enum class TraceOpts
{
	//! when the tracer exits all tracees will be sent SIGKILL
	//EXITKILL = PTRACE_O_EXITKILL,
	//! stop on clone(2) and trace the newly cloned process
	TRACECLONE = PTRACE_O_TRACECLONE,
	//! stop on the next execve(2)
	TRACEEXEC = PTRACE_O_TRACEEXEC,
	//! stop the tracee at exit
	TRACEEXIT = PTRACE_O_TRACEEXIT,
	//! stop at the next fork(2) and start trace on the newly forked proc.
	TRACEFORK = PTRACE_O_TRACEFORK,
	//! stop at the next vfork(2) and start trace on the newly forked proc
	TRACEVFORK = PTRACE_O_TRACEVFORK,
	//! stop tracee at completion of the next vfork(2)
	TRACEVFORKDONE = PTRACE_O_TRACEVFORKDONE,
	//! on system call traps the bit 7 in sig number (SIGTRAP|0x80)
	TRACESYSGOOD = PTRACE_O_TRACESYSGOOD
};

class SystemCall;

/**
 * \brief
 * 	pure virtual interface for consumers of tracing events
 **/
class TraceEventConsumer
{
	friend class TracedProc;
protected: // functions

	virtual void syscallEntry(const SystemCall &sc) = 0;

	virtual void syscallExit(const SystemCall &sc) = 0;
};

/**
 * \brief
 * 	Base class for traced processes
 * \details
 * 	The concrete implementation of TracedProc defines the means of how the
 * 	traced process is attached to and detached from etc.
 **/
class TracedProc
{
public:
	virtual ~TracedProc() {}

	/**
	 * \brief
	 * 	Logic to handle attaching to the tracee
	 **/
	virtual void attach() = 0;

	/**
	 * \brief
	 * 	Logic to handle detaching from the tracee
	 **/
	virtual void detach() = 0;

	/**
	 * \brief
	 * 	Actually start tracing the tracee
	 **/
	void trace();

	/**
	 * \brief
	 * 	Reads a word of data from the tracee's memory
	 * \details
	 * 	The word found at \c addr is returned from this function on
	 * 	success. On error an exception is thrown.
	 **/
	long getData(const long *addr) const;

protected:

	TracedProc(TraceEventConsumer &consumer);

	/**
	 * \brief
	 * 	Waits for the next trace event of this tracee
	 **/
	void wait(WaitRes &res);
	
	/**
	 * \brief
	 * 	Causes the traced process to stop
	 **/
	void interrupt();

	/**
	 * \brief
	 * 	Continues the traced process, optionally delivering \c signal
	 **/
	void cont(
		const ContinueMode &mode = ContinueMode::NORMAL,
		const Signal &signal = Signal(0)
	);

	/**
	 * \brief
	 * 	Returns a message about the current ptrace event
	 * \details
	 * 	This is either the exit status if the child exited or the PID
	 * 	of a new process for fork/clone tracing.
	 **/
	unsigned long getEventMsg() const;

	/**
	 * \brief
	 * 	Sets \c options, a bitmask of TraceOpts
	 **/
	void setOptions(int options);

	/**
	 * \brief
	 * 	Makes the tracee a tracee
	 **/
	void seize();

	/**
	 * \brief
	 * 	Sets the tracee, if not already done so
	 **/
	void setTracee(const pid_t &tracee);

	//! called when the tracee exits
	virtual void exited(const WaitRes &r) {}

	/**
	 * \brief
	 * 	Reads the current register set from the process
	 * \details
	 * 	This is only possible it the tracee is currently in stopped
	 * 	state
	 **/
	void getRegisters(RegisterSet &rs);

protected:
	//! callback interface receiving our information
	TraceEventConsumer &m_consumer;
	//! the current state the tracee is in
	TraceState m_state;
	//! PID of the tracee we're dealing with
	pid_t m_tracee;
};
	
/**
 * \brief
 * 	Specialization of TracedProc that attaches to an existing, unrelated
 * 	process in the system
 **/
class TracedSeizedProc :
	public TracedProc
{
public: // functions

	/**
	 * \brief
	 * 	Create a traced process object by attaching to the given
	 * 	process ID
	 **/
	TracedSeizedProc(TraceEventConsumer &consumer);

	~TracedSeizedProc() override;

	/**
	 * \brief
	 * 	Sets the given process ID as the process to be traced
	 **/
	void configure(const pid_t &tracee);

	void attach() override;
	void detach() override;

protected: // data

};

/**
 * \brief
 * 	Specialization of TracedProc that creates a new child process for
 * 	tracing
 **/
class TracedSubProc :
	public TracedProc
{
public: // functions

	/**
	 * \brief
	 * 	Create a traced process by creating a new process from \c
	 * 	prog_args
	 **/
	TracedSubProc(TraceEventConsumer &consumer);

	~TracedSubProc() override;

	/**
	 * \brief
	 * 	Set the child process executable and parameters to trace
	 **/
	void configure(const StringVector &prog_args);
	void attach() override;
	void detach() override;

	//! the exit code of the sub-process, valid only after detach()
	int exitCode() const { return m_exit_code; }

protected: // functions

	void exited(const WaitRes &r) override;

protected: // data

	//! sub-process we're tracing
	SubProc m_child;
	int m_exit_code;
};


} // end ns

#endif // inc. guard

