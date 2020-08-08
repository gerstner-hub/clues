#ifndef CLUES_TRACEDPROC_HXX
#define CLUES_TRACEDPROC_HXX

// C++

// Linux
#include <unistd.h>
#include <sys/ptrace.h>

// cosmos
#include "cosmos/proc/SubProc.hxx"
#include "cosmos/proc/Signal.hxx"
#include "cosmos/proc/ptrace.hxx"

// clues
#include "clues/types.hxx"
#include "clues/RegisterSet.hxx"
#include "clues/SystemCallDB.hxx"
#include "clues/TraceState.hxx"

using namespace cosmos;

namespace clues
{

class RegisterSet;
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

public: // types

protected:

	explicit TracedProc(TraceEventConsumer &consumer);

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
	void setOptions(const cosmos::TraceOptsMask &opts);

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

	void handleSystemCall();

	void handleSignal(const WaitRes &wr);

protected:
	//! callback interface receiving our information
	TraceEventConsumer &m_consumer;
	//! the current state the tracee is in
	TraceState m_state = TraceState::UNKNOWN;
	//! PID of the tracee we're dealing with
	pid_t m_tracee = INVALID_PID;
	//! here we store our current knowledge open file descriptions
	DescriptorPathMapping m_fd_path_map;
	//! reusable database object for tracing system calls
	SystemCallDB m_syscall_db;
	//! reusable register set object for tracing system calls
	RegisterSet m_reg_set;
	//! holds state for the currently executing system call
	SystemCall *m_current_syscall = nullptr;
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
	int m_exit_code = 0;
};

} // end ns

#endif // inc. guard

