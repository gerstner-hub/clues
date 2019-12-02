#ifndef TUXTRACE_SUBPROC_HXX
#define TUXTRACE_SUBPROC_HXX

// C++
#include <iosfwd>
#include <string>

// Linux
#include <unistd.h>

// tuxtrace
#include <tuxtrace/include/types.hxx>
#include <tuxtrace/include/WaitRes.hxx>

namespace tuxtrace
{
	class SubProc;
}

std::ostream& operator<<(std::ostream&, const tuxtrace::SubProc &);

namespace tuxtrace
{

/**
 * \brief
 * 	Class representing a child process created by us via fork/exec or
 * 	whatever
 **/
class SubProc
{
	friend class TracedSubProc;
public:
	SubProc();

	~SubProc();

	bool running() const { return m_pid != INVALID_PID; }

	std::string exe() const
	{
		return m_argv.empty() ? std::string("") : m_argv[0];
	}

	void setExe(const std::string &exe)
	{
		if( ! m_argv.empty() )
			m_argv[0] = exe;

		m_argv.push_back(exe);
	}

	const StringVector& args() const { return m_argv; }

	void setArgs(const StringVector &sv) { m_argv = sv; }

	void clearArgs(const bool and_exe = false)
	{
		m_argv.erase( and_exe ? m_argv.begin() : m_argv.begin() + 1 );
	}

	/**
	 * \brief
	 * 	Run a subprocess, either the one temporarily specified in \c
	 * 	sv or the one configured in \c m_argv via setArgs()
	 **/
	void run(const StringVector &sv = StringVector());

	WaitRes wait();

	void kill(int signal);

	void setCWD(const std::string &cwd) { m_cwd = cwd; }

	const std::string& cwd() const { return m_cwd; }

	void setEnv(const std::string &block) { m_env = block; }

	void setTrace(const bool trace) { m_trace = trace; }
	bool trace() const { return m_trace; }

	pid_t pid() const { return m_pid; }

public: // data

	static const pid_t INVALID_PID;

protected: // functions

	//! \brief
	//! performs settings done after forking i.e. in the child process but
	//! before exec() ing
	void postFork();

	void exec(CStringVector &v);

	/**
	 * \brief
	 * 	Called from TracedProc if we've started a tracee subprocess
	 * 	and an external wait was done for it that we don't know of
	 * \details
	 * 	The WaitRes \c r is the result the child process delivered, if
	 * 	we need to know something from it ...
	 *
	 * 	Otherwise the function resets the information about the
	 * 	running process in the SubProc object so no errors occur upon
	 * 	destruction etc.
	 **/
	void gone(const WaitRes &r);

protected: // data

	//! the pid of the child process, if any
	pid_t m_pid;
	//! executable plus arguments to use
	StringVector m_argv;
	//! an explicit working directory, if any
	std::string m_cwd;
	//! an explicit environment block, if any
	std::string m_env;
	//! whether the child process shall become a tracee of us
	bool m_trace;

	friend std::ostream& ::operator<<(std::ostream&, const SubProc &);
};

} // end ns

std::ostream& operator<<(std::ostream &o, const tuxtrace::SubProc &proc);

tuxtrace::SubProc& operator<<(tuxtrace::SubProc &proc, const std::string &arg);

#endif // inc. guard

