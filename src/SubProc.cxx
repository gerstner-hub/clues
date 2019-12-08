// C++
#include <cstdlib>
#include <iostream>

// Linux
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

// clues
#include "clues/ApiError.hxx"
#include "clues/InternalError.hxx"
#include "clues/SubProc.hxx"

namespace clues
{

const pid_t SubProc::INVALID_PID = -1;

SubProc::SubProc() :
	m_pid(INVALID_PID),
	m_trace(false)
{}

SubProc::~SubProc()
{
	if( m_pid != INVALID_PID )
	{
		std::cerr << "child process still running: " << m_pid << "\n";
		std::abort();
	}
}

void SubProc::run(const StringVector &sv)
{
	const StringVector &args = sv.empty() ? m_argv : sv;

	if( args.empty() )
	{
		throw 5;
	}

	switch( (m_pid = ::fork()) )
	{
	default: // parent process with child pid
		return;
	case -1: // an error occured
		clues_throw( ApiError() );
		return;
	case 0: // the child process
		// let's do something!
		break;
	}

	try
	{
		postFork();

		CStringVector argv;

		for( auto arg: args )
		{
			argv.push_back(arg.c_str());
		}

		argv.push_back(NULL);

		this->exec(argv);
	}
	catch( const TuxTraceError &tte )
	{
		std::cerr
			<< "Execution of child process failed:\n"
			<< *this << "\n" << tte.what() << std::endl;
		::_exit(1);
	}
}

void SubProc::postFork()
{
	if( ! m_cwd.empty() )
	{
		if( ::chdir(m_cwd.c_str()) != 0 )
		{
			clues_throw( ApiError() );
		}
	}

	if( m_trace )
	{
#if 0
		// actually if we make our parent a tracer this way then we
		// can't deal with it the "new" way as possible with SEIZED
		// processes. So we only raise a SIGSTOP as below to have the
		// parent catch us before doing anything else and otherwise
		// the parent can SEIZE us.
		if( ::ptrace( PTRACE_TRACEME, INVALID_PID, 0, 0 ) != 0 )
		{
			clues_throw( ApiError() );
		}
#endif

		// this allows our parent to wait for us such that is knows
		// we're a tracee now
		if( ::raise( SIGSTOP ) )
		{
			clues_throw( ApiError() );
		}
	}
}

void SubProc::exec(CStringVector &v)
{
	if( v.empty() )
	{
		clues_throw( InternalError("called with empty argument vector") );
	}

	::execvp(
		v[0],
		const_cast<char**>(v.data())
	);

	clues_throw( ApiError() );
}

void SubProc::kill(int signal)
{
	if( ::kill( m_pid, signal ) )
	{
		clues_throw( ApiError() );
	}
}

WaitRes SubProc::wait()
{
	WaitRes wr;

	pid_t pid = m_pid;
	m_pid = INVALID_PID;

	if( ::waitpid(pid, &wr.m_status, 0) == -1 )
	{
		clues_throw( ApiError() );
	}

	return wr;
}

void SubProc::gone(const WaitRes &r)
{
	m_pid = INVALID_PID;
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SubProc &proc)
{
	o << "Subprocess PID " << proc.m_pid << "\n";
	o << "Arguments: " << proc.args() << "\n";
	if( !proc.cwd().empty() )
		o << "CWD: " << proc.cwd() << "\n";
	if( !proc.trace() )
		o << "Trace: " << proc.trace() << "\n";

	return o;
}

