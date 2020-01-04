// C++
#include <cstdlib>
#include <iostream>

// Linux
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>

// clues
#include "clues/errors/ApiError.hxx"
#include "clues/errors/InternalError.hxx"
#include "clues/errors/UsageError.hxx"
#include "clues/SubProc.hxx"

namespace clues
{

SubProc::SubProc()
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
		clues_throw( UsageError(
			"attempted to run a subprocess w/o specifying an executable path"
		) );
	}

	switch( (m_pid = ::fork()) )
	{
	default: // parent process with child pid
		// as documented, to prevent future inheritance of undefined
		// file descriptor state
		resetStdFiles();
		return;
	case -1: // an error occured
		// see above, same for error case
		resetStdFiles();
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

		for( auto &arg: args )
		{
			argv.push_back(arg.c_str());
		}

		argv.push_back(nullptr);

		this->exec(argv);
	}
	catch( const CluesError &ce )
	{
		std::cerr
			<< "Execution of child process failed:\n"
			<< *this << "\n" << ce.what() << std::endl;
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

	redirectFD(STDOUT_FILENO, m_stdout);
	redirectFD(STDERR_FILENO, m_stderr);
	redirectFD(STDIN_FILENO, m_stdin);

	resetStdFiles();

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
		Signal::raiseSignal( Signal(SIGSTOP) );
	}
}

void SubProc::redirectFD(FileDesc orig, FileDesc redirect)
{
	if( redirect == INVALID_FILE_DESC )
		return;

	/*
	 * the second parameter is newfd, the number under which the first
	 * parameter will be known in the future. a bit confusing naming
	 * scheme.
	 *
	 * note that dup2 automatically removes any O_CLOEXEC flag from the
	 * orig file descriptor, so inheriting it across exec*() is not a
	 * problem.
	 */
	if( dup2(redirect, orig) == -1 )
	{
		clues_throw( ApiError() );
	}
}

void SubProc::exec(CStringVector &v)
{
	if( v.empty() )
	{
		clues_throw( InternalError("called with empty argument vector") );
	}

	::execvp( v[0], const_cast<char**>(v.data()) );

	clues_throw( ApiError() );
}

void SubProc::kill(const Signal &s)
{
	Signal::sendSignal(m_pid, s);
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

bool SubProc::waitTimed(const size_t max_ms, WaitRes &res)
{
	res = WaitRes();
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGCHLD);

	struct timespec ts;
	auto left_ms = max_ms % 1000;
	ts.tv_sec = (max_ms - left_ms) / 1000;
	ts.tv_nsec = left_ms * 1000 * 1000;

	while(true)
	{
		auto res = sigtimedwait(&sigs, nullptr, &ts);

		if( res != -1 )
			break;

		switch(errno)
		{
		case EINTR:
			// TODO: the interface doesn't allow to sleep for the
			// correct left time, so we'll probably sleep to long
			// in this case. Rather claim it's an early timeout.
			return false;
		case EAGAIN:
			return false;
		default:
			clues_throw( ApiError() );
		}
	}

	// okay, something happened, let's check
	//
	// NOTE: in the timeout case the value in res.m_status can't be
	// differentiated from the non-timeout case if the child exited
	// successfully with exit code 0. Therefore we need to distuingish the
	// timeout condition using a separate bool and can't rely on the
	// WaitRes type.
	auto pid = ::waitpid(m_pid, &res.m_status, WNOHANG);

	if( pid == 0 )
	{
		// the child still didn't exit, bogus
		// sigtimedwait()? claim it's an early timeout
		return false;
	}
	else if( pid == -1 )
	{
		// something went wrong, clean up our state,
		// the child is probably lost in some way.
		m_pid = INVALID_PID;
		clues_throw( ApiError() );
	}

	m_pid = INVALID_PID;

	// okay the child actually exited
	return true;
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

