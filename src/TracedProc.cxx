// C++
#include <iostream>

// Linux
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

// tuxtrace
#include <tuxtrace/include/TracedProc.hxx>
#include <tuxtrace/include/ApiError.hxx>
#include <tuxtrace/include/WaitRes.hxx>
#include <tuxtrace/include/RegisterSet.hxx>
#include <tuxtrace/include/SystemCall.hxx>
#include <tuxtrace/include/SystemCallDB.hxx>

namespace tuxtrace
{

TracedProc::TracedProc(TraceEventConsumer &consumer) :
	m_consumer(consumer),
	m_state(TraceState::UNKNOWN),
	m_tracee(SubProc::INVALID_PID)
{}

void TracedProc::setTracee(const pid_t &tracee)
{
	m_tracee = tracee;
}

void TracedProc::cont(
	const ContinueMode &mode,
	const Signal &signal)
{
	if( ::ptrace(
		static_cast<__ptrace_request>(mode),
		m_tracee,
		signal.raw() ? &signal.raw() : nullptr,
		nullptr ) )
	{
		tt_throw( ApiError() );
	}
}

unsigned long TracedProc::getEventMsg() const
{
	unsigned long ret;

	if( ::ptrace(
		PTRACE_GETEVENTMSG,
		m_tracee,
		nullptr,
		&ret) )
	{
		tt_throw( ApiError() );
	}

	return ret;
}

void TracedProc::setOptions(int options)
{
	if( ::ptrace(
		PTRACE_SETOPTIONS,
		m_tracee,
		nullptr,
		options) )
	{
		tt_throw( ApiError() );
	}
}

void TracedProc::interrupt()
{
	if( ::ptrace( PTRACE_INTERRUPT, m_tracee, nullptr, nullptr ) )
	{
		tt_throw( ApiError() );
	}
}

void TracedProc::seize()
{
	if( ::ptrace( PTRACE_SEIZE, m_tracee, nullptr, nullptr ) != 0 )
	{
		tt_throw( ApiError() );
	}
}

void TracedProc::wait(WaitRes &res)
{
	if( ::waitpid(m_tracee, res.raw(), 0) == -1 )
	{
		tt_throw( ApiError() );
	}
}

void TracedProc::trace()
{
	WaitRes wr;
	interrupt();

	SystemCallDB scdb;
	RegisterSet rs;
	SystemCall *sc = nullptr;

	while( true )
	{
		wait(wr);

		if( wr.stopped() )
		{
			//std::cout << "Tracee stopped" << std::endl;

			if( wr.syscallTrace() )
			{
				if( m_state != TraceState::SYSCALL_ENTER )
				{
					m_state = TraceState::SYSCALL_ENTER;
					getRegisters(rs);
					sc = &scdb.get(rs.syscall());
					sc->setEntryRegs(*this, rs);
					m_consumer.syscallEntry(*sc);
				}
				else
				{
					m_state = TraceState::SYSCALL_EXIT;
					getRegisters(rs);
					sc->setExitRegs(*this, rs);
					sc->updateOpenFiles(m_fd_path_map);
					m_consumer.syscallExit(*sc);
				}
			}
			else
			{
				std::cout << "Got signal: " << wr.stopSignal() << std::endl;
			}

			cont(ContinueMode::SYSCALL, wr.stopSignal());
		}
		else if( wr.exited() )
		{
			std::cout << "Tracee exited" << std::endl;
			this->exited(wr);
			m_state = TraceState::EXITED;
			break;
		}
		else
		{
			std::cout << "Other Tracee event" << std::endl;
		}
	}
}

void TracedProc::getRegisters(RegisterSet &rs)
{
	struct iovec reg_vector;
	rs.fillIov(reg_vector);

	if( ::ptrace( PTRACE_GETREGSET, m_tracee, rs.registerType(), &reg_vector ) != 0 )
	{
		tt_throw( ApiError() );
	}
	
	//std::cout << "Read registers " << reg_vector.iov_len << " vs. " << sizeof(regs) << std::endl;
}

long TracedProc::getData(const long *addr) const
{
	errno = 0;
	const long ret = (long)::ptrace( PTRACE_PEEKDATA, m_tracee, addr, 0 );

	if( errno != 0 )
	{
		tt_throw( ApiError() );
	}

	return ret;
}

TracedSeizedProc::TracedSeizedProc(TraceEventConsumer &consumer) :
	TracedProc(consumer)
{
}

void TracedSeizedProc::configure(const pid_t &tracee)
{
	m_tracee = tracee;
}

void TracedSeizedProc::attach()
{
	seize();
	interrupt();
	WaitRes wr;

	do
	{
		wait(wr);

		if( wr.exited() )
			return;
	}
	while( ! wr.stopped() && ! wr.stopSignal().raw() == SIGTRAP );

	setOptions( (int)TraceOpts::TRACESYSGOOD );
	m_state = TraceState::ATTACHED;
	cont(ContinueMode::SYSCALL);
}

void TracedSeizedProc::detach()
{
	if( m_tracee != SubProc::INVALID_PID && m_state != TraceState::EXITED )
	{
		if( ::ptrace( PTRACE_DETACH, m_tracee, nullptr, nullptr ) != 0 )
		{
			tt_throw( ApiError() );
		}

		m_tracee = SubProc::INVALID_PID;
	}
}

TracedSeizedProc::~TracedSeizedProc()
{
	try
	{
		detach();
	}
	catch( const TuxTraceError &tte )
	{
		std::cerr
			<< "Couldn't detach from " << m_tracee << ":\n\n"
			<< tte.what() << "\n";
	}
}


TracedSubProc::TracedSubProc(TraceEventConsumer &consumer) :
	TracedProc(consumer),
	m_exit_code(EXIT_SUCCESS)
{
}

void TracedSubProc::configure(const StringVector &prog_args)
{
	m_child.setArgs(prog_args);
	m_child.setTrace(true);
}

TracedSubProc::~TracedSubProc()
{
	try
	{
		if( m_child.running() )
		{
			// make sure we can wait for it
			try
			{
				m_child.kill(SIGKILL);
			}
			catch( ... ) { }
		}

		detach();
	}
	catch( const TuxTraceError &tte )
	{
		std::cerr << "Error detaching from child process " << m_child
			<< ":\n\n" << tte.what();
	}
}

void TracedSubProc::attach()
{
	m_exit_code = EXIT_SUCCESS;
	m_child.run();

	setTracee(m_child.pid());
		
	seize();

	WaitRes r;

	do
	{
		wait(r);
	}
	while( ! r.stopped() && ! r.exited() );

	setOptions( (int) TraceOpts::TRACESYSGOOD );
	
	if( r.stopped() )
	{
		m_state = TraceState::ATTACHED;
		cont(ContinueMode::SYSCALL);
	}
}

void TracedSubProc::detach()
{
	if( m_child.running() )
	{
		WaitRes wr = m_child.wait();
		m_exit_code = wr.exitStatus();
	}
}

void TracedSubProc::exited(const WaitRes &r)
{
	m_child.gone(r);
}

} // end ns

