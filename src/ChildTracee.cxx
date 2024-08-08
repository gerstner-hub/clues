// cosmos
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/ChildTracee.hxx>

namespace clues {

ChildTracee::ChildTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void ChildTracee::configure(const cosmos::StringVector &prog_args) {
	m_cloner.setArgs(prog_args);
	m_cloner.setPostForkCB([](const cosmos::ChildCloner &){
#if 0
               // actually if we make our parent a tracer this way then we
               // can't deal with it the "new" way that is possible with SEIZED
               // processes. So we only raise a SIGSTOP instead to have the
               // parent catch us before doing anything else and otherwise
               // the parent can SEIZE us.
               if( ::ptrace( PTRACE_TRACEME, INVALID_PID, 0, 0 ) != 0 )
               {
                       cosmos_throw( ApiError() );
               }
#endif

               // this allows our parent to wait for us, such that is knows we're a tracee now
               cosmos::signal::raise(cosmos::signal::STOP);
	});
}

ChildTracee::~ChildTracee() {
	try {
		if (m_child.running()) {
			// make sure we can wait for it
			try {
				m_child.kill(cosmos::signal::KILL);
			} catch( ... ) { }
		}

		detach();
	} catch (const cosmos::CosmosError &ce) {
		if (logger) {
			logger->error() << "Error detaching from child process PID "
				<< cosmos::to_integral(m_child.pid())
				<< ":\n\n" << ce.what();
		}
	}
}

void ChildTracee::wait(cosmos::WaitRes &res) {
	res = m_child.wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_EXITED, cosmos::WaitFlag::WAIT_FOR_STOPPED});
}

void ChildTracee::attach() {
	m_exit_code = cosmos::ExitStatus::SUCCESS;
	m_child = m_cloner.run();

	setTracee(m_child.pid());

	seize();

	cosmos::WaitRes r;

	do {
		wait(r);

		if (r.exited())
			return;
	} while (!r.trapped());

	setOptions(cosmos::TraceFlags{cosmos::TraceFlag::TRACESYSGOOD});

	if (r.trapped()) {
		m_state = TraceState::ATTACHED;
		cont(cosmos::ContinueMode::SYSCALL);
	}
}

void ChildTracee::detach() {
	if (m_child.running()) {
		cosmos::WaitRes wr = m_child.wait();
		m_exit_code = wr.exitStatus();
	}
}

} // end ns
