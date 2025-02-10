// cosmos
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/ChildCloner.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/ChildTracee.hxx>

namespace clues {

ChildTracee::ChildTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void ChildTracee::configure(const cosmos::StringVector &prog_args) {
	m_args = prog_args;
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

void ChildTracee::wait(cosmos::ChildData &data) {
	data = m_child.wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_EXITED, cosmos::WaitFlag::WAIT_FOR_STOPPED});
}

void ChildTracee::attach() {
	m_exit_code = cosmos::ExitStatus::SUCCESS;

	cosmos::ChildCloner cloner;
	cloner.setArgs(m_args);
	cloner.setPostForkCB([](const cosmos::ChildCloner &){
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
	m_child = cloner.run();

	setTracee(m_child.pid());

	seize(cosmos::ptrace::Opts{cosmos::ptrace::Opt::TRACESYSGOOD});

	cosmos::ChildData child;

	do {
		wait(child);

		if (child.exited())
			return;
	} while (!child.trapped());

	if (child.trapped()) {
		m_state = TraceState::ATTACHED;
		restart(cosmos::Tracee::RestartMode::SYSCALL);
	}
}

void ChildTracee::detach() {
	if (m_child.running()) {
		cosmos::ChildData data = m_child.wait();
		if (data.status) {
			m_exit_code = *data.status;
		}
	}
}

} // end ns
