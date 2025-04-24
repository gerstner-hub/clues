// cosmos
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/ChildCloner.hxx>

// clues
#include <clues/ChildTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

ChildTracee::ChildTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void ChildTracee::create(const cosmos::StringVector &args) {
	cosmos::ChildCloner cloner;
	cloner.setArgs(args);
	cloner.setPostForkCB([](const cosmos::ChildCloner &){
               // this allows our parent to trace us before execve() happens
               cosmos::signal::raise(cosmos::signal::STOP);
	});
	m_child = cloner.run();

	m_child.wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_STOPPED});
	m_flags.set(Flag::INJECTED_SIGSTOP);

	setTracee(m_child.pid());
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
		LOG_ERROR("Error detaching from child process PID "
				<< cosmos::to_integral(m_child.pid()) << ":\n\n"
				<< ce.what());
	}
}

void ChildTracee::wait(cosmos::ChildData &data) {
	data = m_child.wait(cosmos::WaitFlags{
		cosmos::WaitFlag::WAIT_FOR_EXITED,
		cosmos::WaitFlag::WAIT_FOR_STOPPED
	});
}

void ChildTracee::detach() {

	if (m_state != State::DEAD && m_state != State::DETACHED) {
		m_ptrace.detach();
		changeState(State::DETACHED);
	}

	// this should actually only happen if a ChildTracee is detached
	// explicitly and we're sending a SIGINT or something like that.
	if (m_child.running()) {
		cosmos::ChildData data = m_child.wait();
		m_exit_data = data;
	}
}

} // end ns
