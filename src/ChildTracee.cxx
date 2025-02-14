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

void ChildTracee::create(const cosmos::StringVector &args) {
	m_exit_code = std::nullopt;

	cosmos::ChildCloner cloner;
	cloner.setArgs(args);
	cloner.setPostForkCB([](const cosmos::ChildCloner &){
               // this allows our parent to trace us before execve() happens
               cosmos::signal::raise(cosmos::signal::STOP);
	});
	m_child = cloner.run();

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

void ChildTracee::detach() {
	if (m_child.running()) {
		cosmos::ChildData data = m_child.wait();
		if (data.status) {
			m_exit_code = *data.status;
		}
	}
}

} // end ns
