// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/ChildCloner.hxx>

// clues
#include <clues/ChildTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

ChildTracee::ChildTracee(Engine &engine, EventConsumer &consumer) :
		Tracee{engine, consumer} {
}

void ChildTracee::create(const cosmos::StringVector &args) {
	/// TODO: libcosmos's behaviour to output error messages in the forked
	/// process when the target executable cannot be run is unfortunate
	/// for our purposes.
	/// We could think about making the error behaviour configurable, to
	/// output nothing or to to use fexecve() to move the most common
	/// kinds of errors into the parent process.
	cosmos::ChildCloner cloner;
	cloner.setArgs(args);
	cloner.setPostForkCB([](const cosmos::ChildCloner &){
               // this allows our parent to trace us before execve() happens
               cosmos::signal::raise(cosmos::signal::STOP);
	});
	m_child = cloner.run();

	m_child.wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_STOPPED});
	m_flags.set(Flag::INJECTED_SIGSTOP);

	setPID(m_child.pid());
}

ChildTracee::~ChildTracee() {
	try {
		if (m_child.running()) {
			// make sure we can wait for it
			try {
				m_child.kill(cosmos::signal::KILL);
			} catch( ... ) { }
		}

		cleanupChild();
	} catch (const cosmos::CosmosError &ce) {
		LOG_ERROR("Error detaching from child process PID "
				<< cosmos::to_integral(m_child.pid()) << ":\n\n"
				<< ce.what());
	}
}

void ChildTracee::cleanupChild() {

	// this should actually only happen if a ChildTracee is detached
	// explicitly and we're sending a SIGINT or something like that.
	if (m_child.running()) {
		try {
			// the base class already stored the exit data
			// this is just for keeping the SubProc state in sync.
			(void)m_child.wait();
		} catch (const cosmos::ApiError &error) {
			if (error.errnum() != cosmos::Errno::NO_CHILD) {
				// if it is ESRCH then just ignore it, the
				// Engine already collected the result.
				//
				// this step is necessary to clean up the
				// SubProc's internal state. Otherwise we'd
				// need to use cosmos::proc::fork() to avoid
				// using SubProc in the first place.
				throw;
			}
		}
	}
}

} // end ns
