// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/filesystem.hxx>
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
	/*
	 * Here we have an issue with proper error reporting when the desired
	 * executable cannot be run. The execve() happens in child context and
	 * it is difficult to forward an error indication into parent context.
	 *
	 * ChildCloner offers a feature to forward execve() errors in the
	 * child synchronously to the parent. This doesn't work for our case,
	 * however, since we raise SIGSTOP in the child before executing,
	 * which would cause the `run()` call below to block forever, waiting
	 * for an execve() result.
	 *
	 * Using `fexecve()` would move typical file open errors to an earlier
	 * stage, but it has issues with scripts thats use the shebang to
	 * invoke an interpreter.
	 *
	 * It seems the only sensible thing to do is to check existence of the
	 * target path in a racy way beforehand.
	 */
	if (args.empty() || !cosmos::fs::which(args[0])) {
		changeState(State::DEAD);
		cosmos_throw(cosmos::RuntimeError{
				cosmos::sprintf("%s: does not exist or is not executable",
				args.empty() ? "<empty-path>" : args[0].c_str())});
	}

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
