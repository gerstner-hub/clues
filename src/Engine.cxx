// clues
#include <clues/AutoAttachedTracee.hxx>
#include <clues/ChildTracee.hxx>
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>
#include <clues/ForeignTracee.hxx>
#include <clues/logger.hxx>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/InternalError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

namespace clues {

Engine::~Engine() {
	if (!m_tracees.empty()) {
		try {
			stop(cosmos::signal::KILL);
			trace();
		} catch (const std::exception &ex) {
			LOG_WARN("Trying to stop remaining tracess in ~Engine():" << ex.what());

			if (!m_tracees.empty()) {
				LOG_ERROR("Failed to cleanup Engine");
				std::abort();
			}
		}
	}
}

Tracee& Engine::addTracee(const cosmos::ProcessID pid, const FollowChilds follow_childs) {
	auto tracee = std::make_unique<ForeignTracee>(*this, m_consumer);
	tracee->configure(pid);
	tracee->attach(follow_childs);
	Tracee &ret = *tracee;
	m_tracees[pid] = std::move(tracee);
	return ret;
}

Tracee& Engine::addTracee(const cosmos::StringVector &cmdline, const FollowChilds follow_childs) {
	auto tracee = std::make_unique<ChildTracee>(*this, m_consumer);
	tracee->create(cmdline);
	tracee->attach(follow_childs);
	Tracee &ret = *tracee;
	m_tracees[tracee->pid()] = std::move(tracee);
	return ret;
}

void Engine::checkCleanupTracee(TraceeMap::iterator it) {
	auto &tracee = *it->second;

	if (tracee.state() == Tracee::State::DETACHED) {
		if (!tracee.isChildProcess()) {
			m_tracees.erase(it);
		}
	} else if (tracee.state() == Tracee::State::DEAD) {
		tracee.detach();
		m_tracees.erase(it);
	}
}

void Engine::trace() {
	cosmos::ChildData data;

	while (!m_tracees.empty()) {
		data = *cosmos::proc::wait(cosmos::WaitFlags{
				cosmos::WaitFlag::WAIT_FOR_EXITED,
				cosmos::WaitFlag::WAIT_FOR_STOPPED});

		if (auto it = m_tracees.find(data.child.pid); it != m_tracees.end()) {
			Tracee &tracee = *it->second;
			tracee.processEvent(data);

			checkCleanupTracee(it);
		} else {
			LOG_WARN("wait() event about unknown child: " << cosmos::to_integral(data.child.pid));
		}
	}
}

void Engine::stop(const std::optional<cosmos::Signal> signal) {
	for (auto it = m_tracees.begin(); it != m_tracees.end(); it++) {
		auto &tracee = *it->second;
		if (tracee.isChildProcess() && tracee.alive() && signal) {
			cosmos::signal::send(tracee.pid(), *signal);
		}
		tracee.detach();

		if (!tracee.alive()) {
			m_tracees.erase(it);
		}
	}
}

void Engine::handleAutoAttach(
		Tracee &parent, const cosmos::ProcessID pid, const cosmos::ptrace::Event event) {

	if (event != cosmos::ptrace::Event::VFORK_DONE) {
		auto tracee = std::make_unique<AutoAttachedTracee>(*this, m_consumer);

		tracee->configure(parent, pid);

		auto [it, _] = m_tracees.insert({pid, std::move(tracee)});

		m_consumer.newChildProcess(parent, *it->second, event);

		/// TODO: not the smartest approach to first allocate and
		/// insert the new tracee, just to possibly remove and delete
		/// it again right away.
		checkCleanupTracee(it);
	} else {
		// if the pid is no longer found then it either already died
		// or it was detached from
		if (auto it = m_tracees.find(pid); it != m_tracees.end()) {
			m_consumer.vforkComplete(parent, it->second.get());
		} else {
			m_consumer.vforkComplete(parent, nullptr);
		}
	}

}

TraceePtr Engine::handleSubstitution(const cosmos::ProcessID old_pid) {
	auto it = m_tracees.find(old_pid);
	if (it == m_tracees.end()) {
		// TODO: what happens if we only tracee a single thread of a
		// multi-threaded process here?
		// in theory it should currently work like this:
		// - tracing a thread other than the main thread or the
		//   execve() thread: it will just exit and tracing ends
		// - tracing the execve() thread: will "disappear" before
		//   execve() completes and tracing ends (?)
		// - tracing the main thread: will see a new exec context out
		//   of nowhere with no state to sync with.
		//
		// what does strace do in these cases?
		cosmos_throw (cosmos::InternalError("substitution with non-existent tracee"));
	}

	auto &old_tracee = *it->second;

	try {
		old_tracee.detach();
	} catch (const cosmos::ApiError &err) {
		// it seems the kernel implicitly detaches at this point
		if (err.errnum() != cosmos::Errno::SEARCH) {
			throw;
		}
	}

	auto ret = std::move(it->second);

	m_tracees.erase(it);
	// TODO: the man page says at this stage we should forget about any
	// other treads of the process that still exist.
	// is this really necessary? it also says that it is guaranteed that
	// only two threads will still exist: the main and the execve()
	// thread.

	return ret;
}

} // end ns
