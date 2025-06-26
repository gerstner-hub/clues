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

TraceePtr Engine::addTracee(const cosmos::ProcessID pid, const FollowChildren follow_children,
		const AttachThreads attach_threads, const cosmos::ProcessID sibling) {
	TraceePtr sibling_ptr;
	if (auto it = m_tracees.find(sibling); it != m_tracees.end()) {
		sibling_ptr = it->second;
	}
	auto tracee = std::make_shared<ForeignTracee>(*this, m_consumer, sibling_ptr);
	tracee->configure(pid);
	tracee->attach(follow_children, attach_threads);
	m_tracees[pid] = tracee;
	return tracee;
}

TraceePtr Engine::addTracee(const cosmos::StringVector &cmdline, const FollowChildren follow_children) {
	auto tracee = std::make_shared<ChildTracee>(*this, m_consumer);
	tracee->create(cmdline);
	tracee->attach(follow_children);
	m_tracees[tracee->pid()] = tracee;
	return tracee;
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

void Engine::handleNoChildren() {
	for (auto it = m_tracees.begin(); it != m_tracees.end(); it++) {
		auto &tracee = it->second;

		if (tracee->flags()[Tracee::Flag::WAIT_FOR_EXITED]) {
			/*
			 * This can be observed with the main thread when
			 * another thread (which isn't traced) calls execve().
			 *
			 * For this situation no EXITED wait() status is
			 * reported for the main thread, only PTHREAD_EXIT is
			 * seen. After that we can ECHLD with wait() and ESRCH
			 * with ptrace().
			 */
			LOG_DEBUG("Tracee "
					<< cosmos::to_integral(tracee->pid())
					<< " likely disappeared because of execve() in another thread");
		} else {
			LOG_WARN("Tracee " << cosmos::to_integral(tracee->pid())
					<< " suddenly lost?!");
		}

		// actually we already seem to be detached, but this function
		// also takes care of this case and properly resets object
		// state
		tracee->detach();

		checkCleanupTracee(it);
	}
}

void Engine::trace() {
	cosmos::ChildState data;

	while (!m_tracees.empty()) {
		try {
			data = *cosmos::proc::wait(cosmos::WaitFlags{
					cosmos::WaitFlag::WAIT_FOR_EXITED,
					cosmos::WaitFlag::WAIT_FOR_STOPPED});
		} catch (const cosmos::ApiError &ex) {
			if (ex.errnum() == cosmos::Errno::NO_CHILD) {
				handleNoChildren();
				return;
			}

			throw;
		}

		while (true) {
			if (auto it = m_tracees.find(data.child.pid); it != m_tracees.end()) {
				Tracee &tracee = *it->second;
				tracee.processEvent(data);

				checkCleanupTracee(it);
			} else {
				if (checkUnknownTraceeEvent(data)) {
					// retry if we can process the event this time
					continue;
				}

				LOG_WARN("received unknown trace event for PID " << cosmos::to_integral(data.child.pid));
			}

			break;
		}
	}
}

bool Engine::checkUnknownTraceeEvent(const cosmos::ChildState &data) {

	if (data.trapped() && data.signal->isPtraceEventStop()) {
		const auto [_, event] = cosmos::ptrace::decode_event(*data.signal);
		if (event == cosmos::ptrace::Event::EXEC) {
			/*
			 * This means execve() happened in a multi-threaded
			 * process, but we're not tracing the main thread,
			 * only the exec()'ing thread.
			 *
			 * The exec()'ing thread now has become the main
			 * thread, changing PID personality. Try to recover.
			 */
			cosmos::Tracee ptrace{data.child.pid};
			const auto former_pid = ptrace.getPIDEventMsg();
			LOG_DEBUG("PID " << cosmos::to_integral(former_pid) << " issued execve(), but main thread is not traced. Trying to update records.");
			return tryUpdateTraceePID(former_pid, data.child.pid);
		}
	}

	return false;
}

bool Engine::tryUpdateTraceePID(const cosmos::ProcessID old_pid, const cosmos::ProcessID new_pid) {
	auto node = m_tracees.extract(old_pid);
	if (node.empty())
		return false;
	// don't change the Tracee object's PID just yet. This will be done
	// in Tracee::handleExecEvent()).
	//
	// At this stage we just want to be able to lookup the correct Tracee
	// within Engine for now.
	node.key() = new_pid;

	m_tracees.insert(std::move(node));
	return true;
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
		auto tracee = std::make_shared<AutoAttachedTracee>(
				*this,
				m_consumer,
				m_tracees[parent.pid()]);

		tracee->configure(pid, event);

		auto [it, _] = m_tracees.insert({pid, tracee});

		m_consumer.newChildProcess(parent, *it->second, event);

		/// TODO: not the smartest approach to first allocate and
		/// insert the new tracee, just to possibly remove and delete
		/// it again right away.
		checkCleanupTracee(it);
	} else {
		// if the pid is no longer found then it either already died
		// or it was detached from
		if (auto it = m_tracees.find(pid); it != m_tracees.end()) {
			m_consumer.vforkComplete(parent, it->second);
		} else {
			m_consumer.vforkComplete(parent, nullptr);
		}
	}

}

TraceePtr Engine::handleSubstitution(const cosmos::ProcessID old_pid) {
	/*
	 * The following scenarios exist for multi-threaded processes:
	 *
	 * a) we are tracing all threads of the process. Some thread calls
	 * execve(). We'll see all other threads exiting out of the blue. The
	 * main thread's Tracee object will set the
	 * WAIT_FOR_EXECVE_REPLACEMENT flag. Once the PID personality change
	 * happens we'll recycle the main thread's Tracee object to be used
	 * for further tracing. The reason for this is that the Tracee object
	 * may be a ChildTracee with ownership of a SubProc that needs to live
	 * on.
	 *
	 * b) we are only tracing a thread other than the main thread or the
	 * execve() thread: it will just exit and tracing ends
	 *
	 * c) we are only tracing the execve() thread which is not the main
	 * thread. Upon PID substitution we'll suddenly get a ptrace()
	 * event for a PID we never attached to. Engine decodes the event in
	 * `checkUnknownTraceeEvent()` and will update the key in `m_tracees`,
	 * then feed the event to the Tracee object. In this case the only
	 * available Tracee object will be kept.
	 *
	 * d) we are tracing only the main thread but another thread calls
	 * execve(): the thread disappears and `wait()` suddenly fails
	 * with ENOCHILD.
	 *
	 * What does strace do in these cases?
	 *
	 * - in case c) it sees the ptrace event for the changed PID, then
	 *   detaches from it stating it is an unknown PID. Then tracing ends.
	 * - in case d) it fails with ENOCHILD and tracing ends.
	 *
	 * Technically is is possible to deal with case c), which is complex
	 * but managable. It makes sense to continue tracing in this case.
	 *
	 * In case d) it could be argued that is also makes sense to continue
	 * tracing, since the main thread is traced but continues in another
	 * context. Technically it is not possible to do this, though, because
	 * we have no information at all about the execve() that is happening
	 * until we lose the tracee. Thus in this case we try to detach cleanly.
	 * Clients of libclues can identify the exit reason via
	 * Tracee::flags() by looking for Flag::WAIT_FOR_EXECVE_REPLACEMENT,
	 * which will still be set in this scenario.
	 */

	auto it = m_tracees.find(old_pid);

	if (it == m_tracees.end()) {
		// this is likely case c), the `old_pid` was not traced by us.
		return nullptr;
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

	auto ret = it->second;

	m_tracees.erase(it);

	/* The man page says at this stage we should forget about any other
	 * treads of the process that still exist.
	 * Is this really necessary? It also says that it is guaranteed that
	 * only two threads will still exist now: the main and the execve()
	 * thread. So forgetting about any other threads would only be
	 * relevant for the non-execve() thread that still remains. We already
	 * deal successfully with all the constellations that can occur, so I
	 * don't think there's any explicit "forgetting" to be implemented
	 * here.
	 */

	return ret;
}

} // end ns
