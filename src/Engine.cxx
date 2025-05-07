// clues
#include <clues/AutoAttachedTracee.hxx>
#include <clues/ChildTracee.hxx>
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>
#include <clues/ForeignTracee.hxx>
#include <clues/logger.hxx>

// cosmos
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

namespace clues {

Engine::~Engine() {
	if (!m_tracees.empty()) {
		stop(cosmos::signal::KILL);
		trace();
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
		tracee.detach();
		if (tracee.isChildProcess() && tracee.alive() && signal) {
			cosmos::signal::send(tracee.pid(), *signal);
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

} // end ns
