#pragma once

// Cosmos
#include <cosmos/proc/process.hxx>
#include <cosmos/io/EventFile.hxx>
#include <cosmos/io/StdLogger.hxx>

// Clues
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>
#include <clues/logger.hxx>

/// This class helps creating child processes for testing tracing with libclues.
template <typename FUNC>
class TraceeCreator {
public:
	TraceeCreator(const FUNC &&func, clues::EventConsumer &consumer) :
			m_func{std::move(func)},
			m_engine{consumer} {
		m_logger.setChannels(true, true, false, false);
		m_logger.configFromEnvVar("CLUES_LOGGING");
		clues::set_logger(m_logger);
	}

	void run(const clues::FollowChildren follow_children = clues::FollowChildren{false}) {
		cosmos::EventFile event;
		if (auto pid = cosmos::proc::fork(); pid) {
			// parent context
			m_engine.addTracee(*pid,
					follow_children,
					clues::AttachThreads{true});
			event.signal();
			m_engine.trace();
		} else {
			// make sure the parent manages to attach as tracer to
			// use before continuing
			event.wait();
			// child context
			m_func();
			cosmos::proc::exit(cosmos::ExitStatus::SUCCESS);
		}
	}

protected:
	const FUNC m_func;
	clues::Engine m_engine;
	cosmos::StdLogger m_logger;
};
