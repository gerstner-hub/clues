#pragma once

// Cosmos
#include <cosmos/proc/process.hxx>
#include <cosmos/io/EventFile.hxx>

// Clues
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>

/// This class helps creating child processes for testing tracing with libclues.
template <typename FUNC>
class TraceeCreator {
public:
	TraceeCreator(const FUNC &&func, clues::EventConsumer &consumer) :
		m_func{std::move(func)},
       		m_engine{consumer} {
	}

	void run() {
		cosmos::EventFile event;
		if (auto pid = cosmos::proc::fork(); pid) {
			// parent context
			m_engine.addTracee(*pid,
					clues::FollowChildren{false},
					clues::AttachThreads{false});
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
};
