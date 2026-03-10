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
		// when building with sanitizers, the test helper programs
		// will be linked against sanitized libcosmos.
		//
		// sanitized programs cannot be run under ptrace(), though,
		// which is why SCons filters out the sanitizer flags.
		//
		// the libs are still sanitized, and complain about missing
		// sanitizer support in the executable. Suppress this by
		// setting the following environment variables.
		//
		// it would be cleaner to link the helper programs against
		// non-sanitized libraries in this case, but this would make
		// things even more complex ... let's see how far we get this
		// way.
		cosmos::proc::set_env_var("ASAN_OPTIONS", "verify_asan_link_order=false:detect_leaks=0", cosmos::proc::OverwriteEnv{true});
	}

	void run(const clues::FollowChildren follow_children = clues::FollowChildren{false}, const bool explicit_signal = false) {
		if (auto pid = cosmos::proc::fork(); pid) {
			// parent context
			m_engine.addTracee(*pid,
					follow_children,
					clues::AttachThreads{true});
			if (!explicit_signal) {
				m_event.signal();
			} else {
				m_explicit_signal = true;
			}
			m_engine.trace();
		} else {
			// make sure the parent manages to attach as tracer to
			// use before continuing
			m_event.wait();
			// child context
			m_func();
			cosmos::proc::exit(cosmos::ExitStatus::SUCCESS);
		}
	}

	void signalChild() {
		if (m_explicit_signal) {
			m_event.signal();
			m_explicit_signal = false;
		}
	}

protected:
	const FUNC m_func;
	bool m_explicit_signal = false;
	cosmos::EventFile m_event;
	clues::Engine m_engine;
	cosmos::StdLogger m_logger;
};
