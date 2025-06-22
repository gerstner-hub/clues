#pragma once

// C++
#include <map>
#include <memory>
#include <optional>

// cosmos
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/proc/types.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/types.hxx>

namespace cosmos {
	struct ChildState;
}

namespace clues {

class Tracee;
class EventConsumer;

/// Main class for configuring and running libclues
/**
 * This is the main class for configuring Tracee's and actually performing
 * tracing. The tracing main loop is implemented here and callbacks are
 * delivered to the EventConsumer interface.
 *
 * Note that this class uses the `wait()` family of system calls to keep track
 * of trace events. This API consumes process-global events, which means that
 * there will be problems if other components in the same process deal with
 * child processes, like:
 *
 * - extra events will be seen that libclues / the other component is not
 *   prepared for.
 * - events that are expected by libclues can be lost to the other component.
 *
 * For this reason it is simply not sensibly possible to create regular child
 * process in parallel to tracing.
 **/
class CLUES_API Engine {
	friend class Tracee;
public: // functions

	/// Creates a new Engine that reports events to `consumer`.
	explicit Engine(EventConsumer &consumer) :
			m_consumer{consumer} {
	}

	/// Tear down any tracees.
	/**
	 * If tracees are still present then they will be detached from via
	 * stop(cosmos::signal::KILL).
	 **/
	virtual ~Engine();

	/// Add the given `pid` as tracee.
	/**
	 * For tracing unrelated processes the current process needs to have
	 * sufficient privileges. This is usually the case if you are root or
	 * if the target process has the same credentials as the current
	 * process.
	 *
	 * The Linux Yama kernel security module can further restrict tracing
	 * of unrelated processes. Check the
	 * /proc/sys/kernel/yama/ptrace_scope file for more information.
	 *
	 * If attaching fails then this call immediately throws an exception.
	 *
	 * On success the target process will be interrupted to determine its
	 * current state. Any state can be encountered and the caller needs to
	 * be prepared for any kind of tracing event (signal, system call,
	 * process exit, ...) to occur as a result.
	 *
	 * `follow_childs` determines whether newly created child processes
	 * will automatically be attached. \see Tracee::attach().
	 *
	 * `attach_threads` determines whether other threads of the target
	 * process should automatically be attached, too.
	 **/
	TraceePtr addTracee(const cosmos::ProcessID pid, const FollowChilds follow_childs, const AttachThreads attach_threads);

	/// Create a new child process to be traced.
	/**
	 * Use this function to create a new child process which will be
	 * traced from the very beginning. The first tracing event observed
	 * will typically be a system call entry.
	 *
	 * `follow_childs` determines whether newly created child processes
	 * will automatically be attached. \see Tracee::attach().
	 **/
	TraceePtr addTracee(const cosmos::StringVector &cmdline, const FollowChilds follow_childs);

	/// Enter the tracing main loop and process tracing events.
	/**
	 * At least one tracee must have been added via addTracee() for this
	 * call to do anything. The call will block and deliver tracing events
	 * to the given `consumer` interface until all of the tracees have
	 * exited or have been detached from.
	 **/
	void trace();

	/// Stop tracing any active tracees.
	/**
	 * If you want to stop a running trace then you can call this function
	 * to initiate detach from all active tracees. Each tracee will either
	 * be immediately be detached from, if its current state allows this,
	 * or it will be interrupted to detach from it during the next ptrace
	 * event.
	 *
	 * If new child processes have been created for tracing then `signal`
	 * determines how they will be dealt with:
	 *
	 * - std::nullopt means that they will be waited for, without sending
	 *   a signal. This can mean that it will take a long time before the
	 *   child processes terminate and the trace() call can return.
	 * - Otherwise `signal` denotes the signal that will be sent to direct
	 *   children to have them terminate in a timely fashion.
	 *   cosmos::signal::KILL will be the safest way to tear down any
	 *   remaining child processes.
	 *
	 * After calling this function an active trace() invocation should be
	 * returning soon. Further trace events may be reported to the
	 * EventConsumer interface until the detachment process is complete.
	 **/
	void stop(const std::optional<cosmos::Signal> signal);

protected: // types

	using TraceeMap = std::map<cosmos::ProcessID, TraceePtr>;

protected: // functions

	void checkCleanupTracee(TraceeMap::iterator it);

	void handleNoChilds();

	/// Check the given trace event if we can make sense of it.
	/**
	 * If the function was able to adjust internal state for being able to
	 * properly handle `data`, then it returns `true` and a retry should
	 * be performed. Otherwise `false` is returned and the event should be
	 * discarded.
	 **/
	bool checkUnknownTraceeEvent(const cosmos::ChildState &data);

	bool tryUpdateTraceePID(const cosmos::ProcessID old_pid, const cosmos::ProcessID new_pid);

	/// Invoked by a Tracee once a new child process is auto-attached.
	/**
	 * `pid` provides the process ID of the new child process and `event`
	 * describes the event that triggered the creation of the new child.
	 **/
	void handleAutoAttach(Tracee &parent, const cosmos::ProcessID pid,
			const cosmos::ptrace::Event event);

	/// Invoked by a Tracee when multi-threaded execve() leads to substitution of a PID by another.
	TraceePtr handleSubstitution(const cosmos::ProcessID old_pid);

protected: // data

	/// Currently active tracees.
	TraceeMap m_tracees;
	EventConsumer &m_consumer;
};

} // end ns
