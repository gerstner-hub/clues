#pragma once

// C++
#include <map>
#include <memory>
#include <optional>

// cosmos
#include <cosmos/BitMask.hxx>
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
class SystemCall;

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
public: // types

	enum class FormatFlag : uint64_t {
		FD_INFO = 1, ///< print detailed file descriptor information
	};

	using FormatFlags = cosmos::BitMask<FormatFlag>;

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
	 * `follow_children` determines whether newly created child processes
	 * will automatically be attached. \see Tracee::attach().
	 *
	 * `attach_threads` determines whether other threads of the target
	 * process should automatically be attached, too.
	 *
	 * `sibling´, if set, refers to an existing Tracee that belongs to the
	 * same process as `pid`. The tracees will then share the same
	 * ProcessData.
	 **/
	TraceePtr addTracee(const cosmos::ProcessID pid, const FollowChildren follow_children,
			const AttachThreads attach_threads, const cosmos::ProcessID sibling = cosmos::ProcessID::INVALID);

	/// Create a new child process to be traced.
	/**
	 * Use this function to create a new child process which will be
	 * traced from the very beginning. The first tracing event observed
	 * will typically be a system call entry.
	 *
	 * `follow_children` determines whether newly created child processes
	 * will automatically be attached. \see Tracee::attach().
	 *
	 * The library will perform an initial check whether the executable
	 * specified in `cmdline` exists and is executable. If this is not the
	 * case, then a `RuntimeError` is thrown. There can be other errors
	 * trying to execute the new process that cannot be caught before the
	 * new process is forked. To catch these situations, it is best to
	 * observe the tracee's system calls: If it exits before a successful
	 * initial `execve()` system call occurred, then a pre execution
	 * error happened.
	 **/
	TraceePtr addTracee(const cosmos::StringVector &cmdline, const FollowChildren follow_children);

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

	FormatFlags formatFlags() const {
		return m_format_flags;
	}

	/// Change formatting behaviour for system calls.
	/**
	 * These flags influences the implementation of SystemCallItem::str().
	 * See `FormatFlag` for details.
	 **/
	void setFormatFlags(const FormatFlags flags) {
		m_format_flags = flags;
	}

protected: // types

	using TraceeMap = std::map<cosmos::ProcessID, TraceePtr>;

	using EventMap = std::map<cosmos::ProcessID, cosmos::ChildState>;

	/// Different decisions what to do with ptrace events.
	enum class Decision {
		RETRY, ///< retry processing the event.
		DROP, ///< ignore/drop the event.
		STORE, ///< store the event for later.
		DONE, ///< the event has been successfully processed.
	};

protected: // functions

	void checkCleanupTracee(TraceeMap::iterator it);

	void checkUnknownEvents();

	Decision handleEvent(const cosmos::ChildState &data);

	void handleNoChildren();

	/// Check the given trace event if we can make sense of it.
	/**
	 * If the function was able to adjust internal state for being able to
	 * properly handle `data`, then it returns `true` and a retry should
	 * be performed. Otherwise `false` is returned and the event should be
	 * discarded.
	 **/
	Decision checkUnknownTraceeEvent(const cosmos::ChildState &data);

	bool tryUpdateTraceePID(const cosmos::ProcessID old_pid, const cosmos::ProcessID new_pid);

	/// Invoked by a Tracee once a new child process is auto-attached.
	/**
	 * `pid` provides the process ID of the new child process and `event`
	 * describes the event that triggered the creation of the new child.
	 * `sc` refers to the system call that lead to the creation of the new
	 * child, providing additional details of child properties.
	 **/
	void handleAutoAttach(Tracee &parent, const cosmos::ProcessID pid,
			const cosmos::ptrace::Event event, const SystemCall &sc);

	/// Invoked by a Tracee when multi-threaded execve() leads to substitution of a PID by another.
	TraceePtr handleSubstitution(const cosmos::ProcessID old_pid);

protected: // data

	/// Currently active tracees.
	TraceeMap m_tracees;
	/// Unknown ptrace events stored for later processing.
	EventMap m_unknown_events;
	/// The PID of a newly auto-attached Tracee, if any.
	cosmos::ProcessID m_newly_attached_pid = cosmos::ProcessID::INVALID;
	EventConsumer &m_consumer;
	/// Format settings for all tracees attached to this engine.
	FormatFlags m_format_flags;
};

} // end ns
