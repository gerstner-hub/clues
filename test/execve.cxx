// C++
#include <iostream>
#include <vector>

// Cosmos
#include <cosmos/fs/File.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/path.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/thread/Condition.hxx>
#include <cosmos/thread/PosixThread.hxx>

// Clues
#include <clues/SystemCall.hxx>
#include <clues/syscallnrs.hxx>
#include <clues/Tracee.hxx>

// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

/*
 * This test covers the various execve() scenarios:
 *
 * - regular exexcve in a single-threaded process.
 * - execve in the main thread of a multi-threaded process.
 * - execve in a non-main thread of a multi-threaded process.
 *
 * The test verifies that the trace events come in as expected, that the
 * personality change (if any) occurs and that no crashes happen.
 */

class ExecveTracer : public clues::EventConsumer {
public:
	explicit ExecveTracer(const clues::SystemCallNr exec_nr) :
		m_exec_nr{exec_nr} {}

	auto numExecEntrySeen() const {
		return m_seen_exec_entry;
	}

	auto numExecExitSeen() const {
		return m_seen_exec_exit;
	}

	auto numSuccessfulExecSeen() const {
		return m_seen_successful_exec;
	}

	auto numSeenAttached() const {
		return m_seen_attached;
	}

	auto numSeenExits() const {
		return m_seen_exits;
	}

	auto numSeenLostToExecve() const {
		return m_seen_lost_to_execve;
	}

	auto waitStatus() const {
		return m_status;
	}

	auto& oldExecutable() const {
		return m_old_executable;
	}

	auto& oldCmdline() const {
		return m_old_cmdline;
	}

	auto& oldPID() const {
		return m_old_pid;
	}

	auto& newExecutable() const {
		return m_new_executable;
	}

	auto& attachedPIDs() const {
		return m_attached_pids;
	}
protected:
	void syscallEntry(clues::Tracee &,
			const clues::SystemCall &call,
			const StatusFlags) override {
		if (call.callNr() == m_exec_nr) {
			m_seen_exec_entry++;
		}
	}

	void syscallExit(clues::Tracee &,
			const clues::SystemCall &call,
			const StatusFlags) override {
		if (call.callNr() == m_exec_nr) {
			m_seen_exec_exit++;
			if (call.hasResultValue()) {
				m_seen_successful_exec++;
			}
		}
	}

	void attached(clues::Tracee &tracee) override {
		m_seen_attached++;
		m_attached_pids.push_back(tracee.pid());
	}

	void exited(clues::Tracee &, const cosmos::WaitStatus status, const StatusFlags state) override {
		m_seen_exits++;
		if (state[StatusFlag::LOST_TO_EXECVE]) {
			m_seen_lost_to_execve++;
		}
		m_status = status;
	}

	void newExecutionContext(clues::Tracee &tracee,
			const std::string &old_executable,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> old_pid) override {
		m_old_executable = old_executable;
		m_old_cmdline = old_cmdline;
		m_old_pid = old_pid;
		m_new_executable = tracee.executable();
	}

	size_t m_seen_exec_entry = 0;
	size_t m_seen_exec_exit = 0;
	size_t m_seen_successful_exec = 0;
	size_t m_seen_attached = 0;
	size_t m_seen_lost_to_execve = 0;
	size_t m_seen_exits = 0;
	const clues::SystemCallNr m_exec_nr;
	std::optional<cosmos::WaitStatus> m_status;
	std::string m_old_executable;
	cosmos::StringVector m_old_cmdline;
	std::optional<cosmos::ProcessID> m_old_pid;
	std::string m_new_executable;
	// PIDs we've seen during attached() in order of appearance
	std::vector<cosmos::ProcessID> m_attached_pids;
};

cosmos::ConditionMutex condition;
bool thread_running = false;

cosmos::pthread::ExitValue thread_entry_blocking(cosmos::pthread::ThreadArg) {
	condition.lock();
	thread_running = true;
	condition.unlock();
	condition.signal();
	// wait for nothing, just so that we can block on something
	condition.lock();
	condition.wait();
	return cosmos::pthread::ExitValue{0};
}

cosmos::pthread::ExitValue thread_entry_exec(cosmos::pthread::ThreadArg exiter_ptr) {
	const char *exiter = reinterpret_cast<const char*>(exiter_ptr);
	cosmos::proc::exec(exiter);
	return cosmos::pthread::ExitValue{1};
}

class ExecveTest : public cosmos::TestBase {
	void runTests() override {
		findExiter();
		testRegularExecve();
		testMainThreadExecve();
		testOtherThreadExecve();
	}

	void findExiter() {
		/*
		 * we need our own custom helper tool to execute while tracing
		 * e.g. for the '-m32' build use case, because a 32-bit tracer
		 * cannot (sensibly) trace a 64-bit program.
		 * the exiter replaces the true/false binaries and exits with
		 * the parameter passed to it.
		 */
		std::string dir{m_argv.at(0)};
		dir = dir.substr(0, dir.rfind('/'));
		auto exiter = dir + "/exiter";
		exiter = cosmos::fs::canonicalize_path(exiter);
		if (!cosmos::fs::exists_file(exiter)) {
			throw cosmos::RuntimeError{"couldn't find exiter"};
		}

		m_exiter = exiter;
	}

	void testRegularExecve() {
		START_TEST("regular execve");

		ExecveTracer tracer{clues::SystemCallNr::EXECVE};

		TraceeCreator creator{[this]() {
				// without parameters, it returns a 0 exit status
				cosmos::proc::exec(m_exiter);
			}, tracer};
		creator.run();

		RUN_STEP("seen-execve-entry", tracer.numExecEntrySeen() == 1);
		RUN_STEP("seen-execve-exit", tracer.numExecExitSeen() == 1);
		RUN_STEP("num-entry-matches-num-exit",
				tracer.numExecEntrySeen() == tracer.numExecExitSeen());
		RUN_STEP("seen-successful-execve", tracer.numSuccessfulExecSeen() == 1);
		RUN_STEP("seen-attached-once", tracer.numSeenAttached() == 1);
		RUN_STEP("seen-exited", tracer.waitStatus() != std::nullopt);
		RUN_STEP("num-exited-is-one", tracer.numSeenExits() == 1);
		RUN_STEP("wait-status-is-zero",
				tracer.waitStatus()->exited() &&
				tracer.waitStatus()->status() == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("execve-old-pid-is-not-there", tracer.oldPID() == std::nullopt);
		RUN_STEP("new-executable-matches-true", tracer.newExecutable() == m_exiter);
		if (!onValgrind()) {
			// when running on valgrind then there's a valgrind frontend instead, confusing things
			RUN_STEP("old-executable-is-us", tracer.oldExecutable().find("execve") != std::string::npos);
			RUN_STEP("old-cmdline-is-ours", tracer.oldCmdline() == m_argv);
		}
	}

	void testMainThreadExecve() {
		START_TEST("main thread execve (multithreaded)");

		// test this time with fexecve() (EXECVEAT system call)
		ExecveTracer tracer{clues::SystemCallNr::EXECVEAT};

		cosmos::File exiter_fd{m_exiter, cosmos::OpenMode::READ_ONLY};

		TraceeCreator creator{[&exiter_fd]() {
				// create a random thread that just sits there
				cosmos::PosixThread thread{
					thread_entry_blocking, cosmos::pthread::ThreadArg{0}};
				condition.lock();
				while (!thread_running) {
					condition.wait();
				}
				condition.unlock();
				cosmos::proc::fexec(exiter_fd.fd(), cosmos::CStringVector{"exiter", "1", nullptr});
				thread.join();
			}, tracer};
		creator.run(clues::FollowChildren{true});
		// NOTE: Valgrind heavily changes the system call sequences
		// here and somehow turns the execveat() into a regular
		// execve(). Doesn't make sense to catch up with this fat
		// emulation layer here.
		RUN_STEP("seen-execve-entry", tracer.numExecEntrySeen() == 1);
		RUN_STEP("seen-execve-exit", tracer.numExecExitSeen() == 1);
		RUN_STEP("num-entry-matches-num-exit",
				tracer.numExecEntrySeen() == tracer.numExecExitSeen());
		RUN_STEP("seen-successful-execve", tracer.numSuccessfulExecSeen() == 1);
		RUN_STEP("seen-attached-twice", tracer.numSeenAttached() == 2);
		RUN_STEP("seen-exited", tracer.waitStatus() != std::nullopt);
		RUN_STEP("num-exited-is-two", tracer.numSeenExits() == 2);
		RUN_STEP("seen-lost-to-execve", tracer.numSeenLostToExecve() == 1);
		RUN_STEP("wait-status-is-one",
				tracer.waitStatus()->exited() &&
				tracer.waitStatus()->status() == cosmos::ExitStatus::FAILURE);
		RUN_STEP("execve-old-pid-is-not-there", tracer.oldPID() == std::nullopt);
		RUN_STEP("new-executable-matches-exiter", tracer.newExecutable() == m_exiter);
		if (!onValgrind()) {
			// when running on valgrind then there's a valgrind frontend instead, confusing things
			RUN_STEP("old-executable-is-us", tracer.oldExecutable().find("execve") != std::string::npos);
			RUN_STEP("old-cmdline-is-ours", tracer.oldCmdline() == m_argv);
		}
	}

	void testOtherThreadExecve() {
		START_TEST("non-main-thread execve (multithreaded)");

		ExecveTracer tracer{clues::SystemCallNr::EXECVE};

		TraceeCreator creator{[this]() {
				// create a random thread that runs execve
				cosmos::PosixThread thread{
					thread_entry_exec, cosmos::pthread::ThreadArg{(intptr_t)m_exiter.c_str()}};
				// just block to avoid an exit of the main thread.
				thread.join();
			}, tracer};
		creator.run(clues::FollowChildren{true});
		RUN_STEP("seen-execve-entry", tracer.numExecEntrySeen() == 1);
		RUN_STEP("seen-execve-exit", tracer.numExecExitSeen() == 1);
		RUN_STEP("num-entry-matches-num-exit",
				tracer.numExecEntrySeen() == tracer.numExecExitSeen());
		RUN_STEP("seen-successful-execve", tracer.numSuccessfulExecSeen() == 1);
		RUN_STEP("seen-attached-twice", tracer.numSeenAttached() == 2);
		RUN_STEP("seen-exited", tracer.waitStatus() != std::nullopt);
		RUN_STEP("num-exited-is-two", tracer.numSeenExits() == 2);
		RUN_STEP("seen-lost-to-execve", tracer.numSeenLostToExecve() == 1);
		RUN_STEP("wait-status-is-zero",
				tracer.waitStatus()->exited() &&
				tracer.waitStatus()->status() == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("execve-old-pid-matches-other-thread", tracer.oldPID() == tracer.attachedPIDs().back());
		RUN_STEP("new-executable-matches-exiter", tracer.newExecutable().find("exiter") != std::string::npos);
		if (!onValgrind()) {
			// when running on valgrind then there's a valgrind frontend instead, confusing things
			RUN_STEP("old-executable-is-us", tracer.oldExecutable().find("execve") != std::string::npos);
			RUN_STEP("old-cmdline-is-ours", tracer.oldCmdline() == m_argv);
		}
	}
protected:
	/// path to the exiter helper
	std::string m_exiter;
};

int main(const int argc, const char **argv) {
	ExecveTest test;
	return test.run(argc, argv);
}

