// C++
#include <iostream>

// Cosmos
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/proc/process.hxx>

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

class RegularExecveTracer : public clues::EventConsumer {
public:
	explicit RegularExecveTracer(const clues::SystemCallNr exec_nr) :
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
protected:
	void syscallEntry(clues::Tracee &,
			const clues::SystemCall &call,
			const State) override {
		if (call.callNr() == m_exec_nr) {
			m_seen_exec_entry++;
		}
	}

	void syscallExit(clues::Tracee &,
			const clues::SystemCall &call,
			const State) override {
		if (call.callNr() == m_exec_nr) {
			m_seen_exec_exit++;
			if (call.hasResultValue()) {
				m_seen_successful_exec++;
			}
		}
	}

	void attached(clues::Tracee &) override {
		m_seen_attached++;
	}

	void exited(clues::Tracee &, const cosmos::WaitStatus status, const State) override {
		m_status = status;
	}

	void newExecutionContext(clues::Tracee &tracee,
			const std::string &old_executable,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> old_pid) {
		m_old_executable = old_executable;
		m_old_cmdline = old_cmdline;
		m_old_pid = old_pid;
		m_new_executable = tracee.executable();
	}

	size_t m_seen_exec_entry = 0;
	size_t m_seen_exec_exit = 0;
	size_t m_seen_successful_exec = 0;
	size_t m_seen_attached = 0;
	const clues::SystemCallNr m_exec_nr;
	std::optional<cosmos::WaitStatus> m_status;
	std::string m_old_executable;
	cosmos::StringVector m_old_cmdline;
	std::optional<cosmos::ProcessID> m_old_pid;
	std::string m_new_executable;
};

class ExecveTest : public cosmos::TestBase {
	void runTests() override {
		testRegularExecve();
	}

	void testRegularExecve() {
		START_TEST("regular execve");

		RegularExecveTracer tracer{clues::SystemCallNr::EXECVE};

		// lookup the exact path beforehand to avoid additional
		// execve() attempts when only using the basename
		auto true_exe = cosmos::fs::which("true");

		RUN_STEP("find-true-executable", true_exe != std::nullopt);

		TraceeCreator creator{[&true_exe]() {
				cosmos::proc::exec(*true_exe);
			}, tracer};
		creator.run();

		RUN_STEP("seen-execve-entry", tracer.numExecEntrySeen() == 1);
		RUN_STEP("seen-execve-exit", tracer.numExecExitSeen() == 1);
		RUN_STEP("num-entry-matches-num-exit",
				tracer.numExecEntrySeen() == tracer.numExecExitSeen());
		RUN_STEP("seen-successful-execve", tracer.numSuccessfulExecSeen() == 1);
		RUN_STEP("seen-attached-once", tracer.numSeenAttached() == 1);
		RUN_STEP("seen-exited", tracer.waitStatus() != std::nullopt);
		RUN_STEP("wait-status-is-zero",
				tracer.waitStatus()->exited() &&
				tracer.waitStatus()->status() == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("execve-old-pid-is-not-there", tracer.oldPID() == std::nullopt);
		RUN_STEP("new-executable-matches-true", tracer.newExecutable() == true_exe);
		if (!onValgrind()) {
			// when running on valgrind then there's a valgrind frontend instead, confusing things
			RUN_STEP("old-executable-is-us", tracer.oldExecutable().find("execve") != std::string::npos);
			RUN_STEP("old-cmdline-is-ours", tracer.oldCmdline() == m_argv);
		}
	}
};

int main(const int argc, const char **argv) {
	ExecveTest test;
	return test.run(argc, argv);
}

