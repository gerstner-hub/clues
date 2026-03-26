// C++
#include <iostream>
#include <vector>

// cosmos
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/path.hxx>

// clues
#include <clues/Tracee.hxx>

// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

/*
 * This test verified whether detaching from a forked child works during the
 * PTRACE_EVENT callback.
 */

class CloneTracer : public clues::EventConsumer {
public:
	explicit CloneTracer() {
	}

	void newChildProcess(clues::Tracee &, clues::Tracee &child, const cosmos::ptrace::Event event, const clues::EventConsumer::StatusFlags) override {
		(void)event;
		child.detach();
		std::cout << "detaching from new child proc\n";
		detach_count++;
	}

public:
	size_t detach_count = 0;
};

class DetachTest : public cosmos::TestBase {
	void runTests() override {
		findCloneTest();
		testDetachOnClone();
	}

	void findCloneTest() {
		std::string dir{m_argv.at(0)};
		dir = dir.substr(0, dir.rfind('/'));
		auto cloner = dir + "/samples/clone";
		cloner = cosmos::fs::canonicalize_path(cloner);
		if (!cosmos::fs::exists_file(cloner)) {
			throw cosmos::RuntimeError{"couldn't find 'clone' syscall test helper"};
		}

		m_clone_test = cloner;
	}

	void testDetachOnClone() {
		START_TEST("detach from child on clone/fork event");
		CloneTracer tracer;
		TraceeCreator creator{[this]() {
				cosmos::proc::exec(m_clone_test);
			}, tracer};
		creator.run(clues::FollowChildren{true});
		RUN_STEP("seen-detaches", tracer.detach_count > 1);
	}
protected:
	/// path to the clone() syscall test program
	std::string m_clone_test;
};


int main(const int argc, const char **argv) {
	DetachTest test;
	return test.run(argc, argv);
}
