// C++
#include <iostream>
#include <regex>
#include <vector>

// Test
#include "TestBase.hxx"
#include "TracerInvoker.hxx"

using namespace std::string_literals;

class TracerTest : public cosmos::TestBase {
public:
	TracerTest() {
		m_parser_cb = std::bind(&TracerTest::parseEvents, this, std::placeholders::_1);
	}

protected:
	void runTests() override {
		testExecveAt();
		testExitCode();
		m_invoker.shutdown();
	}

	void testExecveAt() {
		START_TEST("test execveat()");

		/*
		 * we're looking for an execveat system call here which is
		 * correctly detected as a change of execution context
		 */
		m_expected_events = {
			std::regex{R"(^execveat\(.*= 0)"},
			std::regex{"no longer running.*helpers"},
			std::regex{"now running.*true"},
		};

		auto status = m_invoker.run({"--", findHelper("fexec")}, m_parser_cb);
		RUN_STEP("tracer-exited-successfully", status == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

	void testExitCode() {
		START_TEST("test exit code");

		m_expected_events = {
			std::regex{"exited with 77"},
		};

		auto status = m_invoker.run({"--", findHelper("exiter"), "77"}, m_parser_cb);
		RUN_STEP("tracer-exited-with-77", status == cosmos::ExitStatus{77});
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

protected: // utils
	   //
	void parseEvents(const std::string &line) {
		if (m_seen_events.size() == m_expected_events.size())
			return;

		const auto &next_event = m_expected_events[m_seen_events.size()];

		if (std::regex_search(line, next_event)) {
			m_seen_events.push_back(line);
		}
	}

	bool verifyEvents() {
		auto ret = m_expected_events.size() == m_seen_events.size();
		m_seen_events.clear();
		return ret;
	}

	std::string findHelper(const std::string& base) {
		auto helper = std::string{m_argv[0]};
		helper = helper.substr(0, helper.find_last_of("/"));
		helper += "/helpers/"s + base;

		if (!cosmos::fs::exists_file(helper)) {
			throw cosmos::RuntimeError{cosmos::sprintf("Could not find helper executable at %s", helper.data())};
		}

		return helper;
	}
protected:
	TracerInvoker m_invoker;
	TracerInvoker::LineParserCB m_parser_cb;
	std::vector<std::string> m_seen_events;
	std::vector<std::regex> m_expected_events;
};

int main(const int argc, const char **argv) {
	TracerTest test;
	return test.run(argc, argv);
}
