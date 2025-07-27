// C++
#include <iostream>
#include <regex>
#include <list>
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

	enum class EventFlag {
		ALLOW_OUT_OF_ORDER = 1
	};

	using EventFlags = cosmos::BitMask<EventFlag>;

	struct EventInfo {
		std::regex pattern;
		EventFlags flags;

		EventInfo(const std::regex &&_pattern, const EventFlags &_flags = {}) :
				pattern{std::move(_pattern)},
				flags{_flags} {
		}

		bool allowOutOfOrder() const {
			return flags[EventFlag::ALLOW_OUT_OF_ORDER];
		}
	};

	void runTests() override {
		testExecveAt();
		testExitCode();
		testForkWithoutFollow();
		testForkWithFollow();
		// explicitly shut down to prevent a bogus file descriptor
		// leak alarm in TestBase
		m_invoker.shutdown();
	}

	void testExecveAt() {
		START_TEST("test execveat()");

		/*
		 * we're looking for an execveat system call here which is
		 * correctly detected as a change of execution context
		 */
		m_expected_events = {
			EventInfo{std::regex{R"(^execveat\(.*= 0)"}},
			EventInfo{std::regex{"no longer running.*helpers"}},
			EventInfo{std::regex{"now running.*true"}},
		};

		auto status = m_invoker.run({"--", findHelper("fexec")}, m_parser_cb);
		RUN_STEP("tracer-exited-successfully", status == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

	void testExitCode() {
		START_TEST("test exit code");

		/*
		 * we're simply looking for the expected exit status both of
		 * the tracer itself and the matching diagnostic.
		 */

		m_expected_events = {
			EventInfo{std::regex{"exited with 77"}},
		};

		auto status = m_invoker.run({"--", findHelper("exiter"), "77"}, m_parser_cb);
		RUN_STEP("tracer-exited-with-77", status == cosmos::ExitStatus{77});
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

	void testForkWithoutFollow() {
		START_TEST("test fork without follow");

		/*
		 * this runs without --follow, thus we
		 * don't expect an additionally attached tracee.
		 */

		m_expected_events = {
			EventInfo{std::regex{R"(^clone\(.*\) = [0-9]+)"}},
		};

		m_forbidden_events = {
			std::regex{"automatically attached"},
		};

		const auto forker = findHelper("forker");

		auto status = m_invoker.run({"--", forker}, m_parser_cb);
		RUN_STEP("tracer-exited-successfully", status == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

	void testForkWithFollow() {
		START_TEST("test fork with follow");

		/*
		 * this time we expect an automatically attached tracee
		 */

		m_expected_events = {
			EventInfo{std::regex{R"(clone\(.*\) = [0-9]+)"}, EventFlag::ALLOW_OUT_OF_ORDER},
			EventInfo{std::regex{"automatically attached.*created by PID.*via fork"}, EventFlag::ALLOW_OUT_OF_ORDER}
		};

		const auto forker = findHelper("forker");

		auto status = m_invoker.run({"-f", "--", forker}, m_parser_cb);
		RUN_STEP("tracer-exited-successfully", status == cosmos::ExitStatus::SUCCESS);
		RUN_STEP("seen-all-expected-trace-events", verifyEvents());
	}

protected: // utils
	   //
	void parseEvents(const std::string &line) {
		/*
		 * normally we expect events to appear in the order they're
		 * found in m_expected_events.
		 *
		 * when multi-threading is involved then races can occur, thus
		 * some events are allowed out-of-order. These are always
		 * checked if no other match is found.
		 */
		if (!m_expected_events.empty()) {
			auto &next_event = m_expected_events.front();

			if (std::regex_search(line, next_event.pattern)) {
				m_seen_events.push_back(line);
				m_expected_events.pop_front();
			} else {
				for (auto it = ++m_expected_events.begin(); it != m_expected_events.end(); it++) {
					auto &event = *it;
					if (!event.allowOutOfOrder())
						continue;

					if (std::regex_search(line, event.pattern)) {
						m_seen_events.push_back(line);
						m_expected_events.erase(it);
						break;
					}
				}
			}
		}

		for (const auto &forbidden: m_forbidden_events) {
			if (std::regex_search(line, forbidden)) {
				m_violated_events.push_back(line);
			}
		}
	}

	bool verifyEvents() {
		auto ret = m_expected_events.empty();

		if (!ret) {
			if (!m_seen_events.empty()) {
				std::cerr << "\n\t → last matching event was " << m_seen_events.back() << "\n";
			} else {
				std::cerr << "\n\t → no matching events seen\n";
			}
		}

		for (const auto &violation: m_violated_events) {
			std::cerr << "\n\t → forbidden event occured: " << violation << "\n";
			ret = false;
		}

		m_seen_events.clear();
		m_violated_events.clear();
		m_forbidden_events.clear();
		m_expected_events.clear();

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
	std::list<EventInfo> m_expected_events;

	std::vector<std::regex> m_forbidden_events;
	std::vector<std::string> m_violated_events;
};

int main(const int argc, const char **argv) {
	TracerTest test;
	return test.run(argc, argv);
}
