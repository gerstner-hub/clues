#pragma once

#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/fs/File.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/io/Pipe.hxx>
#include <cosmos/io/StreamAdaptor.hxx>
#include <cosmos/proc/ChildCloner.hxx>
#include <cosmos/formatting.hxx>

class TracerInvoker {
public:
	using LineParserCB = std::function<void (const std::string &)>;

	TracerInvoker() {
		if (m_tracer_path.empty()) {
			m_tracer_path = findTracer();
		}

		if (!m_null.isOpen()) {
			m_null.open("/dev/null", cosmos::OpenMode::WRITE_ONLY);
		}
	}

	void shutdown() {
		m_null.close();
	}

	cosmos::ExitStatus run(
			const cosmos::StringVector &args, LineParserCB parser) {
		cosmos::Pipe m_pipe;
		cosmos::ChildCloner cloner;

		cloner.setExe(m_tracer_path);

		for (const auto &arg: args) {
			cloner << arg;
		}

		cloner.setStdErr(m_pipe.writeEnd());
		cloner.setStdOut(m_null.fd());
		auto tracer = cloner.run();
		m_pipe.closeWriteEnd();

		cosmos::InputStreamAdaptor pipe_io{m_pipe.readEnd()};

		std::string line;
		while (std::getline(pipe_io, line).good()) {
			parser(line);
		}

		m_pipe.closeReadEnd();

		auto state = tracer.wait();

		if (!state.exited()) {
			throw cosmos::RuntimeError{"abnormal tracer exit"};
		}

		return *state.status;
	}

	std::string findTracer() const {
		auto tracer = cosmos::fs::read_symlink("/proc/self/exe");
		tracer = tracer.substr(0, tracer.find_last_of("/"));
		tracer += "/../src/termtracer/clues";

		if (!cosmos::fs::exists_file(tracer)) {
			throw cosmos::RuntimeError{cosmos::sprintf("Could not find tracer executable at %s", tracer.c_str())};
		}

		return tracer;
	}

protected:

	std::string m_tracer_path;
	cosmos::File m_null;
};
