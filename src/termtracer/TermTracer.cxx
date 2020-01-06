// tclap
#include <tclap/CmdLine.h>

// C++
#include <cstdlib>
#include <iostream>

// clues
#include "clues/Init.hxx"
#include "clues/TracedProc.hxx"
#include "clues/SubProc.hxx"
#include "clues/errors/CluesError.hxx"
#include "clues/SystemCall.hxx"

namespace clues
{

class TermTracer :
	public TraceEventConsumer
{
public: // functions

	TermTracer();

	~TermTracer();

	int run(const int argc, const char **argv);

protected: // event consumer interface


	void syscallEntry(const SystemCall &sc) override;

	void syscallExit(const SystemCall &sc) override;

protected: // data

	TCLAP::CmdLine m_cmdline;
	//! already running process to attach to
	TCLAP::ValueArg<pid_t> m_attach_proc;
	//! switch to express we want to start a new process as a frontend
	TCLAP::SwitchArg m_start_proc;

	TracedSeizedProc m_seized_proc;
	TracedSubProc m_sub_proc;
	//! generic handling of either TracedSeizedProc or TracedSubProc
	TracedProc *m_proc = nullptr;
};

TermTracer::TermTracer() :
	m_cmdline("Command line process tracer", ' ', "0.1"),
	m_attach_proc(
		"p", "process",
		"attach to the given already running process for tracing",
		false,
		INVALID_PID,
		"Process ID"),
	m_start_proc(
		"c", "create",
		"create a new process using arguments specified after '--'",
		false),
	m_seized_proc(*this),
	m_sub_proc(*this)
{
}

TermTracer::~TermTracer()
{
	m_proc = nullptr;
}

void TermTracer::syscallEntry(const SystemCall &sc)
{

}

void TermTracer::syscallExit(const SystemCall &sc)
{
	std::cout << sc << std::endl;
}

int TermTracer::run(const int argc, const char **argv)
{
	m_cmdline.add(m_attach_proc);
	m_cmdline.add(m_start_proc);
	m_cmdline.parse(argc, argv);

	if( m_attach_proc.isSet() )
	{
		m_seized_proc.configure( m_attach_proc.getValue() );
		m_proc = &m_seized_proc;
	}
	else if( m_start_proc.isSet() )
	{
		// extract any additional arguments into a StringVector
		StringVector sv;
		bool found_sep = false;

		for( auto arg = 1; arg < argc; arg++ )
		{
			if( std::string(argv[arg]) == "--" )
			{
				found_sep = true;
				continue;
			}

			if( found_sep )
			{
				sv.push_back( argv[arg] );
			}
		}

		m_sub_proc.configure(sv);
		m_proc = &m_sub_proc;
	}
	else
	{
		std::cerr << "Neither -p nor -c was given. Nothing to do.\n";
		return EXIT_FAILURE;
	}

	m_proc->attach();
	m_proc->trace();

	m_proc->detach();

	return m_attach_proc.isSet() ? EXIT_SUCCESS : m_sub_proc.exitCode();
}

}

int main(const int argc, const char **argv)
{
	try
	{
		clues::Init init;
		return clues::TermTracer().run(argc, argv);
	}
	catch( const clues::CluesError &ce )
	{
		std::cerr
			<< "Exception catched:\n\n"
			<< ce.what() << std::endl;

		return EXIT_FAILURE;
	}
}

