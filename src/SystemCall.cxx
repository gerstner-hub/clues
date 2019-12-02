// C++
#include <ostream>

// Linux
#include <sys/syscall.h> // system call nr. constants

// tuxtrace
#include <tuxtrace/include/SystemCall.hxx>
#include <tuxtrace/include/Parameters.hxx>

namespace tuxtrace
{

SystemCall& SystemCallDB::get(const SystemCallNr nr)
{
	iterator it = find(nr);

	if( it == end() )
	{
		std::pair<iterator, bool> res;
		res = insert(
			std::make_pair(
				nr,
				createSysCall(nr)
			)
		);

		it = res.first;
	}

	return *(it->second);
}
				
SystemCall* SystemCallDB::createSysCall(
	const SystemCallNr nr)
{
	typedef SystemCallParameter Par;
	typedef SystemCall Call;

	switch( nr )
	{
	case SYS_write:
		//return new SystemCall<ssize_t, int, void*, size_t>(nr, "write");
		return new Call(nr, "write",
			new Par("bytes written"),
			{
				new FileDescriptorParameter(),
				new Par("source data"),
				new Par("source length")
			}
		);
	case SYS_open:
		//return new SystemCall<int, /*char**/ void*, int, mode_t>(nr, "open");
		return new Call(nr, "open",
			new FileDescriptorParameter(),
			{
				new StringParameter("filename"),
				new Par("flags"),
				new Par("mode")
			}
		);
	case SYS_close:
		//return new SystemCall<int, int>(nr, "close");
		return new Call(nr, "close",
			new Par("errno"),
			{
				new FileDescriptorParameter()
			}
		);
	default:
		return new Call(nr, "unknown",
			new Par("result"),
			{} );
	}
}

SystemCall::~SystemCall()
{
	while( m_pars.empty() )
	{
		delete *m_pars.rbegin();
		m_pars.pop_back();
	}

	delete m_return;
}
	
void SystemCall::setEntryRegs(const TracedProc &proc, const RegisterSet &r)
{
	for( size_t par = 0; par < m_pars.size(); par++ )
	{
		m_pars[par]->set(proc, r.syscallParameter(par));
	}
}

void SystemCall::setExitRegs(const TracedProc &proc, const RegisterSet &r)
{
	if( ! m_return )
		return;

	m_return->set(proc, r.syscallRes());
}

void SystemCallParameter::set(
	const TracedProc &proc,
	const RegisterSet::Word word)
{
	m_val = word;
	process(proc);
}

std::string SystemCallParameter::str() const
{
	// by default simply return the register value as a string
	return std::to_string(m_val);
}

} // end ns

std::ostream& operator<<(std::ostream &o, const tuxtrace::SystemCall &sc)
{
	o << sc.name() << " (" << sc.callNr() << "): " << sc.numPars() << " parameters";

	for( const auto &par: sc.m_pars )
	{
		o << "\n\t" << *par;
	}

	o << "\n\tResult -> " << *(sc.m_return);

	return o;
}

std::ostream& operator<<(
	std::ostream &o,
	const tuxtrace::SystemCallParameter &par)
{
	o << par.name() << " = " << par.str();
	return o;
}

