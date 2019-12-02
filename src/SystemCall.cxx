// C++
#include <ostream>

// tuxtrace
#include <tuxtrace/include/SystemCall.hxx>
#include <tuxtrace/include/SystemCallDB.hxx>
#include <tuxtrace/include/SystemCallParameter.hxx>

namespace tuxtrace
{
	
SystemCall::SystemCall(
	const SystemCallNr nr,
	const char *name,
	SystemCallParameter *ret,
	ParameterVector &&pars
) : m_nr(nr), m_name(name), m_return(ret), m_pars(pars)
{
	for( auto &par: m_pars )
		par->setSystemCall(*this);
}

SystemCall::~SystemCall()
{
	while( ! m_pars.empty() )
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
	if( m_return )
		m_return->set(proc, r.syscallRes());

	
	for( auto &par: m_pars )
	{
		if( par->needsUpdate() )
			par->update(proc);
	}
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

