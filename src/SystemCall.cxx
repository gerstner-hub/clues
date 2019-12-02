// C++
#include <iostream>
#include <cassert>

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
	ParameterVector &&pars,
	const size_t open_id_par,
	const size_t close_fd_par
) :
	m_nr(nr), m_name(name), m_return(ret), m_pars(pars),
	m_open_id_par(open_id_par), m_close_fd_par(close_fd_par)
{
	assert( open_id_par == SIZE_MAX || open_id_par < m_pars.size() );
	assert( close_fd_par == SIZE_MAX || close_fd_par < m_pars.size() );

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
			par->exitedCall(proc);
	}
}

void SystemCall::updateOpenFiles(DescriptorPathMapping &mapping)
{
	if( m_open_id_par != SIZE_MAX )
	{
		const int new_fd = (int)m_return->value();

		if( new_fd < 0 )
			return;

		auto res = mapping.insert(
			std::make_pair(new_fd, m_pars[m_open_id_par]->str())
		);

		if( ! res.second )
		{
			std::cerr
				<< "WARNING: file descriptor already open?!"
				<< std::endl;
		}
	}
	else if( m_close_fd_par != SIZE_MAX )
	{
		if( m_return->value() != 0 )
			// unsuccessful system call, so don't update anything
			return;

		const int closed_fd = (int)m_pars[m_close_fd_par]->value();

		if( mapping.erase(closed_fd) == 0 )
		{
		#if 0
			// this is stdout, stderr & friends
			std::cerr
				<< "WARNING: closed file that wasn't open?!"
				<< std::endl;
		#endif
		}
	}
	else return;

	//std::cout << "New path mapping:\n" << mapping << std::endl;
}


void SystemCallParameter::set(
	const TracedProc &proc,
	const RegisterSet::Word word)
{
	m_val = word;
	enteredCall(proc);
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

