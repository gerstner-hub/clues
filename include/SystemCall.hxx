#ifndef TUXTRACE_SYSTEMCALL_HXX
#define TUXTRACE_SYSTEMCALL_HXX

// C++
#include <iosfwd>
#include <map>
#include <string>
#include <vector>
#include <utility>

// Linux

// tuxtrace
#include <tuxtrace/include/RegisterSet.hxx>

namespace tuxtrace
{
	class SystemCall;
	class TracedProc;
}

std::ostream& operator<<(std::ostream &o, const tuxtrace::SystemCall &sc);

namespace tuxtrace
{


//! a system call table number
typedef RegisterSet::Word SystemCallNr;

class SystemCallParameter;

/**
 * \brief
 * 	Base class for all kinds of different system call instances
 * \details
 * 	This type stores all properties that are common to all system calls:
 *
 * 	- the system call nr.
 * 	- the number of parameters the system call takes
 * 	- a human readable name to identify the system call
 *
 * 	The actual instance type SystemCall knows all about the individual
 * 	system call parameters and type of return value etc.
 *
 * 	Also a virtual print() function allows to generically assemble
 * 	information about a system call
 **/
class SystemCall
{
	friend std::ostream& ::operator<<(std::ostream&, const SystemCall&);
public: // types

	//! vector of the required parameters for a system call
	typedef std::vector<SystemCallParameter*> ParameterVector;

public: // functions

	SystemCall(
		const SystemCallNr nr,
		const char *name,
		SystemCallParameter *ret,
		ParameterVector &&pars
	) :
		m_nr(nr),
		m_name(name),
		m_return(ret),
		m_pars(pars)
	{}

	~SystemCall();

	void setEntryRegs(const TracedProc &proc, const RegisterSet &r);
	void setExitRegs(const TracedProc &proc, const RegisterSet &r);

	//! returns the system call's name
	const char* name() const { return m_name; }
	//! returns the number of parameters for this system call
	size_t numPars() const { return m_pars.size(); }
	//! returns the system call table nr. for this system call
	SystemCallNr callNr() const { return m_nr; }
	
protected: // functions	
	
protected:

	//! the raw sytem call number we represent
	SystemCallNr m_nr;
	//! the basic name of the system call we're representing
	const char *m_name;
	//! the return value type of the system call
	SystemCallParameter *m_return;
	//! the array of system call parameters, if any
	ParameterVector m_pars;
};

/**
 * \brief
 * 	Base class for any kind of system call parameter
 **/
class SystemCallParameter
{
public:

	SystemCallParameter(const char *name) :
		m_name(name)
	{}

	void set(const TracedProc &proc, const RegisterSet::Word word);

	const char* name() const { return m_name; }
	RegisterSet::Word value() const { return m_val; }
	
	//! returns a string representation of the parameter
	virtual std::string str() const;

protected:

	//! processes the value stored in m_val acc. to the actual parameter
	//! type
	virtual void process(const TracedProc &proc) {};

protected:

	//! a human readable name for the parameter
	const char *m_name;
	//! the raw register value for the parameter
	RegisterSet::Word m_val;
};

#if 0
template <typename RET, typename... PARS>
class SystemCall :
	public SystemCallBase
{
public:

	SystemCall(
		const SystemCallNr nr,
		const char *name) :
		SystemCallBase(nr, name, sizeof...(PARS)),
		m_pars()
	{
	}

	void printPars(std::ostream &o) const override;

	template <size_t NUM=0, typename CALL, typename... PACK>
	typename std::enable_if<NUM == sizeof...(PACK), void>::type
		itTuple(std::ostream &o, const std::tuple<PACK...> &p, CALL &c) const
	{
	}

	template <size_t NUM=0, typename CALL, typename... PACK>
	typename std::enable_if<NUM < sizeof...(PACK), void>::type
	itTuple(std::ostream &o, const std::tuple<PACK...> &tuple, CALL &call) const
	{
		call(o, std::get<NUM>(tuple));

		itTuple<NUM+1, CALL, PACK...>( o, tuple, call );
	}

	const RET& returnVal() const { return m_return; }

	template<typename T>
	void operator()(std::ostream &o, const T &t) const;

protected:

protected:

	//! the return value type of the system call
	RET m_return;
	//! the unknown amount of templated system call parameters
	std::tuple<PARS...> m_pars;
};
#endif

/**
 * \brief
 * 	Stores information about each system call nr. in form of
 * 	SystemCall objects
 * \details
 * 	This is a caching map object. It doesn't fill in all system calls at
 * 	once but fills in each system call as it comes up.
 **/
class SystemCallDB :
	protected std::map<SystemCallNr, SystemCall*>
{
public:

	SystemCall& get(const SystemCallNr nr);
	
	const SystemCall& get(const SystemCallNr nr) const
	{ return const_cast<SystemCallDB&>(*this).get(nr); }

protected:

	SystemCall* createSysCall(const SystemCallNr nr);
};

} // end ns

std::ostream& operator<<(
	std::ostream &o,
	const tuxtrace::SystemCallParameter &par);

#endif // inc. guard

