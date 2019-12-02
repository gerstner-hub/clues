#ifndef TUXTRACE_SYSTEMCALLPARAMETER_HXX
#define TUXTRACE_SYSTEMCALLPARAMETER_HXX

// tuxtrace
#include <tuxtrace/include/SystemCall.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	Base class for any kind of system call parameter
 **/
class SystemCallParameter
{
	friend SystemCall;
public: // types

	//! direction of data transfer
	enum FlowType
	{
		//! the parameter is an input parameter to the system call
		IN,
		//! the parameter is an output parameter filled by the s. c.
		OUT,
		//! the parameter is both an input and output parameter
		IN_OUT
	};

public: // functions

	SystemCallParameter(const char *name, const FlowType &flow = IN) :
		m_call(nullptr),
		m_flow(flow),
		m_name(name)
	{}

	virtual ~SystemCallParameter() {}

	const FlowType type() const { return m_flow; }

	void set(const TracedProc &proc, const RegisterSet::Word word);

	bool needsUpdate() const { return m_flow != IN; }
	//! called upon exit of the system call to update possible out par.
	virtual void update(const TracedProc &proc) {}

	const char* name() const { return m_name; }
	RegisterSet::Word value() const { return m_val; }
	
	//! returns a string representation of the parameter
	virtual std::string str() const;

protected: // functions

	//! processes the value stored in m_val acc. to the actual parameter
	//! type
	virtual void process(const TracedProc &proc) {};

	//! sets the system call this parameter is a part of
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

protected: // data

	//! \brief
	//! the system call the parameter is a part of for context
	//! sensitiveness
	const SystemCall *m_call;
	//! the kind of parameter flow
	const FlowType m_flow;
	//! a human readable name for the parameter
	const char *m_name;
	//! the raw register value for the parameter
	RegisterSet::Word m_val;
};

} // end ns

std::ostream& operator<<(
	std::ostream &o,
	const tuxtrace::SystemCallParameter &par);

#endif // inc. guard

