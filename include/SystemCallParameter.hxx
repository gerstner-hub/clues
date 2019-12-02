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

	SystemCallParameter(const char *name, const FlowType &flow) :
		m_call(nullptr),
		m_flow(flow),
		m_name(name)
	{}

	virtual ~SystemCallParameter() {}

	const FlowType type() const { return m_flow; }

	const bool isIn() const { return m_flow == IN; }
	const bool isOut() const { return m_flow == OUT; }
	const bool isInOut() const { return m_flow == IN_OUT; }

	void set(const TracedProc &proc, const RegisterSet::Word word);

	bool needsUpdate() const { return m_flow != IN; }

	const char* name() const { return m_name; }
	RegisterSet::Word value() const { return m_val; }

	//! returns a string representation of the parameter
	virtual std::string str() const;

protected: // functions

	//! processes the value stored in m_val acc. to the actual parameter
	//! type before entering the system call
	virtual void enteredCall(const TracedProc &proc) = 0;

	//! called upon exit of the system call to update possible out par.
	virtual void exitedCall(const TracedProc &proc) = 0;

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

/**
 * \brief
 * 	A pass by value parameter for a system call
 * \details
 * 	These are typically INT parameter denoting IDs, enums, flags etc. that
 * 	are pass to a system call or returned from a system call.
 *
 * 	The enteredCall and exitedCall functions are implemented as no-ops,
 * 	because no additional data needs to be fetched from the tracee for
 * 	this kind of parameter.
 **/
class ValueParameter :
	public SystemCallParameter
{
public:

	ValueParameter(const char *name, const FlowType &flow) :
		SystemCallParameter(name, flow)
	{}

protected:

	void enteredCall(const TracedProc &proc) override {}

	void exitedCall(const TracedProc &proc) override {}
};

/**
 * \brief
 * 	Specialization of ValueParameter for IN parameters
 **/
class ValueInParameter :
	public ValueParameter
{
public:

	ValueInParameter(const char *name) :
		ValueParameter(name, SystemCallParameter::IN)
	{}
};

/**
 * \brief
 * 	Specialization of ValueParameter for OUT parameters
 **/
class ValueOutParameter :
	public ValueParameter
{
public:

	ValueOutParameter(const char *name) :
		ValueParameter(name, SystemCallParameter::OUT)
	{}
};

/**
 * \brief
 * 	A parameter that consists of a pointer to some data area
 * \details
 * 	Unlike the ValueParameter the PointerParameter is only a pointer to
 * 	some userspace data structure. Thus the enteredCall() and exitedCall()
 * 	functions need to perform more complex operations on the tracee to
 * 	gather the data as appropriate.
 **/
class PointerParameter :
	public SystemCallParameter
{
public:
	PointerParameter(const char *name, const FlowType &flow) :
		SystemCallParameter(name, flow)
	{}
};

/**
 * \brief
 * 	Specialization of a PointerParameter for out-parameters
 * \details
 * 	This specialization is pre-configured to have implemented the
 * 	enteredCall() member function that serves no purpose for out
 * 	parameters.  Also the flow type is predetermined to OUT.
 **/
class PointerOutParameter :
	public PointerParameter
{
public:
	PointerOutParameter(const char *name) :
		PointerParameter(name, FlowType::OUT)
	{}

protected:

	//! \brief
	//! empty implementation of this function, because it's not needed
	//! for out parameters
	void enteredCall(const TracedProc &proc) override {}

};

/**
 * \brief
 * 	Specialization of a PointerParameter for in-parameters
 * \details
 * 	This specializatin is pre-configured to have implemented the
 * 	exitedCall() member function that serves no purpose for in parameters.
 * 	Also the flow type is predetermined to in.
 **/
class PointerInParameter :
	public PointerParameter
{
public:
	PointerInParameter(const char *name) :
		PointerParameter(name, FlowType::IN)
	{}

protected:

	void exitedCall(const TracedProc &proc) override {}
};

} // end ns

std::ostream& operator<<(
	std::ostream &o,
	const tuxtrace::SystemCallParameter &par);

#endif // inc. guard

