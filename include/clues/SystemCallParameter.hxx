#ifndef CLUES_SYSTEMCALLPARAMETER_HXX
#define CLUES_SYSTEMCALLPARAMETER_HXX

// clues
#include "clues/SystemCall.hxx"

namespace clues
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

	/**
	 * \brief
	 * 	Constructs a new SystemCallParameter
	 * \param[in] name
	 * 	A friendly name for this parameter
	 * \param[in] flow
	 * 	The data flow of the parameter during the system call
	 **/
	SystemCallParameter(const char *name, const FlowType &flow) :
		m_flow(flow),
		m_name(name)
	{}

	virtual ~SystemCallParameter() {}

	const FlowType type() const { return m_flow; }

	const bool isIn() const { return m_flow == IN; }
	const bool isOut() const { return m_flow == OUT; }
	const bool isInOut() const { return m_flow == IN_OUT; }

	void set(const TracedProc &proc, const RegisterSet::Word word);

	//! returns whether the parameter data needs to be updated after the
	//! system call is finished
	bool needsUpdate() const { return m_flow != IN; }

	//! returns the friendly name for this parameter
	const char* name() const { return m_name; }
	//! returns the current value for this parameter
	RegisterSet::Word value() const { return m_val; }

	/**
	 * \brief
	 *	returns a human readable string representation of the
	 *	parameter
	 * \details
	 * 	This member function should be specialized by derived classes
	 * 	for output the parameter data in a fahsion more suitable the
	 * 	concrete parameter type.
	 **/
	virtual std::string str() const;

protected: // functions

	//! processes the value stored in m_val acc. to the actual parameter
	//! type before entering the system call
	virtual void enteredCall(const TracedProc &proc) = 0;

	//! called upon exit of the system call to update possible out
	//! parameters
	virtual void exitedCall(const TracedProc &proc) = 0;

	//! sets the system call context this parameter is a part of
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

protected: // data

	//! the system call context the parameter is a part of
	const SystemCall *m_call = nullptr;
	//! the kind of parameter flow
	const FlowType m_flow;
	//! a human readable name for the parameter
	const char *m_name = nullptr;
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
	const clues::SystemCallParameter &par
);

#endif // inc. guard

