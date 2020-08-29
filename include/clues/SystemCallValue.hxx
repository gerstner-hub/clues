#ifndef CLUES_SYSTEMCALLVALUE_HXX
#define CLUES_SYSTEMCALLVALUE_HXX

// C++
#include <iosfwd>

// clues
#include "clues/SystemCall.hxx"

namespace clues
{

/**
 * \brief
 * 	Base class for any kind of system call value
 * \details
 * 	This can represent a system call parameter or return value.
 **/
class SystemCallValue
{
	friend SystemCall;
public: // types

	//! basic type of system call value
	enum class Type
	{
		//! the value is an input parameter to the system call
		PARAM_IN,
		//! the value is an output parameter filled by in by the
		//! system call
		PARAM_OUT,
		//! the value is both an input and output parameter
		PARAM_IN_OUT,
		//! the value is a system call return value
		RETVAL
	};

public: // functions

	/**
	 * \brief
	 * 	Constructs new SystemCallValue
	 * \param[in] short_name
	 * 	A short friendly name for this value (one word)
	 * \param[in] long_name
	 *	A longer name for this value, optional
	 * \param[in] type
	 * 	The basic type of the value
	 **/
	explicit SystemCallValue(
		const Type &type,
		const char *short_name,
		const char *long_name = nullptr) :
		m_type(type),
		m_short_name(short_name),
		m_long_name(long_name)
	{}

	virtual ~SystemCallValue() {}

	auto type() const { return m_type; }

	bool isIn() const { return m_type == Type::PARAM_IN; }
	bool isOut() const { return m_type == Type::PARAM_OUT; }
	bool isInOut() const { return m_type == Type::PARAM_IN_OUT; }
	bool isReturnValue() const { return m_type == Type::RETVAL; }

	/**
	 * \brief
	 *	Fills the system call value from the given register data
	 **/
	void fill(const TracedProc &proc, const RegisterSet::Word word);

	//! returns whether the value needs to be updated after the
	//! system call is finished
	bool needsUpdate() const { return m_type != Type::PARAM_IN; }

	//! returns the friendly short name for this value
	const char* shortName() const { return m_short_name; }
	//! returns the friendly long name for this value, if available, else
	//! the sort name
	const char* longName() const { return m_long_name ? m_long_name : shortName(); }

	auto hasLongName() const { return m_long_name != nullptr; }

	//! returns the currently stored value
	auto value() const { return m_val; }

	/**
	 * \brief
	 *	Returns a human readable string representation of the
	 *	value
	 * \details
	 * 	This member function should be specialized by derived classes
	 * 	to output the value data in a fahsion more suitable for the
	 * 	concrete value type.
	 **/
	virtual std::string str() const;

protected: // functions

	//! processes the value stored in m_val acc. to the actual value type
	virtual void processValue(const TracedProc &proc) = 0;

	//! called upon exit of the system call to update possible out
	//! parameters
	virtual void updateData(const TracedProc &proc) = 0;

	//! sets the system call context this value is a part of
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

protected: // data

	//! the system call context the value is a part of
	const SystemCall *m_call = nullptr;
	//! the type of value
	const Type m_type;
	//! a human readable short name for the value, should be one word only
	const char *m_short_name = nullptr;
	//! a human readable longer name for the value
	const char *m_long_name = nullptr;
	//! the raw register value for the value
	RegisterSet::Word m_val;
};

class ReturnValue :
	public SystemCallValue
{
public:
	explicit ReturnValue(const char *short_name, const char *long_name = nullptr) :
		SystemCallValue(Type::RETVAL, short_name, long_name)
	{}

protected: // functions

	void processValue(const TracedProc &proc) override {}

	void updateData(const TracedProc &proc) override {}
};

/**
 * \brief
 * 	A pass by value parameter for a system call
 * \details
 * 	These are typically PARAM_IN types denoting IDs, enums, flags etc.
 * 	that are pass to a system call or returned from a system call.
 *
 * 	The processValue() and updateValue() functions are implemented as
 * 	no-ops, because no additional data needs to be fetched from the tracee
 * 	for this kind of parameter.
 **/
class ValueParameter :
	public SystemCallValue
{
public: // functions

	explicit ValueParameter(
		const Type &type,
		const char *short_name,
		const char *long_name) :
		SystemCallValue(type, short_name, long_name)
	{}

protected: // functions

	void processValue(const TracedProc &proc) override {}

	void updateData(const TracedProc &proc) override {}
};

/**
 * \brief
 * 	Specialization of ValueParameter for IN parameters
 **/
class ValueInParameter :
	public ValueParameter
{
public:

	explicit ValueInParameter(
		const char *short_name,
		const char *long_name = nullptr) :
		ValueParameter(Type::PARAM_IN, short_name, long_name)
	{}
};

/**
 * \brief
 * 	Specialization of ValueParameter for OUT parameters
 **/
class ValueOutParameter :
	public ValueParameter
{
public: // functions

	explicit ValueOutParameter(
		const char *short_name,
		const char *long_name) :
		ValueParameter(Type::PARAM_OUT, short_name, long_name)
	{}
};

/**
 * \brief
 * 	A value that consists of a pointer to some data area
 * \details
 * 	Unlike the ValueParameter the PointerValue is only a pointer to
 * 	some userspace data structure. Thus the processValue() and updateData()
 * 	functions need to perform more complex operations on the tracee to
 * 	gather the data as appropriate.
 **/
class PointerValue :
	public SystemCallValue
{
public: // functions
	explicit PointerValue(
		const Type &type,
		const char *short_name,
		const char *long_name) :
		SystemCallValue(type, short_name, long_name)
	{}
};

/**
 * \brief
 * 	Specialization of a PointerValue for out-parameters
 * \details
 * 	This specialization is pre-configured to have implemented the
 * 	processValue() member function that serves no purpose for out
 * 	parameters. Also the value type is predetermined to OUT.
 **/
class PointerOutValue :
	public PointerValue
{
public: // functions
	explicit PointerOutValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_OUT) :
		PointerValue(type, short_name, long_name)
	{}

protected: // functions

	//! \brief
	//! empty implementation of this function, because it's not needed
	//! for out parameters
	void processValue(const TracedProc &proc) override {}
};

/**
 * \brief
 * 	Specialization of a PointerValue for in-parameters
 * \details
 * 	This specialization is pre-configured to have implemented the
 * 	updateData() member function that serves no purpose for in parameters.
 * 	Also the value type is predetermined to in.
 **/
class PointerInValue :
	public PointerValue
{
public: // functions
	explicit PointerInValue(
		const char *short_name,
		const char *long_name = nullptr) :
		PointerValue(Type::PARAM_IN, short_name, long_name)
	{}

protected: // functions

	void updateData(const TracedProc &proc) override {}
};

} // end ns

std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallValue &value
);

#endif // inc. guard

