#pragma once

// C++
#include <iosfwd>

// clues
#include <clues/SystemCall.hxx>

namespace clues {

/// Base class for any kind of system call value.
/**
 * This can represent a system call parameter or return value.
 **/
class CLUES_API SystemCallValue {
	friend SystemCall;
public: // types

	/// Basic type of system call value.
	enum class Type {
		/// The value is an input parameter to the system call.
		PARAM_IN,
		/// The value is an output parameter filled by in by the system call.
		PARAM_OUT,
		/// The value is both an input and output parameter.
		PARAM_IN_OUT,
		/// The value is a system call return value.
		RETVAL
	};

public: // functions

	/// Constructs new SystemCallValue.
	/**
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
			m_type{type},
			m_short_name{short_name},
			m_long_name{long_name}
	{}

	virtual ~SystemCallValue() {}

	auto type() const { return m_type; }

	bool isIn() const          { return m_type == Type::PARAM_IN; }
	bool isOut() const         { return m_type == Type::PARAM_OUT; }
	bool isInOut() const       { return m_type == Type::PARAM_IN_OUT; }
	bool isReturnValue() const { return m_type == Type::RETVAL; }

	/// Fills the system call value from the given register data.
	void fill(const Tracee &proc, const RegisterSet::Word word);

	/// Returns whether the value needs to be updated after the system call is finished.
	bool needsUpdate() const { return m_type != Type::PARAM_IN; }

	/// Returns the friendly short name for this value.
	const char* shortName() const { return m_short_name; }
	/// Returns the friendly long name for this value, if available, else the sort name.
	const char* longName() const { return m_long_name ? m_long_name : shortName(); }

	auto hasLongName() const { return m_long_name != nullptr; }

	/// Returns the currently stored value.
	auto value() const { return m_val; }

	/// Returns a human readable string representation of the value.
	/**
	 * This member function should be specialized by derived classes to
	 * output the value data in a fashion more suitable for the concrete
	 * value type.
	 **/
	virtual std::string str() const;

protected: // functions

	/// Processes the value stored in m_val acc. to the actual value type.
	virtual void processValue(const Tracee &proc) = 0;

	/// Called upon exit of the system call to update possible out parameters.
	virtual void updateData(const Tracee &proc) = 0;

	/// Sets the system call context this value is a part of.
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

protected: // data

	/// The system call context the value is a part of.
	const SystemCall *m_call = nullptr;
	/// The type of value.
	const Type m_type;
	/// A human readable short name for the value, should be one word only.
	const char *m_short_name = nullptr;
	/// A human readable longer name for the value.
	const char *m_long_name = nullptr;
	/// The raw register value for the value.
	RegisterSet::Word m_val;
};

class ReturnValue :
		public SystemCallValue
{
public:
	explicit ReturnValue(const char *short_name, const char *long_name = nullptr) :
		SystemCallValue{Type::RETVAL, short_name, long_name}
	{}

protected: // functions

	void processValue(const Tracee &) override {}

	void updateData(const Tracee &) override {}
};

/// A pass by value parameter for a system call.
/**
 * These are typically PARAM_IN types denoting IDs, enums, flags etc.  that
 * are pass to a system call or returned from a system call.
 * 
 * The processValue() and updateValue() functions are implemented as no-ops,
 * because no additional data needs to be fetched from the tracee for this
 * kind of parameter.
 **/
class ValueParameter :
		public SystemCallValue {
public: // functions

	explicit ValueParameter(
		const Type &type,
		const char *short_name,
		const char *long_name) :
		SystemCallValue{type, short_name, long_name}
	{}

protected: // functions

	void processValue(const Tracee &) override {}

	void updateData(const Tracee &) override {}
};

/// Specialization of ValueParameter for IN parameters.
class ValueInParameter :
	public ValueParameter {
public:

	explicit ValueInParameter(
		const char *short_name,
		const char *long_name = nullptr) :
		ValueParameter{Type::PARAM_IN, short_name, long_name}
	{}
};

/// Specialization of ValueParameter for OUT parameters.
class ValueOutParameter :
	public ValueParameter {
public: // functions

	explicit ValueOutParameter(
		const char *short_name,
		const char *long_name) :
		ValueParameter{Type::PARAM_OUT, short_name, long_name}
	{}
};

/// A value that consists of a pointer to some data area.
/**
 * Unlike the ValueParameter the PointerValue is only a pointer to some
 * userspace data structure. Thus the processValue() and updateData()
 * functions need to perform more complex operations on the tracee to gather
 * the data as appropriate.
 **/
class PointerValue :
		public SystemCallValue {
public: // functions

	explicit PointerValue(
		const Type &type,
		const char *short_name,
		const char *long_name) :
		SystemCallValue{type, short_name, long_name}
	{}
};

/// Specialization of a PointerValue for out-parameters.
/**
 * This specialization is pre-configured to have implemented the
 * processValue() member function that serves no purpose for out parameters.
 * Also the value type is predetermined to OUT.
 **/
class PointerOutValue :
		public PointerValue {
public: // functions

	explicit PointerOutValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type &type = Type::PARAM_OUT) :
		PointerValue{type, short_name, long_name}
	{}

protected: // functions

	/// Empty implementation of this function, because it's not needed for out parameters.
	void processValue(const Tracee &) override {}
};

/// Specialization of a PointerValue for in-parameters.
/**
 * This specialization is pre-configured to have implemented the updateData()
 * member function that serves no purpose for in parameters. Also the value
 * type is predetermined to in.
 **/
class PointerInValue :
		public PointerValue {
public: // functions

	explicit PointerInValue(
		const char *short_name,
		const char *long_name = nullptr) :
		PointerValue{Type::PARAM_IN, short_name, long_name}
	{}

protected: // functions

	void updateData(const Tracee &) override {}
};

} // end ns

CLUES_API std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallValue &value
);
