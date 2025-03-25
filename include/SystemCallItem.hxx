#pragma once

// C++
#include <iosfwd>
#include <type_traits>

// cosmos
#include <cosmos/utils.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

class SystemCall;
class Tracee;

/// Basic type of a SystemCallItem.
enum class ItemType {
	PARAM_IN,     ///< An input parameter to the system call.
	PARAM_OUT,    ///< An output parameter filled by in by the system call.
	PARAM_IN_OUT, ///< Both an input and output parameter.
	RETVAL        ///< A system call return value.
};

/// Base class for any kind of system call parameter or return value.
/**
 * Concrete types need to derive from this and override virtual methods as
 * needed.
 **/
class CLUES_API SystemCallItem {
	friend SystemCall;
public: // functions

	/// Constructs a new SystemCallItem.
	/**
	 * \param[in] type
	 * 	The type of item.
	 * \param[in] short_name
	 * 	A short friendly name for this item (one word)
	 * \param[in] long_name
	 *	A longer name for this item, optional
	 **/
	explicit SystemCallItem(
		const ItemType &type,
		const char *short_name,
		const char *long_name = nullptr) :
			m_type{type},
			m_short_name{short_name},
			m_long_name{long_name}
	{}

	virtual ~SystemCallItem() {}

	auto type() const { return m_type; }

	bool isIn() const          { return m_type == ItemType::PARAM_IN; }
	bool isOut() const         { return m_type == ItemType::PARAM_OUT; }
	bool isInOut() const       { return m_type == ItemType::PARAM_IN_OUT; }
	bool isReturnValue() const { return m_type == ItemType::RETVAL; }

	/// Fills the item from the given register data.
	void fill(const Tracee &proc, const Word word);

	/// Returns whether the item needs to be updated after the system call is finished.
	bool needsUpdate() const { return m_type != ItemType::PARAM_IN; }

	/// Returns the friendly short name for this item.
	const char* shortName() const { return m_short_name; }
	/// Returns the friendly long name for this item, if available, else the short name.
	const char* longName() const { return m_long_name ? m_long_name : shortName(); }

	auto hasLongName() const { return m_long_name != nullptr; }

	/// Returns a human readable string representation of the item.
	/**
	 * This member function should be specialized in derived classes to
	 * output the item's data in a fashion suitable for the concrete item
	 * type.
	 **/
	virtual std::string str() const;

	/// Returns the currently stored raw value of the item.
	Word value() const { return m_val; }

	/// Helper to cast the strongly typed `Word` `m_val` to other strong enum types.
	/**
	 * This also silences data loss warnings. On x86_64 Word is 64-bit
	 * wide, but many parameters are actually only 32-bit wide, so this
	 * warning comes up a lot. There shouldn't be many dangerous
	 * situations in this context as long as we select the correct target
	 * type.
	 **/
	template <typename OTHER>
	OTHER valueAs() const {
		const auto baseval = cosmos::to_integral(m_val);
		if constexpr (std::is_enum_v<OTHER>) {
			const auto baseret = static_cast<typename std::underlying_type<OTHER>::type>(baseval);
			return OTHER{baseret};
		}

		if constexpr (std::is_pointer_v<OTHER>) {
			return reinterpret_cast<OTHER>(baseval);
		}

		if constexpr (!std::is_enum_v<OTHER> && !std::is_pointer_v<OTHER>) {
			return static_cast<OTHER>(baseval);
		}
	}

protected: // functions

	/// Processes the value stored in m_val acc. to the actual item type.
	virtual void processValue(const Tracee &) {}

	/// Called upon exit of the system call to update possible out parameters.
	virtual void updateData(const Tracee &) {}

	/// Sets the system call context this item is a part of.
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

protected: // data

	/// The system call context this item part of.
	const SystemCall *m_call = nullptr;
	/// The type of item.
	ItemType m_type;
	/// A human readable short name for the item, should be one word only.
	const char *m_short_name = nullptr;
	/// A human readable longer name for the item.
	const char *m_long_name = nullptr;
	/// The raw register value for the item.
	Word m_val;
};

/// Base class for a system call return values.
class ReturnValue :
		public SystemCallItem {
public:
	explicit ReturnValue(const char *short_name, const char *long_name = nullptr) :
		SystemCallItem{ItemType::RETVAL, short_name, long_name}
	{}
};

/// Base class for a pass-by-value parameter of a system call.
/**
 * These are typically PARAM_IN types denoting IDs, enums, flags etc. that are
 * passed to a system call.
 *
 * The processValue() and updateValue() functions are implemented as no-ops,
 * because no additional data needs to be fetched from the tracee for this
 * kind of parameter.
 **/
class ValueParameter :
		public SystemCallItem {
public: // functions

	explicit ValueParameter(
		const ItemType &type,
		const char *short_name,
		const char *long_name = nullptr) :
			SystemCallItem{type, short_name, long_name} {
	}
};

/// Specialization of ValueParameter for PARAM_IN parameters.
class ValueInParameter :
		public ValueParameter {
public: // functions

	explicit ValueInParameter(
		const char *short_name,
		const char *long_name = nullptr) :
			ValueParameter{ItemType::PARAM_IN, short_name, long_name} {
	}
};

/// Specialization of ValueParameter for PARAM_OUT parameters.
class ValueOutParameter :
		public ValueParameter {
public: // functions

	explicit ValueOutParameter(
		const char *short_name,
		const char *long_name) :
			ValueParameter{ItemType::PARAM_OUT, short_name, long_name} {
	}
};

/// A value that consists of a pointer to some data area.
/**
 * Unlike ValueParameter, PointerValue is a pointer to some userspace
 * data structure. Thus the processValue() and updateData() functions need to
 * perform more complex operations on the tracee to gather the data as
 * appropriate.
 **/
class PointerValue :
		public SystemCallItem {
public: // functions

	explicit PointerValue(
		const ItemType &type,
		const char *short_name,
		const char *long_name) :
			SystemCallItem{type, short_name, long_name} {
	}
};

/// Specialization of a PointerValue for out-parameters.
/**
 * This specialization has a no-op implementation of the processValue() member
 * function that serves no purpose for out parameters. Also the value type is
 * predetermined to PARAM_OUT.
 **/
class PointerOutValue :
		public PointerValue {
public: // functions

	explicit PointerOutValue(
		const char *short_name,
		const char *long_name = nullptr,
		const ItemType &type = ItemType::PARAM_OUT) :
			PointerValue{type, short_name, long_name} {
	}
};

/// Specialization of a PointerValue for in-parameters.
/**
 * This specialization has a no-op implementation of the updateData() member
 * function that serves no purpose for in parameters. Also the value type is
 * predetermined to PARAM_IN..
 **/
class PointerInValue :
		public PointerValue {
public: // functions

	explicit PointerInValue(
		const char *short_name,
		const char *long_name = nullptr) :
			PointerValue{ItemType::PARAM_IN, short_name, long_name} {
	}
};

} // end ns

CLUES_API std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallItem &value
);
