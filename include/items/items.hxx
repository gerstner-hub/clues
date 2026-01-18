#pragma once

// clues
#include <clues/SystemCallItem.hxx>

/*
 * Various specializations of SystemCallItem are found in this header
 */

namespace clues::item {

/// Base class for a system call return values.
class ReturnValue :
		public SystemCallItem {
public:
	explicit ReturnValue(const std::string_view short_name, const std::string_view long_name = {}) :
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
		const ItemType type,
		const std::string_view short_name,
		const std::string_view long_name = {}) :
			SystemCallItem{type, short_name, long_name} {
	}
};

/// Specialization of ValueParameter for PARAM_IN parameters.
class ValueInParameter :
		public ValueParameter {
public: // functions

	explicit ValueInParameter(
		const std::string_view short_name,
		const std::string_view long_name = {}) :
			ValueParameter{ItemType::PARAM_IN, short_name, long_name} {
	}
};

/// Specialization of ValueParameter for PARAM_OUT parameters.
class ValueOutParameter :
		public ValueParameter {
public: // functions

	explicit ValueOutParameter(
		const std::string_view short_name,
		const std::string_view long_name) :
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
		const ItemType type,
		const std::string_view short_name,
		const std::string_view long_name) :
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
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_OUT) :
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
		const std::string_view short_name,
		const std::string_view long_name = {}) :
			PointerValue{ItemType::PARAM_IN, short_name, long_name} {
	}
};

/*
 * TODO: support to get the length of the data area from a context-sensitive
 * sibling parameter and then print out the binary/ascii data as appropriate
 */
class CLUES_API GenericPointerValue :
		public PointerValue {
public: // functions

	explicit GenericPointerValue(
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

/// A simple scalar in/out/return value parameter.
template <typename INT, ItemType DEF_ITEM_TYPE = ItemType::PARAM_IN>
class CLUES_API IntValueT :
		public ValueParameter {
public: // functions

	explicit IntValueT(
		const std::string_view short_name,
		const std::string_view long_name = "",
		const ItemType type = DEF_ITEM_TYPE) :
			ValueParameter{type, short_name, long_name} {
	}

	INT value() const {
		return m_value;
	}

	std::string str() const override {
		return std::to_string(m_value);
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_value = valueAs<INT>();
	}

protected: // data

	INT m_value = 0;
};

using IntValue = IntValueT<int>;
using Uint32Value = IntValueT<uint32_t>;

} // end ns
