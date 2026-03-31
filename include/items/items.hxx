#pragma once

// C++
#include <vector>

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

	ForeignPtr ptr() const {
		return ForeignPtr{valueAs<uintptr_t>()};
	}

protected: // functions

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

/// Pointer to a buffer of a certain size containing arbitrary data.
/**
 * This type is used for read/write buffers like found in read()/write()
 * system calls. They are accompanied by another system call parameter
 * denoting the number of bytes found in the buffer.
 **/
class CLUES_API BufferPointer :
		public PointerValue {
public: // functions

	explicit BufferPointer(
		const SystemCallItem &size_par,
		const ItemType type,
		const std::string_view short_name,
		const std::string_view long_name = {}) :
			PointerValue{type, short_name, long_name},
			m_size_par{size_par} {
	}

	const auto& data() const {
		return m_data;
	}

	/// Returns the actual number of input bytes available in the Tracee.
	/**
	 * Depending on configuration libclues only fetches part of the
	 * tracee's buffer data. This function returns the actual amount of
	 * data available in the tracee, in bytes.
	 *
	 * The amount of pre-fetched data can be controlled per tracee via
	 * Tracee::setMaxBufferPrefetch().
	 **/
	size_t availableBytes() const;

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override;
	void updateData(const Tracee &) override;

	void fillBuffer(const Tracee &);

protected: // data

	const SystemCallItem &m_size_par;
	std::vector<uint8_t> m_data;
};

/// A pointer to an integral data type which will be filled in by the kernel.
/**
 * The type can also be an enum type, but the size of the underlying type must
 * match the system call's pointed-to type.
 **/
template <typename INT>
class CLUES_API PointerToScalar :
		public PointerValue {
public: // functions

	explicit PointerToScalar(
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_OUT) :
			PointerValue{type, short_name, long_name} {
	}

	ForeignPtr pointer() const {
		return m_ptr;
	}

	std::optional<INT> value() const {
		return m_val;
	}

	std::string str() const override;

	void setBase(const Base base) {
		m_base = base;
	}

protected: // functions

	void processValue(const Tracee &tracee) override {
		m_ptr = valueAs<ForeignPtr>();

		if (isIn() || isInOut()) {
			fetchValue(tracee);
		}
	}

	void updateData(const Tracee &tracee) override {
		if (needsUpdate()) {
			fetchValue(tracee);
		}
	}

	void fetchValue(const Tracee &tracee);

	virtual std::string scalarToString() const;

protected: // data

	ForeignPtr m_ptr = ForeignPtr{};
	std::optional<INT> m_val;
	Base m_base = Base::DEC;
};

/// A simple scalar in/out/return value parameter.
template <typename INT>
class CLUES_API IntValueT :
		public ValueParameter {
public: // functions

	explicit IntValueT(
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_IN) :
			ValueParameter{type, short_name, long_name} {
	}

	INT value() const {
		return m_value;
	}

	std::string str() const override;

	void setBase(const Base base) {
		m_base = base;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_value = valueAs<INT>();
	}

protected: // data

	INT m_value = 0;
	Base m_base = Base::DEC;
};

using IntValue = IntValueT<int>;
using UintValue = IntValueT<unsigned int>;
using Uint32Value = IntValueT<uint32_t>;
using ULongValue = IntValueT<unsigned long>;
using SizeValue = IntValueT<size_t>;
using OffsetValue = IntValueT<off_t>;

///! Represents an unused system call parameter.
/**
 * In some system calls a certain system call parameter needs to be skipped
 * (e.g. in futex()). Since the SystemCall uses a `std::vector` to access
 * parameters linearly we need a way to identify unused parameters. This
 * global instance is used for this purpose.
 **/
CLUES_API extern SystemCallItem unused;

inline bool is_unused_par(const SystemCallItem &item) {
	return &item == &unused;
}

/// Item used together with UnknownSystemCall.
struct UnknownItem :
		public ValueInParameter {

	UnknownItem() :
		ValueInParameter{"unknown"} {
	}

	std::string str() const override {
		return "<yet unsupported system call>";
	}
};

} // end ns
