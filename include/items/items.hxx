#pragma once

// C++
#include <vector>
#include <cstddef>

// clues
#include <clues/arch.hxx>
#include <clues/SystemCallItem.hxx>

/*
 * Various specializations of SystemCallItem are found in this header
 */

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

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

	ForeignPtr ptr() const {
		return ForeignPtr{valueAs<uintptr_t>()};
	}

protected:

	std::string formatBadPointer() const;
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

class GenericPointerValue :
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

/// Pointer to a buffer of a certain size containing arbitrary data.
/**
 * This type is used for read/write buffers like found in read()/write()
 * system calls. They are accompanied by another system call parameter
 * denoting the number of bytes found in the buffer.
 **/
class BufferPointer :
		public PointerValue {
public: // functions

	/// Create a new BufferPointer item.
	/**
	 * \param[in] is_binary If set then no attempt is made to interpret
	 * the data as text in formatting operations.
	 **/
	explicit BufferPointer(
		const SystemCallItem &size_par,
		const ItemType type,
		const std::string_view short_name,
		const std::string_view long_name = {},
		const bool is_binary = false) :
			PointerValue{type, short_name, long_name},
			m_size_par{size_par},
			m_is_binary{is_binary} {
		if (type == ItemType::PARAM_IN) {
			/*
			 * currently needed for write(), but other system
			 * calls might be affected, too.
			 */
			m_flags.set(Flag::DEFER_FILL);
		}
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

	/// Fetch any remaining data from the tracee.
	/**
	 * In case only part of the buffer was fetched from the Tracee, fetch
	 * all remaining data and fill the buffer returned from `data()` with
	 * it.
	 *
	 * This is only safe to do during the associated system call stop
	 * when the partial buffer was filled, otherwise there is no
	 * guarantee that the Tracee memory is still in the proper state to
	 * read from.
	 *
	 * In case fetching the missing data fails an exception is thrown. The
	 * original buffer data and size will remain intact in this case.
	 **/
	virtual void fetchRemainingData(const Tracee &proc);

protected: // functions

	void processValue(const Tracee &) override;
	void updateData(const Tracee &) override;

	void fillBuffer(const Tracee &);

protected: // data

	const SystemCallItem &m_size_par;
	const bool m_is_binary = false;
	std::vector<std::byte> m_data;
};

/// A pointer to an integral data type which will be filled in by the kernel.
/**
 * The type can also be an enum type, but the size of the underlying type must
 * match the system call's pointed-to type.
 **/
template <typename INT>
class PointerToScalar :
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
		} else {
			m_val.reset();
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
class IntValueT :
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

using IntValue    = IntValueT<int>;
using UintValue   = IntValueT<unsigned int>;
using Uint32Value = IntValueT<uint32_t>;
using ULongValue  = IntValueT<unsigned long>;
using LongValue   = IntValueT<long>;
using SizeValue   = IntValueT<size_t>;
using Int8Value   = IntValueT<int8_t>;
using OffsetValue = IntValueT<kernel_off_t>;

/// A 0/1 integer representing a boolean value.
class BoolValue :
		public ValueParameter {
public: // functions

	explicit BoolValue(
		const std::string_view short_name,
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_IN) :
			ValueParameter{type, short_name, long_name} {
	}

	bool value() const {
		return m_value;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override {
		m_value = valueAs<bool>();
	}

protected: // data

	bool m_value = false;
};

/// Item used together with UnknownSystemCall.
struct UnknownItem :
		public ValueInParameter {

	UnknownItem() :
			ValueInParameter{"unknown"} {
	}

	std::string str() const override {
		return "<unsupported or invalid system call>";
	}
};

/// Item used together with NotImplementedSystemCall.
struct UnsupportedItem :
		public ValueInParameter {

	UnsupportedItem() :
			ValueInParameter{"unknown"} {
	}

	std::string str() const override {
		return "<not yet supported system call>";
	}
};

/// Item used together with DroppedSystemCall.
struct DroppedItem :
		public ValueInParameter {

	DroppedItem() :
			ValueInParameter{"unknown"} {
	}

	std::string str() const override {
		return "<legacy system call no longer available in the kernel>";
	}
};

///! Represents an unused system call parameter.
/**
 * In some system calls a certain system call parameter needs to be skipped
 * (e.g. in futex()). Since the SystemCall uses a `std::vector` to access
 * parameters linearly we need a way to identify unused parameters. This
 * type is used for this purpose.
 *
 * The global instance clues::item::unused can be used to quickly skip over
 * unused system call registers. In other cases the value in the register is
 * actually used but by another type e.g. in the case of CombinedOffsetValue.
 * In such situations a dedicated instance of UnusedItem is needed. In such
 * situations a dedicated instance of UnusedItem is needed.
 */
struct UnusedItem :
		public ValueInParameter {

	UnusedItem() :
			ValueInParameter{"unused"} {
		m_flags.set(Flag::UNUSED);
	}

	std::string str() const override {
		return "<unused system call parameter>";
	}
};

extern UnusedItem unused;

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
