#pragma once

// C++
#include <iosfwd>
#include <optional>
#include <string_view>
#include <type_traits>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/dso_export.h>
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

/// Basic configuration info of a SystemCallItem.
/**
 * This struct is used for partial overrides of per-class defaults for
 * parameter names and ItemType. It is supposed to be used with designated
 * initializers.
 **/
struct ItemCfg {
	std::optional<ItemType> type = {};
	std::optional<std::string_view> label = {};
	std::optional<std::string_view> desc = {};

	/// Return an object with new defaults applied to unassigned optionals.
	/**
	 * Any members set to std::nullopt will be overriden by the
	 * corresponding member in `cfg`, if provided. The resulting ItemCfg
	 * will be returned.
	 *
	 * This is useful for more deeply nested specializations of
	 * SystemCallItem where base classes expect an ItemCfg as well.
	 **/
	ItemCfg applyDefaults(const ItemCfg &cfg) const {
		return ItemCfg{
			cfg.type ? type.value_or(*cfg.type) : type,
			cfg.label ? label.value_or(*cfg.label) : label,
			cfg.desc ? desc.value_or(*cfg.desc) : desc};
	}
};

/// Construct an ItemCfg using label and desc.
inline ItemCfg make_item_cfg(const std::string_view label, const std::string_view desc) {
	return ItemCfg{.label = label, .desc = desc};
}

/// Base class for any kind of system call parameter or return value.
/**
 * Concrete types need to derive from this and override virtual methods as
 * needed.
 **/
class CLUES_API SystemCallItem {
	friend SystemCall;
public: // types


	enum class Flag {
		/// Only fill in this item after all other items have been filled.
		/**
		 * This helps to model context-dependent parameters that rely
		 * on the values of parameters appearing at a later position.
		 **/
		DEFER_FILL = 1 << 0,
		/// The item is unused.
		/**
		 * This is set for system call registers that remain unused
		 * due to unusual calling conventions or other special needs
		 * of a system call.
		 *
		 * The basic value of the register will still be fetched
		 * during system call entry but processValue() and
		 * updateData() will not be called.
		 **/
		UNUSED     = 1 << 1
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	/// Constructs a new SystemCallItem.
	/**
	 * \param[in] type
	 * 	The type of item.
	 * \param[in] label
	 * 	A short friendly name for this item (one word)
	 * \param[in] desc
	 *	A longer name for this item, optional
	 **/
	explicit SystemCallItem(const ItemCfg &cfg) :
			m_type{*cfg.type},
			m_label{*cfg.label},
			m_desc{cfg.desc.value_or("")} {
	}

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

	/// Returns the friendly label for this item.
	std::string_view label() const { return m_label; }
	/// Returns the friendly description for this item, if available, else the label.
	std::string_view description() const {
		return m_desc.empty() ? label() : m_desc; }

	auto hasDescription() const { return !m_desc.empty(); }

	/// Returns a human readable string representation of the item.
	/**
	 * This member function should be specialized in derived classes to
	 * output the item's data in a fashion suitable for the concrete item
	 * type.
	 **/
	virtual std::string str() const;

	/// Returns whether the parameter is set to 0 / NULL.
	bool isZero() const {
		return value() == Word::ZERO;
	}

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

	ForeignPtr asPtr() const {
		return valueAs<ForeignPtr>();
	}

	Flags flags() const {
		return m_flags;
	}

	bool deferFill() const {
		return m_flags[Flag::DEFER_FILL];
	}

	bool isUnused() const {
		return m_flags[Flag::UNUSED];
	}

protected: // functions

	void reset() {
		m_val = Word::ZERO;
	}

	/// Processes the value stored in m_val acc. to the actual item type.
	/**
	 * This function is called for all parameter types upon entry to a
	 * system call, and for ItemType::RETVAL upon exit from a system call.
	 *
	 * For parameters of ItemType::PARAM_OUT this callback can be used to
	 * reset any stored data to be filled in later when updateData() is
	 * called.
	 **/
	virtual void processValue(const Tracee &) {}

	/// Called upon exit of the system call to update possible out parameters.
	/**
	 * This function is called for parameters of ItemType::PARAM_OUT and
	 * ItemType::PARAM_IN_OUT upon system call exit to update the data
	 * from the values returned from the system call.
	 *
	 * The default implementation calls `processValue()` to allow to share
	 * the same data processing code for input and output for item types
	 * that support both.
	 *
	 * This function is called regardless of system call success or error,
	 * so it can happen that there is no valid data returned by the kernel
	 * or pointers in userspace are broken. Implementations should take
	 * this into consideration when operating on the data.
	 **/
	virtual void updateData(const Tracee &t) {
		processValue(t);
	}

	/// Sets the system call context this item is a part of.
	void setSystemCall(const SystemCall &sc) { m_call = &sc; }

	/// Returns whether the current system call context uses 32-bit time_t.
	bool usesTime32() const;

protected: // data

	/// The system call context this item part of.
	const SystemCall *m_call = nullptr;
	/// The type of item.
	const ItemType m_type;
	/// A human readable label for the item, should be one word only.
	std::string_view m_label;
	/// A human readable description the item.
	std::string_view m_desc;
	/// The raw register value for the item.
	Word m_val;
	/// Flags influencing the processing of the item.
	Flags m_flags;
};

} // end ns

CLUES_API std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallItem &value
);
