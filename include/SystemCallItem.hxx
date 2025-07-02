#pragma once

// C++
#include <iosfwd>
#include <string_view>
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
		const ItemType type,
		const std::string_view short_name = {},
		const std::string_view long_name = {}) :
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
	std::string_view shortName() const { return m_short_name; }
	/// Returns the friendly long name for this item, if available, else the short name.
	std::string_view longName() const {
		return m_long_name.empty() ? shortName() : m_long_name; }

	auto hasLongName() const { return !m_long_name.empty(); }

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
	const ItemType m_type;
	/// A human readable short name for the item, should be one word only.
	const std::string_view m_short_name;
	/// A human readable longer name for the item.
	const std::string_view m_long_name;
	/// The raw register value for the item.
	Word m_val;
};

} // end ns

CLUES_API std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallItem &value
);
