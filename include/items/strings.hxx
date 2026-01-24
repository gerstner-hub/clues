#pragma once

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// c-string style system call data.
class CLUES_API StringData :
		public SystemCallItem {
public: // functions
	explicit StringData(
		const std::string_view short_name = "string",
		const std::string_view long_name = {},
		const ItemType type = ItemType::PARAM_IN) :
			SystemCallItem{type, short_name, long_name} {
	}

	std::string str() const override;

	/// Returns the unmodified string data.
	const std::string& data() const {
		return m_str;
	}

protected: // functions

	void processValue(const Tracee &proc) override {
		if (!this->isOut()) {
			fetch(proc);
		}
	}

	void updateData(const Tracee &proc) override {
		fetch(proc);
	}


	void fetch(const Tracee &);

protected: // data

	std::string m_str;
};

/// A nullptr-terminated array of pointers to c-strings.
/**
 * This is currently only used for argv and envp of the execve system call.
 **/
class CLUES_API StringArrayData :
		public PointerInValue {
public: // functions

	explicit StringArrayData(
		const std::string_view short_name = "string-array",
		const std::string_view long_name = {}) :
			PointerInValue{short_name, long_name} {
	}

	std::string str() const override;

	/// Returns the unmodified string array data as a std::vector.
	const auto& data() const {
		return m_strs;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // functions

	std::vector<std::string> m_strs;
};

} // end ns
