#pragma once

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// c-string style system call data.
class CLUES_API StringData :
		public PointerValue {
public: // functions
	explicit StringData(const ItemCfg &cfg = {}) :
			PointerValue{cfg.applyDefaults(ItemCfg{
				.type = ItemType::PARAM_IN,
				.label = "string",
				.desc = ""})} {
	}

	std::string str() const override;

	/// Returns the unmodified string data.
	const std::optional<std::string>& data() const {
		return m_str;
	}

protected: // functions

	void processValue(const Tracee &proc) override {
		if (!this->isOut()) {
			fetch(proc);
		} else {
			m_str.reset();
		}
	}

	void updateData(const Tracee &proc) override;

	void fetch(const Tracee &, const size_t max = SIZE_MAX);

protected: // data

	std::optional<std::string> m_str;
};

/// An out string parameter with size limitation, possibly without terminator.
/**
 * While many string parameters in the kernel API are null terminated by
 * contract (e.g. file system paths), some string out parameters are
 * accompanied by a buffer size parameter and the data might not be null
 * terminated, like is the case with the readlink family of system calls.
 *
 * This type introduces the coupling to the buffer size similar to what
 * the BufferPointer type does for arbitrary data.
 **/
class CLUES_API StringBuffer :
		public StringData {
public: // functions

	explicit StringBuffer(const SystemCallItem &size_par, const ItemCfg &cfg = {}) :
			StringData{cfg.applyDefaults(ItemCfg{ItemType::PARAM_OUT})},
			m_size_par(size_par) {
	}

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	const SystemCallItem &m_size_par;
};

/// A nullptr-terminated array of pointers to c-strings.
/**
 * This is currently only used for argv and envp of the execve system call.
 **/
class CLUES_API StringArrayData :
		public PointerInValue {
public: // functions

	explicit StringArrayData(const ItemCfg &cfg = {}) :
			PointerInValue{cfg.applyDefaults(ItemCfg{
				.label = "string-array",
				.desc = ""})} {
	}

	std::string str() const override;

	/// Returns the unmodified string array data as a std::vector.
	const auto& data() const {
		return m_strs;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	template <typename PTR>
	void fetchPointers(const Tracee &proc);

protected: // functions

	std::vector<std::string> m_strs;
};

} // end ns
