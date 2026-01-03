#pragma once

// cosmos
#include <cosmos/types.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

class CLUES_API UserID :
		public SystemCallItem {
public: // functions

	explicit UserID(const ItemType type = ItemType::RETVAL,
			const std::string_view short_name = "uid",
			const std::string_view long_name = "user id") :
			SystemCallItem{type, short_name, long_name} {
	}

	auto uid() const {
		return m_uid;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_uid = valueAs<cosmos::UserID>();
	}

protected: // data

	cosmos::UserID m_uid = cosmos::UserID::INVALID;
};

class CLUES_API GroupID :
		public SystemCallItem {
public: // functions

	explicit GroupID(const ItemType type = ItemType::RETVAL,
			const std::string_view short_name = "gid",
			const std::string_view long_name = "group id") :
			SystemCallItem{type, short_name, long_name} {
	}

	auto gid() const {
		return m_gid;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_gid = valueAs<cosmos::GroupID>();
	}

protected: // data

	cosmos::GroupID m_gid = cosmos::GroupID::INVALID;
};

} // end ns
