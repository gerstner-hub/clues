#pragma once

// cosmos
#include <cosmos/creds.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

class CLUES_API UserID :
		public SystemCallItem {
public: // functions

	explicit UserID(const ItemCfg &cfg = ItemCfg{}) :
			SystemCallItem{cfg.applyDefaults(ItemCfg{ItemType::RETVAL, "uid", "user id"})} {
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

	explicit GroupID(const ItemCfg &cfg = ItemCfg{}) :
		SystemCallItem{cfg.applyDefaults(ItemCfg{ItemType::RETVAL, "gid", "group id"})} {
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
