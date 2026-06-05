#pragma once

// C++
#include <vector>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/random.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

// Linux
#include <sys/rseq.h>

namespace clues::item {

/// The flags passed to calls like open().
class CLUES_API GetRandomFlagsValue :
		public SystemCallItem {
public:
	explicit GetRandomFlagsValue() :
			SystemCallItem{ItemType::PARAM_IN, "flags", "random flags"} {
	}

	std::string str() const override;

	cosmos::GetRandomFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::GetRandomFlags m_flags;
};

/// The main `struct rseq` parameter used with RSeqSystemCall.
/**
 * The `struct rseq` is a dynamically sized structure with a final parameter
 * of unknown dimension. For this reason heap-allocated data is used in this
 * type.
 **/
class CLUES_API RSeqParameter :
		public PointerValue {
public: // functions

	explicit RSeqParameter() :
			PointerValue{ItemType::PARAM_IN_OUT,
				"rseq", "struct rseq*"} {
	};

	std::string str() const override;

	const struct rseq* data() const {
		if (m_data.empty())
			return nullptr;

		return reinterpret_cast<const struct rseq*>(m_data.data());
	}

	/// The size of the data structure returned via data() in bytes.
	/**
	 * `struct rseq` is a dynamically sized struct of at least 32 bytes.
	 * This member function returns the exact size as used in the current
	 * system call context.
	 **/
	size_t rseqSize() const {
		return m_data.size();
	}

protected: // functions

	void processValue(const Tracee &) override {
		/* we only look at the struct during system call exit time,
		 * when we will also know the size of the struct and see any
		 * updates the kernel made */
		m_data.clear();
	}

	void updateData(const Tracee&) override;

protected: // data

	std::vector<char> m_data;
};

/// The `flags` argument used with RSeqSystemCall.
class CLUES_API RSeqFlagsValue :
		public ValueInParameter {
public: // types

	enum class Flag {
		REGISTER   = 0,
		UNREGISTER = RSEQ_FLAG_UNREGISTER,
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit RSeqFlagsValue() :
			ValueInParameter{"flags"} {

	}

	std::string str() const override;

	Flags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Flags m_flags;
};

} // end ns
