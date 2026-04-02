#pragma once

// clues
#include <clues/arch.hxx>
#include <clues/items/items.hxx>

// Linux
#ifdef CLUES_HAVE_ARCH_PRCTL
#include <asm/prctl.h>
#endif


namespace clues::item {

#ifdef CLUES_HAVE_ARCH_PRCTL
/// The `op` parameter to the arch_prctl system call.
class CLUES_API ArchOpParameter :
		public ValueInParameter {
public: // types

	enum class Operation : int {
		SET_CPUID = ARCH_SET_CPUID,
		GET_CPUID = ARCH_GET_CPUID,
		SET_FS    = ARCH_SET_FS,
		GET_FS    = ARCH_GET_FS,
		SET_GS    = ARCH_SET_GS,
		GET_GS    = ARCH_GET_GS
	};

public: // functions

	explicit ArchOpParameter() :
			ValueInParameter{"op"} {
	}

	std::string str() const override;

	Operation operation() const {
		return m_op;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_op = Operation{valueAs<int>()};
	}

protected: // data

	Operation m_op = Operation{0};
};
#endif

} // end ns
