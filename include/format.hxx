#pragma once

// C++
#include <cstdint>

// cosmos
#include <cosmos/io/types.hxx>
#include <cosmos/proc/SigInfo.hxx>
#include <cosmos/proc/types.hxx>

// clues
#include <clues/dso_export.h>

namespace clues::format {

/// Returns a string like "SIGINT (Interrupted)" for the given signal number.
CLUES_API std::string signal(const cosmos::SignalNr signal);

/// Returns a string like "{SIGINT (Interrupted), SIGQUIT (Quit), ...}".
CLUES_API std::string signal_set(const sigset_t &set);

/// Returns a string like "SA_NOCLDSTOP|SA_NOCLDWAIT|..."
CLUES_API std::string saflags(const int flags);

/// Returns a human readable limit string like "5 * 1024" or "RLIM64_INFINITY"
CLUES_API std::string limit(const uint64_t lim);

/// Returns a string label for the corresponding C constant like SI_USER
CLUES_API std::string si_code(const cosmos::SigInfo::Source src);

/// Returns a string label for the corresponding C constant like SYS_SECCOMP
CLUES_API std::string si_reason(const cosmos::SigInfo::SysData::Reason reason);

/// Returns a string label for the corresponding C constant like POLL_IN
CLUES_API std::string si_reason(const cosmos::SigInfo::PollData::Reason reason);

/// Returns a string label for the corresponding C constant like ILL_OPC
CLUES_API std::string si_reason(const cosmos::SigInfo::IllData::Reason reason);

/// Returns a string label for the corresponding C constant like FPE_INTDIV
CLUES_API std::string si_reason(const cosmos::SigInfo::FPEData::Reason reason);

/// Returns a string label for the corresponding C constant like SEGV_MAPPERR
CLUES_API std::string si_reason(const cosmos::SigInfo::SegfaultData::Reason reason);

/// Returns a string label for the corresponding C constant like BUS_ADRALN
CLUES_API std::string si_reason(const cosmos::SigInfo::BusData::Reason reason);

/// Returns a string label for the corresponding C constant like AUDIT_ARCH_X86_64
CLUES_API std::string ptrace_arch(const cosmos::ptrace::Arch arch);

/// Returns a string label for the corresponding C constant like CLD_EXITED
CLUES_API std::string child_event(const cosmos::SigInfo::ChildData::Event event);

/// Returns a string label for the corresponding C constant like POLLIN
CLUES_API std::string poll_event(const cosmos::PollEvent event);

/// Returns a string like POLLIN|POLLPRI|...
CLUES_API std::string poll_events(const cosmos::PollEvents events);

} // end ns
