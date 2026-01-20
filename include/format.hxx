#pragma once

// C++
#include <cstdint>

// cosmos
#include <cosmos/io/types.hxx>
#include <cosmos/proc/SigInfo.hxx>
#include <cosmos/proc/types.hxx>
#include <cosmos/fwd.hxx>

// clues
#include <clues/dso_export.h>

struct timespec;

namespace cosmos {
	class SigInfo;
}

namespace clues::format {

/// Returns a string like "SIGINT (Interrupted)" for the given signal number.
/**
 * If `verbose` is set then a human-readable description of the signal is
 * added in parantheses, otherwise just the short signal name is returned.
 **/
CLUES_API std::string signal(const cosmos::SignalNr signal, const bool verbose=true);

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

/// Returns a string like "10 (SIGINT) {si_code=<code> si_timerid=<id> ...}"
CLUES_API std::string sig_info(const cosmos::SigInfo &info);

/// Returns a literal string like "S_IFSOCK" matching `type`.
CLUES_API std::string_view file_type(const cosmos::FileType type);

/// Returns an octal number string like "0644" corresponding to `mode`.
CLUES_API std::string file_mode_numeric(const cosmos::FileModeBits mode);

/// Returns a string like "rwxr-xr-x" corresponding to `mode`.
CLUES_API std::string file_mode_symbolic(const cosmos::FileModeBits mode);

/// returns a string like "0x10:0x05" corresponding to `id`.
CLUES_API std::string device_id(const cosmos::DeviceID id);

/// returns a string like {10s 500ns} corresponding to `ts`.
CLUES_API std::string timespec(const struct timespec &ts, const bool only_secs = false);

/// Returns a debug string showing basic info about the given ptrace event.
std::string event(const cosmos::ChildState &state);

} // end ns
