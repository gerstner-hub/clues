// C++
#include <format>

// cosmos
#include <cosmos/compiler.hxx>

// Linux
#ifdef COSMOS_X86
#	include <asm/prctl.h> // arch_prctl constants
#	include <sys/prctl.h>
#endif

// clues
#include <clues/format.hxx>
#include <clues/items/prctl.hxx>
#include <clues/macros.h>
#include <clues/private/utils.hxx>
#include <clues/syscalls/prctl.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

#ifdef CLUES_HAVE_ARCH_PRCTL
std::string ArchOpParameter::str() const {
	switch (valueAs<int>()) {
#ifdef COSMOS_X86
		CASE_ENUM_TO_STR(ARCH_SET_CPUID);
		CASE_ENUM_TO_STR(ARCH_GET_CPUID);
#ifdef COSMOS_X86_64
		CASE_ENUM_TO_STR(ARCH_SET_FS);
		CASE_ENUM_TO_STR(ARCH_GET_FS);
		CASE_ENUM_TO_STR(ARCH_SET_GS);
		CASE_ENUM_TO_STR(ARCH_GET_GS);
#endif // COSMOS_X86_64
#endif // COSMOS_X86
		default: return "unknown";
	}
}
#endif

std::string AmbientCapOp::str() const {
	switch (cosmos::to_integral(m_op)) {
		CASE_ENUM_TO_STR(PR_CAP_AMBIENT_RAISE);
		CASE_ENUM_TO_STR(PR_CAP_AMBIENT_LOWER);
		CASE_ENUM_TO_STR(PR_CAP_AMBIENT_IS_SET);
		CASE_ENUM_TO_STR(PR_CAP_AMBIENT_CLEAR_ALL);
		default: return "PR_CAP_AMBIENT_???";
	}
}

void AmbientCapOp::processValue(const Tracee&) {
	m_op = Operation{valueAs<long>()};
}

std::string MachineCheckOp::str() const {
	switch (cosmos::to_integral(m_op)) {
		CASE_ENUM_TO_STR(PR_MCE_KILL_CLEAR);
		CASE_ENUM_TO_STR(PR_MCE_KILL_SET);
		default: return "PR_MCE_KILL_???";
	}
}

void MachineCheckOp::processValue(const Tracee&) {
	m_op = Operation{valueAs<long>()};
}

std::string MachineCheckPolicy::str() const {
	switch (cosmos::to_integral(m_policy)) {
		CASE_ENUM_TO_STR(PR_MCE_KILL_EARLY);
		CASE_ENUM_TO_STR(PR_MCE_KILL_LATE);
		default: return "PR_MCE_KILL_???";
	}
}

void MachineCheckPolicy::processValue(const Tracee&) {
	m_policy = Policy{valueAs<long>()};
}

std::string MemoryMapOp::str() const {
	switch (cosmos::to_integral(m_op)) {
		CASE_ENUM_TO_STR(PR_SET_MM_START_CODE);
		CASE_ENUM_TO_STR(PR_SET_MM_END_CODE);
		CASE_ENUM_TO_STR(PR_SET_MM_START_DATA);
		CASE_ENUM_TO_STR(PR_SET_MM_END_DATA);
		CASE_ENUM_TO_STR(PR_SET_MM_START_STACK);
		CASE_ENUM_TO_STR(PR_SET_MM_START_BRK);
		CASE_ENUM_TO_STR(PR_SET_MM_BRK);
		CASE_ENUM_TO_STR(PR_SET_MM_ARG_START);
		CASE_ENUM_TO_STR(PR_SET_MM_ARG_END);
		CASE_ENUM_TO_STR(PR_SET_MM_ENV_START);
		CASE_ENUM_TO_STR(PR_SET_MM_ENV_END);
		CASE_ENUM_TO_STR(PR_SET_MM_AUXV);
		CASE_ENUM_TO_STR(PR_SET_MM_EXE_FILE);
		CASE_ENUM_TO_STR(PR_SET_MM_MAP);
		CASE_ENUM_TO_STR(PR_SET_MM_MAP_SIZE);
		default: return "PR_SET_MM_???";
	}
}

void MemoryMapOp::processValue(const Tracee&) {
	m_op = Operation{valueAs<long>()};
}

void MemoryMapStruct::processValue(const Tracee &proc) {
	/*
	 * zero-initialize the struct and only read at max the size of the
	 * struct or the size specified by the tracee into it. unused fields
	 * will be zero this ways in case the tracee uses an older version of
	 * the struct.
	 */
	m_map.emplace(prctl_mm_map{});

	const auto &prctl_call = dynamic_cast<const prctl::MemoryMapSystemCall&>(*m_call);

	if (!proc.readStruct(asPtr(),
				*m_map, prctl_call.mm_struct_size->value())) {
		m_map.reset();
	}
}

std::string MemoryMapStruct::str() const {

	if (asPtr() == ForeignPtr::NO_POINTER)
		return "NULL";
	else if (!m_map) {
		return format::pointer(asPtr(), "<invalid>");
	}

	const auto &map = *m_map;

	return std::format("{{start_code={}, end_code={}, start_data={}, "
			"end_data={}, start_brk={}, brk={}, start_stack={}, "
			"arg_start={}, arg_end={}, env_start={}, "
			"env_end={}, auxv={}, auxv_size={}, exe_fd={}}}",
		(void*)map.start_code,
		(void*)map.end_code,
		(void*)map.start_data,
		(void*)map.end_data,
		(void*)map.start_brk,
		(void*)map.brk,
		(void*)map.start_stack,
		(void*)map.arg_start,
		(void*)map.arg_end,
		(void*)map.env_start,
		(void*)map.env_end,
		(void*)map.auxv,
		map.auxv_size,
		map.exe_fd
	);
}

std::string ProcessOp::str() const {
	return std::string{label(m_op)};
}

std::string_view ProcessOp::label(const Operation op) const {
	switch (cosmos::to_integral(op)) {
		CASE_ENUM_TO_STR(PR_CAP_AMBIENT);
		CASE_ENUM_TO_STR(PR_CAPBSET_READ);
		CASE_ENUM_TO_STR(PR_CAPBSET_DROP);
		CASE_ENUM_TO_STR(PR_SET_CHILD_SUBREAPER);
		CASE_ENUM_TO_STR(PR_GET_CHILD_SUBREAPER);
		CASE_ENUM_TO_STR(PR_SET_DUMPABLE);
		CASE_ENUM_TO_STR(PR_GET_DUMPABLE);
		CASE_ENUM_TO_STR(PR_SET_ENDIAN);
		CASE_ENUM_TO_STR(PR_GET_ENDIAN);
		CASE_ENUM_TO_STR(PR_SET_FP_MODE);
		CASE_ENUM_TO_STR(PR_GET_FP_MODE);
		CASE_ENUM_TO_STR(PR_SET_FPEMU);
		CASE_ENUM_TO_STR(PR_GET_FPEMU);
		CASE_ENUM_TO_STR(PR_SET_FPEXC);
		CASE_ENUM_TO_STR(PR_GET_FPEXC);
		CASE_ENUM_TO_STR(PR_SET_IO_FLUSHER);
		CASE_ENUM_TO_STR(PR_GET_IO_FLUSHER);
		CASE_ENUM_TO_STR(PR_SET_KEEPCAPS);
		CASE_ENUM_TO_STR(PR_GET_KEEPCAPS);
		CASE_ENUM_TO_STR(PR_MCE_KILL);
		CASE_ENUM_TO_STR(PR_MCE_KILL_GET);
		CASE_ENUM_TO_STR(PR_SET_MM);
		CASE_ENUM_TO_STR(PR_SET_VMA);
		CASE_ENUM_TO_STR(PR_MPX_ENABLE_MANAGEMENT);
		CASE_ENUM_TO_STR(PR_MPX_DISABLE_MANAGEMENT);
		CASE_ENUM_TO_STR(PR_SET_NAME);
		CASE_ENUM_TO_STR(PR_GET_NAME);
		CASE_ENUM_TO_STR(PR_SET_NO_NEW_PRIVS);
		CASE_ENUM_TO_STR(PR_GET_NO_NEW_PRIVS);
		CASE_ENUM_TO_STR(PR_PAC_RESET_KEYS);
		CASE_ENUM_TO_STR(PR_SET_PDEATHSIG);
		CASE_ENUM_TO_STR(PR_GET_PDEATHSIG);
		CASE_ENUM_TO_STR(PR_SET_PTRACER);
		CASE_ENUM_TO_STR(PR_SET_SECCOMP);
		CASE_ENUM_TO_STR(PR_GET_SECCOMP);
		CASE_ENUM_TO_STR(PR_SET_SECUREBITS);
		CASE_ENUM_TO_STR(PR_GET_SECUREBITS);
		CASE_ENUM_TO_STR(PR_GET_SPECULATION_CTRL);
		CASE_ENUM_TO_STR(PR_SET_SPECULATION_CTRL);
		CASE_ENUM_TO_STR(PR_SVE_SET_VL);
		CASE_ENUM_TO_STR(PR_SVE_GET_VL);
		CASE_ENUM_TO_STR(PR_SET_SYSCALL_USER_DISPATCH);
		CASE_ENUM_TO_STR(PR_SET_TAGGED_ADDR_CTRL);
		CASE_ENUM_TO_STR(PR_GET_TAGGED_ADDR_CTRL);
		CASE_ENUM_TO_STR(PR_TASK_PERF_EVENTS_DISABLE);
		CASE_ENUM_TO_STR(PR_TASK_PERF_EVENTS_ENABLE);
		CASE_ENUM_TO_STR(PR_SET_THP_DISABLE);
		CASE_ENUM_TO_STR(PR_GET_THP_DISABLE);
		CASE_ENUM_TO_STR(PR_GET_TID_ADDRESS);
		CASE_ENUM_TO_STR(PR_SET_TIMERSLACK);
		CASE_ENUM_TO_STR(PR_GET_TIMERSLACK);
		CASE_ENUM_TO_STR(PR_SET_TIMING);
		CASE_ENUM_TO_STR(PR_GET_TIMING);
		CASE_ENUM_TO_STR(PR_SET_TSC);
		CASE_ENUM_TO_STR(PR_GET_TSC);
		CASE_ENUM_TO_STR(PR_SET_UNALIGN);
		CASE_ENUM_TO_STR(PR_GET_UNALIGN);
		CASE_ENUM_TO_STR(PR_GET_AUXV);
		CASE_ENUM_TO_STR(PR_SET_MDWE);
		CASE_ENUM_TO_STR(PR_GET_MDWE);
#ifdef PR_RISCV_SET_ICACHE_FLUSH_CTX
		CASE_ENUM_TO_STR(PR_RISCV_SET_ICACHE_FLUSH_CTX);
#endif
#ifdef PR_FUTEX_HASH
		CASE_ENUM_TO_STR(PR_FUTEX_HASH);
#endif
		default: return "PR_???";
	}
}

void ProcessOp::processValue(const Tracee &) {
	m_op = Operation{valueAs<int>()};
}

std::string VirtualMemoryAttr::str() const {
	switch (cosmos::to_integral(m_attr)) {
		CASE_ENUM_TO_STR(PR_SET_VMA_ANON_NAME);
		default: return "PR_SET_VMA_???";
	}
}

void VirtualMemoryAttr::processValue(const Tracee&) {
	m_attr = Attr{valueAs<long>()};
}

std::string SpeculationCtrlMisfeature::str() const {
	switch (cosmos::to_integral(m_misfeature)) {
		CASE_ENUM_TO_STR(PR_SPEC_STORE_BYPASS);
		CASE_ENUM_TO_STR(PR_SPEC_INDIRECT_BRANCH);
		default: return "PR_SPEC_???";
	}
}

void SpeculationCtrlMisfeature::processValue(const Tracee&) {
	m_misfeature = Misfeature{valueAs<long>()};
}

std::string SpeculationCtrlSetting::str() const {
	BITFLAGS_FORMAT_START(m_settings);

	BITFLAGS_ADD(PR_SPEC_PRCTL);
	BITFLAGS_ADD(PR_SPEC_ENABLE);
	BITFLAGS_ADD(PR_SPEC_DISABLE);
	BITFLAGS_ADD(PR_SPEC_FORCE_DISABLE);
	BITFLAGS_ADD(PR_SPEC_DISABLE_NOEXEC);

	return BITFLAGS_STR();
}

void SpeculationCtrlSetting::processValue(const Tracee&) {
	m_settings = Settings{valueAs<long>()};
}

std::string SyscallUserDispatchMode::str() const {
	switch (cosmos::to_integral(m_mode)) {
		CASE_ENUM_TO_STR(PR_SYS_DISPATCH_ON);
		CASE_ENUM_TO_STR(PR_SYS_DISPATCH_OFF);
		default: return "PR_SYS_???";
	}
}

void SyscallUserDispatchMode::processValue(const Tracee&) {
	m_mode = Mode{valueAs<long>()};
}

std::string TaggedAddressControl::str() const {
	switch (cosmos::to_integral(m_mode)) {
		case 0: return "0";
		CASE_ENUM_TO_STR(PR_TAGGED_ADDR_ENABLE);
		default: return "PR_TAGGED_???";
	}
}

void TaggedAddressControl::processValue(const Tracee&) {
	m_mode = Mode{valueAs<long>()};
}

std::string THPDisableState::str() const {
	using enum Config;
	switch (m_config) {
		CASE_ENUM_TO_STR(UNSPECIFIED);
		CASE_ENUM_TO_STR(DISABLED);
		CASE_ENUM_TO_STR(DISABLED_EXCEPT_ADVISED);
		default: return "???";
	}
}

void THPDisableState::processValue(const Tracee&) {
	m_config = Config{valueAs<int>()};
}

std::string THPDisableFlags::str() const {
	BITFLAGS_FORMAT_START(m_flags);
#ifdef PR_THP_DISABLE_EXCEPT_ADVISED
	BITFLAGS_ADD(PR_THP_DISABLE_EXCEPT_ADVISED);
#endif
	return BITFLAGS_STR();
}

void THPDisableFlags::processValue(const Tracee&) {
	m_flags = Flags{valueAs<long>()};
}

std::string TimingMode::str() const {
	using enum Mode;
	switch (cosmos::to_integral(m_mode)) {
		CASE_ENUM_TO_STR(PR_TIMING_STATISTICAL);
		CASE_ENUM_TO_STR(PR_TIMING_TIMESTAMP);
		default: return "PR_TIMING_???";
	}
}

void TimingMode::processValue(const Tracee&) {
	m_mode = Mode{valueAs<int>()};
}

std::string TSCAccess::str() const {
	return to_str(m_access);
}

std::string TSCAccess::to_str(const Access acc) {
	using enum Access;
	switch (cosmos::to_integral(acc)) {
		CASE_ENUM_TO_STR(PR_TSC_ENABLE);
		CASE_ENUM_TO_STR(PR_TSC_SIGSEGV);
		default: return "PR_TSC_???";
	}
}

void TSCAccess::processValue(const Tracee&) {
	m_access = Access{valueAs<int>()};
}

std::string TSCAccessPtr::scalarToString() const {
	return TSCAccess::to_str(m_access);
}

void TSCAccessPtr::updateData(const Tracee &tracee) {
	m_access = Access{0};

	if (!m_call->hasResultValue())
		return;

	PointerToScalar<int>::updateData(tracee);
	if (m_val) {
		m_access = Access{*m_val};
	}
}

std::string MemDenyWriteExecProtectionMask::str() const {
	BITFLAGS_FORMAT_START(m_mask);
	BITFLAGS_ADD(PR_MDWE_REFUSE_EXEC_GAIN);
	BITFLAGS_ADD(PR_MDWE_NO_INHERIT);
	return BITFLAGS_STR();
}

void MemDenyWriteExecProtectionMask::processValue(const Tracee&) {
	m_mask = Mask{valueAs<int>()};
}

void AuxVectorBuffer::processValue(const Tracee &proc) {
	BufferPointer::processValue(proc);
	m_auxv.reset();
}

void AuxVectorBuffer::updateData(const Tracee &proc) {
	BufferPointer::updateData(proc);
	if (!m_data.empty()) {
		/* remove possible excess bytes which are unusable due to truncation */
		const auto cut_off_bytes = m_data.size() % (sizeof(unsigned long) * 2);
		m_auxv.emplace(cosmos::AuxVector{m_data.data(), m_data.size() - cut_off_bytes});
	}
}

void AuxVectorBuffer::fetchRemainingData(const Tracee &proc) {
	BufferPointer::fetchRemainingData(proc);
	// now we can look at the complete vector
	m_auxv.emplace(cosmos::AuxVector{m_data.data(), m_data.size()});
}

} // end ns
