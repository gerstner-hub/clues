// C++
#include <cassert>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallValue.hxx>
#include <clues/types.hxx>

namespace clues {

SystemCall::SystemCall(
		const SystemCallNr nr,
		const char *name,
		ParameterVector &&pars,
		SystemCallValue *ret,
		const size_t open_id_par,
		const size_t close_fd_par) :
		m_nr{nr}, m_name{name}, m_return{ret}, m_pars{pars},
		m_open_id_par{open_id_par}, m_close_fd_par{close_fd_par} {

	assert(open_id_par == SIZE_MAX || open_id_par < m_pars.size());
	assert(close_fd_par == SIZE_MAX || close_fd_par < m_pars.size());

	for (auto &par: m_pars)
		par->setSystemCall(*this);
}

SystemCall::~SystemCall() {
	while (!m_pars.empty()) {
		delete m_pars.back();
		m_pars.pop_back();
	}

	delete m_return;
}

void SystemCall::setEntryInfo(const Tracee &proc, const cosmos::ptrace::SyscallInfo::EntryInfo &info) {
	auto args = info.args();
	for (size_t numpar = 0; numpar < m_pars.size(); numpar++) {
		auto &par = *m_pars[numpar];
		par.fill(proc, Word{args[numpar]});
	}

	m_error.reset();
}

void SystemCall::setExitInfo(const Tracee &proc, const cosmos::ptrace::SyscallInfo::ExitInfo &info) {
	if (info.isValue()) {
		m_return->fill(proc, Word{static_cast<uint64_t>(*info.retVal())});
	} else {
		m_error = ErrnoResult{};
		// TODO: makes no sense to cast the Errno back to a Word just
		// for ErrnoResult to reverse the effect. We need a dedicated
		// type for this situation.
		auto raw_errno = cosmos::to_integral(*info.errVal());
		m_error->fill(proc, Word{raw_errno >= 0 ? static_cast<elf_greg_t>(-raw_errno) : 0});
	}

	for (auto &par: m_pars) {
		if (par->needsUpdate()) {
			par->updateData(proc);
		}
	}
}

void SystemCall::updateOpenFiles(DescriptorPathMapping &mapping) {
	// TODO: this implementation is not finished / not sane yet.
	if (m_open_id_par != SIZE_MAX) {
		const int new_fd = (int)m_return->value();

		if (new_fd < 0)
			return;

		auto res = mapping.insert(
			std::make_pair(new_fd, m_pars[m_open_id_par]->str())
		);

		if (!res.second) {
			LOG_DEBUG("WARNING: file descriptor already open?!");
		}
	} else if(m_close_fd_par != SIZE_MAX) {
		if (m_return->valueAs<cosmos::Errno>() != cosmos::Errno::NO_ERROR)
			// unsuccessful system call, so don't update anything
			return;

		const int closed_fd = (int)m_pars[m_close_fd_par]->value();

		if (mapping.erase(closed_fd) == 0) {
#if 0
			// this is stdout, stderr & friends
			LOG_WARN("closed file that wasn't open?!");
#endif
		}
	} else {
		return;
	}

	//std::cout << "New path mapping:\n" << mapping << std::endl;
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc) {
	o << sc.name() << " (" << cosmos::to_integral(sc.callNr()) << "): " << sc.numPars() << " parameters";

	for (const auto &par: sc.m_pars) {
		o << "\n\t" << *par;
	}

	o << "\n\tResult -> " << *(sc.m_return);

	return o;
}
