// C++
#include <cassert>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/logger.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallInfo.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/Tracee.hxx>
#include <clues/types.hxx>

namespace clues {

const char* SystemCall::name(const SystemCallNr nr) {
	return SYSTEM_CALL_NAMES[cosmos::to_integral(nr)].data();
}

bool SystemCall::validNr(const SystemCallNr nr) {
	return cosmos::to_integral(nr) < SYSTEM_CALL_NAMES.size();
}

void SystemCall::dropParameters(const size_t start_index) {
	m_pars.erase(m_pars.begin() + start_index, m_pars.end());
}

SystemCall::SystemCall(const SystemCallNr nr) :
		m_nr{nr}, m_name{SystemCall::name(nr)} {
}

void SystemCall::fillParameters(const Tracee &proc, const SystemCallInfo &info) {
	const auto args = info.entryInfo()->args();
	std::vector<std::pair<SystemCallItem*, Word>> deferred;

	for (size_t numpar = 0; numpar < m_pars.size(); numpar++) {
		auto &par = *m_pars[numpar];

		const auto word = Word{static_cast<Word>(args[numpar])};

		if (par.deferFill()) {
			deferred.push_back({&par, word});
			continue;
		}

		par.fill(proc, word);
	}

	for (const auto &[item, word]: deferred) {
		item->fill(proc, word);
	}
}

void SystemCall::setEntryInfo(const Tracee &proc, const SystemCallInfo &info) {
	m_abi = info.abi();
	m_error.reset();
	m_info = &info;

	prepareNewSystemCall();

	fillParameters(proc, info);

	if (check2ndPass(proc)) {
		fillParameters(proc, info);
	}

	m_info = nullptr;
}

bool SystemCall::hasOutParameter() const {
	for (auto &par: m_pars) {
		if (par->needsUpdate())
			return true;
	}

	return false;
}

void SystemCall::setExitInfo(const Tracee &proc, const SystemCallInfo &info) {
	m_info = &info;
	const auto exit_info = *info.exitInfo();

	if (exit_info.isValue()) {
		m_return->fill(proc, Word{static_cast<Word>(*exit_info.retVal())});
	} else {
		m_error = ErrnoResult{*exit_info.errVal()};
		m_return->reset();
	}

	for (auto &par: m_pars) {
		if (par->needsUpdate()) {
			par->updateData(proc);
		}
	}

	if (exit_info.isValue()) {
		updateFDTracking(proc);
	}

	postSystemCall(proc);

	m_info = nullptr;
}

void SystemCall::dropFD(const Tracee &proc, const cosmos::FileNum num) {
	proc.dropFD(num);
}

void SystemCall::trackFD(const Tracee &proc, FDInfo &&info) {
	proc.trackFD(std::move(info));
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
