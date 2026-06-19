// C++
#include <format>

// clues
#include <clues/format.hxx>
#include <clues/items/seccomp.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string SecCompMode::str() const {
	switch (cosmos::to_integral(m_mode)) {
		CASE_ENUM_TO_STR(SECCOMP_MODE_STRICT);
		CASE_ENUM_TO_STR(SECCOMP_MODE_FILTER);
		default: return "SECCOMP_MODE_???";
	}
}

void SecCompMode::processValue(const Tracee&) {
	m_mode = valueAs<Mode>();
}

std::string FilterProg::str() const {
	if (!m_prog) {
		return formatBadPointer();
	}

	std::string filters;

	const auto filter_ptr = ForeignPtr{(uintptr_t)m_prog->filter};

	if (m_prog->len && m_filters.empty()) {
		/*
		 * we managed to read struct fprog, but reading struct filter
		 * failed.
		 */
		filters = format::pointer(filter_ptr, "<invalid>");
	} else {
		filters = "[";
		bool first = true;
		for (const auto &filt: m_filters) {
			if (first) {
				first = false;
			} else {
				filters += ", ";
			}

			filters += std::format
				("{{code={:#06x}, jt={}, jf={}, k={:#x}}}",
				filt.code,
				filt.jt,
				filt.jf,
				filt.k
			);
		}
		filters += "]";

		filters = format::pointer(filter_ptr, filters, format::Flag::ARRAY);
	}

	return std::format("{{len={}, filter={}}}", m_prog->len, filters);
}

void FilterProg::processValue(const Tracee &proc) {
	m_filters.clear();
	m_prog.emplace();
	if (!proc.readStruct(ptr(), *m_prog)) {
		m_prog.reset();
		return;
	}

	/*
	 * this could become quite large, should we limit the amount of data
	 * using the generic buffer size limit?
	 */
	m_filters.resize(m_prog->len);

	if (!proc.readStructs(
			ForeignPtr{(uintptr_t)m_prog->filter}, m_filters)) {
		m_filters.clear();
		return;
	}
}

} // end ns
