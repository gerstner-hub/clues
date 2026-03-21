// C++
#include <algorithm>
#include <sstream>
#include <type_traits>

// cosmos
#include <cosmos/formatting.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/items.hxx>
#include <clues/logger.hxx>
#include <clues/Tracee.hxx>

using namespace std::string_literals;

namespace clues::item {

namespace {

template <typename INT>
std::string format_number(INT value, const Base base) {
	switch (base) {
		default: [[fallthrough]];
		case Base::DEC: return std::to_string(value);
		case Base::OCT: return static_cast<std::string>(cosmos::OctNum<INT>{value, 0});
		case Base::HEX: return static_cast<std::string>(cosmos::HexNum<INT>{value, 0});
	}
}

} // end ns

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	if (auto ptr = valueAs<long*>(); ptr) {
		ss << ptr;
	} else {
		ss << "NULL";
	}
	return ss.str();
}

template <typename INT>
std::string IntValueT<INT>::str() const {
	return format_number(m_value, m_base);
}

template <typename INT>
void PointerToScalar<INT>::fetchValue(const Tracee &tracee) {
	INT val;

	m_val.reset();

	if (m_ptr == ForeignPtr::NO_POINTER)
		return;

	try {
		if (tracee.readStruct(Word{static_cast<uintptr_t>(m_ptr)}, val)) {
			m_val = val;
		}
	} catch (const std::exception &) {
		// probably a bad address
	}
}

template <typename INT>
std::string PointerToScalar<INT>::str() const {
	if (m_ptr == ForeignPtr::NO_POINTER) {
		return "NULL";
	}

	return format::pointer((void*)m_ptr, m_val ? scalarToString() : "???"s);
}

template <typename INT>
std::string PointerToScalar<INT>::scalarToString() const {
	if constexpr (std::is_enum_v<INT>) {
		return format_number(cosmos::to_integral(*m_val), m_base);
	}
	if constexpr (!std::is_enum_v<INT>) {
		if constexpr (std::is_pointer_v<INT>) {
			return format_number(reinterpret_cast<uintptr_t>(*m_val), clues::Base::HEX);
		}
		if constexpr (!std::is_pointer_v<INT>) {
			return format_number(*m_val, m_base);
		}
	}
}

void BufferPointer::processValue(const Tracee &tracee) {
	if (isOut()) {
		// this is an out buffer only, will be filled in updateData()
		m_data.clear();
		return;
	}

	fillBuffer(tracee);
}

void BufferPointer::updateData(const Tracee &tracee) {
	if (isIn()) {
		// nothing to update on system call return
		return;
	}

	fillBuffer(tracee);
}

void BufferPointer::fillBuffer(const Tracee &tracee) {
	const auto to_fetch = std::min(tracee.maxBufferPrefetch(), actualBufferSize());
	m_data.resize(to_fetch);

	try {
		tracee.readBlob(valueAs<const long*>(), reinterpret_cast<char*>(m_data.data()), to_fetch);
	} catch (const cosmos::CosmosError &e) {
		LOG_ERROR("Failed to fetch buffer data from Tracee: " << e.what());
		m_data.clear();
	}
}

size_t BufferPointer::actualBufferSize() const {
	return m_size_par.valueAs<size_t>();
}

std::string BufferPointer::str() const {
	const auto is_cut_off = actualBufferSize() != m_data.size();
	auto ret = format::buffer(m_data.data(), m_data.size());

	if (is_cut_off) {
		ret += "...";
	}

	return ret;
}

SystemCallItem unused = SystemCallItem{ItemType::PARAM_IN, "unused", "unused parameter"};

/*
 * explicit template instantiations
 */

template class CLUES_API PointerToScalar<unsigned long>;
template class CLUES_API PointerToScalar<unsigned int>;
template class CLUES_API PointerToScalar<int>;
template class CLUES_API PointerToScalar<cosmos::ProcessID>;
template class CLUES_API PointerToScalar<cosmos::FileNum>;
template class CLUES_API PointerToScalar<void*>;
template class CLUES_API PointerToScalar<ForeignPtr>;
template class CLUES_API IntValueT<int>;
template class CLUES_API IntValueT<uint32_t>;
template class CLUES_API IntValueT<unsigned long>;

} // end ns
