// C++
#include <sstream>
#include <type_traits>

// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/Tracee.hxx>

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
void PointerToScalar<INT>::updateData(const Tracee &tracee) {
	INT val;

	m_val.reset();

	if (m_ptr == TraceePtr::NO_POINTER)
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
	if (m_ptr == TraceePtr::NO_POINTER) {
		return "NULL";
	}

	std::stringstream ss;

	ss << (void*)m_ptr << " → ";
	if (m_val) {
		if constexpr (std::is_enum_v<INT>) {
			ss << "[" << format_number(cosmos::to_integral(*m_val), m_base) << "]";
		}
		if constexpr (!std::is_enum_v<INT>) {
			if constexpr (std::is_pointer_v<INT>) {
				ss << "[" << *m_val << "]";
			}
			if constexpr (!std::is_pointer_v<INT>) {
				ss << "[" << format_number(*m_val, m_base) << "]";
			}
		}
	} else {
		ss << "???";
	}

	return ss.str();
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
template class CLUES_API IntValueT<int>;
template class CLUES_API IntValueT<uint32_t>;
template class CLUES_API IntValueT<unsigned long>;

} // end ns
