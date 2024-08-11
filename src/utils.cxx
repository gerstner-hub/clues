// Clues
#include <clues/utils.hxx>
#include <clues/Tracee.hxx>
// generated
#include <clues/errnodb.h>

// C++
#include <string>
#include <cstring>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || num >= ERRNO_NAMES_MAX)
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

void readTraceeString(
		const Tracee &proc,
		const long *addr,
		std::string &out) {
	return readTraceeVector(proc, addr, out);
}

/// reads data from the tracee and feeds it to \c eater until it's saturated.
template <typename EATER>
void readTraceeData(
		const Tracee &proc,
		const long *addr,
		EATER &eater) {
	long word;

	do {
		word = proc.getData(addr);

		// get the next word
		addr++;
	} while (eater(word));
}


/// An EATER that fills eaten data into a vector-like container until a terminating zero element is found.
template <typename VECTOR>
class VectorEater {
	typedef typename VECTOR::value_type *ptr_type;
public:

	VectorEater(VECTOR &vector) :
			m_vector{vector} {
	}

	bool operator()(long word) {
		static_assert(sizeof(VALUE_SIZE) <= sizeof(long), "Unexpected VALUE_SIZE");
		ptr_type unit = reinterpret_cast<ptr_type>(&word);

		for (size_t cur = 0; cur < sizeof(word) / VALUE_SIZE; cur++) {
			const auto &piece = unit[cur];
			if (piece == 0)
				// termination found
				return false;

			m_vector.push_back(piece);
		}

		return true;
	}

protected:
	VECTOR &m_vector;
	static constexpr size_t VALUE_SIZE = sizeof(typename VECTOR::value_type);
};

template <typename VECTOR>
void readTraceeVector(
		const Tracee &proc,
		const long *addr,
		VECTOR &out) {
	out.clear();

	VectorEater<VECTOR> eater(out);
	readTraceeData(proc, addr, eater);
}

class BlobEater {
public: // functions

	BlobEater(const size_t bytes, char *buffer) :
		m_left{bytes},
		m_buffer{buffer} {
	}

	bool operator()(long word) {
		const size_t to_copy = std::min( sizeof(word), m_left );

		std::memcpy(m_buffer, &word, to_copy);

		m_buffer += to_copy;
		m_left -= to_copy;

		return m_left != 0;
	}

protected: // data

	size_t m_left;
	char *m_buffer;
};

void readTraceeBlob(
		const Tracee &proc,
		const long *addr,
		char *buffer,
		const size_t bytes) {
	BlobEater eater{bytes, buffer};
	readTraceeData(proc, addr, eater);
}

template void readTraceeVector<std::vector<long*>>(const Tracee&, const long*, std::vector<long*>&);

} // end ns
