// Clues
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>
#include <clues/errnodb.h> // generated

// C++
#include <cstring>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || num >= ERRNO_NAMES_MAX)
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

namespace tracee {

namespace {

/// A filler that fills Tracee data into a container supporting push_back() until a terminating zero element is found.
/**
 * This only works for primitive data types that are small than `long` (the
 * basic I/O size for reading data from a Tracee).
 **/
template <typename CONTAINER>
class ContainerFiller {
	using ptr_type = typename CONTAINER::pointer;
public: // functions

	explicit ContainerFiller(CONTAINER &container) :
			m_container{container} {
	}

	bool operator()(long word) {
		static_assert(std::is_pod_v<typename CONTAINER::value_type> == true);
		static_assert(sizeof(ITEM_SIZE) <= sizeof(long), "Unexpected ITEM_SIZE (must be <= sizeof(long))");
		ptr_type word_ptr = reinterpret_cast<ptr_type>(&word);
		typename CONTAINER::value_type item;

		for (size_t numitem = 0; numitem < sizeof(word) / ITEM_SIZE; numitem++) {
			std::memcpy(&item, word_ptr + numitem, sizeof(item));
			if (item == 0)
				// termination found
				return false;

			m_container.push_back(item);
		}

		return true;
	}

protected:
	CONTAINER &m_container;
	static constexpr size_t ITEM_SIZE = sizeof(typename CONTAINER::value_type);
};

/// Fills an opaque blog of data with Tracee data a given number of bytes has bee processed.
class BlobFiller {
public: // functions

	BlobFiller(const size_t bytes, char *buffer) :
			m_left{bytes},
			m_buffer{buffer} {
	}

	bool operator()(long word) {
		const size_t to_copy = std::min(sizeof(word), m_left);

		std::memcpy(m_buffer, &word, to_copy);

		m_buffer += to_copy;
		m_left -= to_copy;

		return m_left != 0;
	}

protected: // data

	size_t m_left;
	char *m_buffer;
};

/// Reads data from the Tracee and feeds it to \c filler until it's saturated.
template <typename FILLER>
void fill_data(const Tracee &proc, const long *addr, FILLER &filler) {
	long word;

	do {
		word = proc.getData(addr);

		// get the next word
		addr++;
	} while (filler(word));
}

} // end anon ns

void read_string(const Tracee &proc, const long *addr, std::string &out) {
	return read_vector(proc, addr, out);
}

template <typename VECTOR>
void read_vector(const Tracee &proc, const long *addr, VECTOR &out) {
	out.clear();

	ContainerFiller<VECTOR> filler(out);
	fill_data(proc, addr, filler);
}

void read_blob(const Tracee &proc, const long *addr, char *buffer, const size_t bytes) {
	BlobFiller filler{bytes, buffer};
	fill_data(proc, addr, filler);
}

// explicit template instantiations
template void read_vector<std::vector<long*>>(const Tracee&, const long*, std::vector<long*>&);

} // end ns
} // end ns
