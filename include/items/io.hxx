#pragma once

// Linux
#include <fcntl.h>

// C++
#include <optional>
#include <vector>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/io/EventFile.hxx>
#include <cosmos/io/StreamIO.hxx>

// clues
#include <clues/items/fcntl.hxx>
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/types.hxx>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

/// Pointer to pipefd[2] array in pipe() system calls.
class PipeEnds :
		public PointerOutValue {
public: // functions

	explicit PipeEnds() :
			PointerOutValue{"pipefd", "pointer to array pipefd[2]"} {
	}

	std::string str() const override;

	cosmos::FileNum readEnd() const {
		return m_read_end;
	}

	cosmos::FileNum writeEnd() const {
		return m_write_end;
	}

	/// Returns whether valid read and write end file numbers are stored.
	/**
	 * On failed system calls or sudden Tracee death these can have
	 * invalid values.
	 **/
	bool haveEnds() const {
		return m_read_end != cosmos::FileNum::INVALID && m_write_end != cosmos::FileNum::INVALID;
	}

protected: // functions

	void reset() {
		m_read_end = cosmos::FileNum::INVALID;
		m_write_end = cosmos::FileNum::INVALID;
	}

	void processValue(const Tracee &) override {
		reset();
	}

	void updateData(const Tracee &proc) override;

protected: // data

	cosmos::FileNum m_read_end = cosmos::FileNum::INVALID;
	cosmos::FileNum m_write_end = cosmos::FileNum::INVALID;
};

/// Flags used in Pipe2SystemCall.
class PipeFlags :
		public ValueInParameter {
public: // types

	enum class Flag : int {
		CLOEXEC           = O_CLOEXEC,
		DIRECT            = O_DIRECT,
		NONBLOCK          = O_NONBLOCK,
		NOTIFICATION_PIPE = O_EXCL /* this constant seems only defined in kernel headers and is just a reused O_EXCL */
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit PipeFlags() :
			ValueInParameter{"flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Flags m_flags;
};

/// A pointer to an array of struct iovec.
/**
 * This handles `struct iovec*` parameters in the readv/writev family of
 * system calls. These point to an array of struct iovec, the element count of
 * which is determined by a sibling system call parameter.
 *
 * This type will fetch each individual struct iovec but not the data the
 * respective buffers point to. That is the job of a specialization of this
 * type which takes care of the differences between input and output I/O
 * vectors.
 **/
class IOVectorBase :
		public PointerValue {
public: // types

	/// Information about a single `struct iovec`.
	struct Buffer {
		/// The pointer to the input/output buffer in the tracee.
		ForeignPtr base = ForeignPtr::NO_POINTER;
		/// The maximum amount of data to read/store at `base`.
		size_t len = 0;
		/// The actual amount of payload data found at `base`.
		/**
		 * In case of an output vector, if the kernel could not fill
		 * all of the vector, this will be less than `len`.
		 **/
		size_t filled = 0;
		/// Payload data at `base` as found in Tracee memory.
		/**
		 * This will be less than `len` in the following cases:
		 *
		 * - maxBufferPrefetch() as configured at the Tracee object is
		 *   less than `len`.
		 * - in case of a read operation:
		 *   	- the kernel returned less data than `len`.
		 * 	- the system call failed.
		 **/
		std::vector<std::byte> data;
	};

public: // functions

	explicit IOVectorBase(
			const SystemCallItem &vector_count,
			const ItemType type) :
			PointerValue{type, "iov", "struct iov*"},
			m_vector_count_par{vector_count} {
		/*
		 * `vector_count` comes after the `struct iovec*` in readv()
		 * and writev(), thus we need to defer the initial
		 * processValue().
		 */
		m_flags.set(Flag::DEFER_FILL);
	}

	/// Provides access to the individual buffers specified in the vector.
	const auto& buffers() const {
		return m_buffers;
	}

	/// Returns the number of buffers contained in iovec array.
	auto count() const {
		return m_buffers.size();
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override = 0;

	/// Fetches the buffer payload for the given buffer spec.
	void fetchBuffer(const Tracee &tracee, Buffer &buffer,
			const size_t left_to_fetch);

protected: // data

	const SystemCallItem &m_vector_count_par;
	std::vector<Buffer> m_buffers;
};

/// A pointer to an array of struct iovec for reading.
/**
 * This is a specialization of IOVectorBase for use with readv()-style system
 * calls. Since short reads can occur this type takes into account how much
 * data has actually been transferred by the kernel and will only fetch the
 * according payload after system call exit into the Buffer::data member of
 * the individual vector buffers.
 **/
class ReadVector :
		public IOVectorBase {
public: // functions

	explicit ReadVector(
			const SystemCallItem &vector_count,
			const SystemCallItem &obtained_bytes) :
			IOVectorBase{vector_count, ItemType::PARAM_IN_OUT},
			m_obtained_bytes_par{obtained_bytes} {
	}

protected: // functions

	void processValue(const Tracee &tracee) override {
		IOVectorBase::processValue(tracee);

	}

	void updateData(const Tracee &) override;

protected: // data

	const SystemCallItem &m_obtained_bytes_par;
};

/// A pointer to an array of struct iovec for writing.
/**
 * This is a specialization of IOVectorBase for use with writev()-style system
 * calls. Since the buffers specified in the vector are supposed to contain
 * valid payload data, this type will fetch contents into Buffer::data already
 * during system call entry.
 **/
class WriteVector :
		public IOVectorBase {
public: // functions

	explicit WriteVector(const SystemCallItem &vector_count) :
			IOVectorBase{vector_count, ItemType::PARAM_IN} {
	}

protected: // functions

	void processValue(const Tracee &tracee) override;
};

/// An I/O offset value spread over two system call registers.
/**
 * Some system calls spread a 64-bit file offset across two registers for
 * legacy reasons. This is currently the case for:
 *
 * - preadv(), preadv2()
 * - pwritev(), pwritev2()
 * - llseek()
 * - fadvise(), fadvise64_64() (on 32-bit ABIs)
 *
 * In these cases the lower 32 bits for the offset are often found in the
 * first system call parameter and the upper 32 bits are found in the
 * following system call parameter (sometimes the other way around).
 *
 * This item types combines both parameters into a single 64-bit offset again.
 * For this purpose the first system call register containing the low order
 * bits is kept as a member of type `UnusedItem`, i.e. this item is actually
 * comprised of itself and a child item.
 *
 * By default this type expects that the low order bits are appearing first
 * in the order of system call arguments. This way processing of the arguments
 * can take place the usual way. If this does not fit the system call
 * signature then `Ordering::LOW_THEN_HIGH` needs to be passed during
 * construction time, in which case the DEFER_FILL flag will be set for this
 * item, to make the low order bits available the time processValue() is
 * called.
 **/
class CombinedOffsetValue :
		public SystemCallItem {
public: // types

	enum class Ordering {
		/// low-order 32-bits come first in the system call arg list.
		LOW_THEN_HIGH,
		/// high-order 32-bit come first in the system call arg list.
		HIGH_THEN_LOW
	};

	using enum Ordering;

public: // data

	explicit CombinedOffsetValue(const Ordering order = LOW_THEN_HIGH, const std::string_view long_desc = "") :
			SystemCallItem{ItemType::PARAM_IN,
				"offset",
				long_desc.empty() ? "read/write offset" : long_desc},
			m_order{order},
			m_lower_bits{} {
		if (order == HIGH_THEN_LOW) {
			m_flags.set(Flag::DEFER_FILL);
		}
	}

	off_t value() const {
		return m_offset;
	}

	std::string str() const override;

	SystemCallItem& lowerPar() {
		return m_lower_bits;
	}

	const SystemCallItem& lowerPar() const {
		return m_lower_bits;
	}

	Ordering order() const {
		return m_order;
	}

protected: // functions

	void processValue(const Tracee &tracee) override;

protected: // data

	const Ordering m_order;
	UnusedItem m_lower_bits;
	off_t m_offset = 0;
};

/// Bitmask flags used in preadv2() and pwritev2().
class ReadWriteFlags :
		public ValueInParameter {
public: // types

	using enum cosmos::StreamIO::ReadWriteFlag;

	using Flags = cosmos::StreamIO::ReadWriteFlags;

public: // functions

	explicit ReadWriteFlags() :
			ValueInParameter{"flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Flags m_flags;
};

/// Seek direction for use with lseek() type system calls.
class Whence :
		public ValueInParameter {
public: // types

	using enum cosmos::StreamIO::SeekType;

	using SeekType = cosmos::StreamIO::SeekType;

public: // functions

	explicit Whence() :
			ValueInParameter{"whence", "seek direction"} {
	}

	SeekType type() const {
		return m_type;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	SeekType m_type = SeekType{0};
};

class EventFDFlags :
		public ValueInParameter {
public: // types

	using enum cosmos::EventFile::Flag;
	using Flags = cosmos::EventFile::Flags;

public: // functions

	explicit EventFDFlags() :
			ValueInParameter{"flags", "creation flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Flags m_flags{0};
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
