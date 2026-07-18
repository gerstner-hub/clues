#pragma once

// Linux
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/select.h>

// C++
#include <array>
#include <optional>
#include <vector>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/io/EventFile.hxx>
#include <cosmos/io/Poller.hxx>
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
			PointerOutValue{make_item_cfg("pipefd", "pointer to array pipefd[2]")} {
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
			ValueInParameter{ItemCfg{.label = "flags"}} {
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
			PointerValue{ItemCfg{type, "iov", "struct iov*"}},
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

	explicit CombinedOffsetValue(const Ordering order = LOW_THEN_HIGH, const ItemCfg &cfg = {}) :
			SystemCallItem{cfg.applyDefaults(ItemCfg{
				.type = ItemType::PARAM_IN,
				.label = "offset",
				.desc = "read/write offset"})},
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
			ValueInParameter{ItemCfg{.label = "flags"}} {
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
			ValueInParameter{make_item_cfg("whence", "seek direction")} {
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
			ValueInParameter{make_item_cfg("flags", "creation flags")} {
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

/// Flags used with epoll_create1().
class EPollCreateFlags :
		public ValueInParameter {
public: // types

	enum class Flag : int {
		CLOEXEC = EPOLL_CLOEXEC
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit EPollCreateFlags() :
			ValueInParameter{make_item_cfg("flags", "creation flags")} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // data

	void processValue(const Tracee &proc) override;

protected: // data

	Flags m_flags{};
};

/// File descriptor sets as used with SelectSystemCall.
/**
 * This data structure is an array allowing to store up to 1024 bits (for a
 * maximum of 1024 file descriptors). This array is supposed to be comprised
 * of `long` words for efficiency reasons. This means the size of the array
 * differs between 32-bit and 64-bit targets.
 *
 * For the purposes of tracing we can always rely on our native word size even
 * for cross-ABI tracing.
 *
 * This type of parameter is always used as an in/out value, so we need to
 * update during system call entry and during system call exit alike. To allow
 * inspection of the requested and matching file descriptor events this type
 * provides the `requestSet()` and the `eventSet()` accessors. The latter is
 * only available after system call exit.
 *
 * The pointer for an fdset is also allowed to be NULL.
 **/
class FDSet :
		public PointerValue {
public: // types

	/// Type to represent the fd_set used in the kernel.
	/**
	 * There is no abstraction for this in libcosmos, since it only wraps
	 * the modern epoll API. Thus we need a small wrapper here ourselves.
	 **/
	struct Array {

		/// Checks whether the given file descriptor is present in the set.
		bool isSet(const cosmos::FileNum fd) const;

		/// Provides access to the POSIX-type corresponding to the set.
		const fd_set* raw() const;

		/// returns a string representation of the file descriptors in the set.
		std::string str(const int max_fd) const;

	protected: // functions

		friend class FDSet;

		fd_set* raw() {
			return const_cast<fd_set*>(const_cast<const Array&>(*this).raw());
		}

	protected: // data

		static constexpr size_t MAX_FD = 1024;
		static constexpr size_t NUM_ULONGS = MAX_FD / (8 * sizeof(long));

		std::array<long, NUM_ULONGS> m_array;
	};

public: // functions

	/// Create a FDSet coupled to the given `nfds` parameter.
	/**
	 * `nfds` is required for the item to know what the largest file
	 * descriptor in the set can be.
	 **/
	explicit FDSet(const SystemCallItem &nfds,
			const ItemCfg &cfg = {}) :
			PointerValue{cfg.applyDefaults(ItemCfg{
					.type = ItemType::PARAM_IN_OUT})},
			m_nfds{nfds} {
	}

	const std::optional<Array>& requestSet() const {
		return m_req_set;
	}

	const std::optional<Array>& eventSet() const {
		return m_ev_set;
	}

	std::string str() const override;

	int maxFD() const {
		return m_nfds.valueAs<int>();
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

protected: // data

	/// The requested set of file descriptors as observed on system call entry.
	std::optional<Array> m_req_set;
	/// The set of file descriptors with events as observed on system call exit.
	std::optional<Array> m_ev_set;
	const SystemCallItem &m_nfds;
};

/// Combined select() arguments for the old variant of select() on 32-bit ABIs like I386.
class CLUES_API OldSelectArgs :
		public PointerValue {
public:

	explicit OldSelectArgs() :
			PointerValue{ItemCfg{
				ItemType::PARAM_IN_OUT,
				"args",
				"struct sel_args_struct*"}} {
	}

	bool valid() const {
		return m_valid;
	}

	int numFDs() const {
		return nfds;
	}

	ForeignPtr readSetPtr() const {
		return readfds;
	}

	ForeignPtr writeSetPtr() const {
		return writefds;
	}

	ForeignPtr exceptSetPtr() const {
		return exceptfds;
	}

	ForeignPtr timeoutPtr() const {
		return timeout;
	}

protected: // functions

	void processValue(const Tracee&) override;

	/*
	 * update is handled via SelectSystemCall::postSystemCall()
	 */
	//void updateData(const Tracee&) override;

	std::string str() const override;

protected: // data

	bool m_valid = false;
	int nfds = 0;
	ForeignPtr readfds; // fd_set*
	ForeignPtr writefds; // fd_set*
	ForeignPtr exceptfds; // fd_set*
	ForeignPtr timeout; // struct timeval32*
};

/// The `op` parameter in `epoll_ctl()`.
class CLUES_API EPollOperation :
		public ValueInParameter {
public: // flags

	enum class Operation : int {
		ADD = EPOLL_CTL_ADD,
		MOD = EPOLL_CTL_MOD,
		DEL = EPOLL_CTL_DEL
	};

	using enum Operation;

public: // functions

	explicit EPollOperation() :
			ValueInParameter{ItemCfg{.label = "op", .desc = "operation"}} {
	}

	Operation operation() const {
		return m_op;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Operation m_op{};
};

/// `struct epoll_event` used with the epoll API.
class CLUES_API EPollEvent :
		public PointerValue {
public: // types

	/*
	 * libcosmos models these as well, but in a split fashion separating
	 * monitoring flags and event reporting flags. for tracing purposes it
	 * is better to use a simple common type.
	 */
	enum class Event : uint32_t {
		SOCKET_HANGUP  = EPOLLRDHUP,
		ERROR          = EPOLLERR,
		HANGUP         = EPOLLHUP,
		INPUT          = EPOLLIN,
		OUTPUT         = EPOLLOUT,
		EXCEPTIONS     = EPOLLPRI,
		EDGE_TRIGGERED = EPOLLET,
		ONESHOT        = EPOLLONESHOT,
		STAY_AWAKE     = EPOLLWAKEUP
	};

	using enum Event;

	using Events = cosmos::BitMask<Event>;

public: // functions

	/**
	 * You need to pass the ItemType in `cfg`.
	 **/
	explicit EPollEvent(const ItemCfg &cfg = {}) :
			PointerValue{cfg.applyDefaults(ItemCfg{
				.label = "event",
				.desc = "struct epoll_event"})} {
	}

	std::string str() const override;

	const std::optional<struct epoll_event>& event() const {
		return m_ev;
	}

	std::optional<Events> flags() const {
		if (!m_ev)
			return {};

		return Events{m_ev->events};
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	std::optional<struct epoll_event> m_ev;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
