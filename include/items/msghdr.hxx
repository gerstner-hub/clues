#pragma once

// cosmos
#include <cosmos/net/message_header.hxx>

// clues
#include <clues/items/io.hxx>
#include <clues/items/items.hxx>
#include <clues/items/net.hxx>

namespace clues::item {

/**
 * @file
 * This header contains types related to the recvmsg() and sendmsg() system
 * calls and related ones. The message header structure(s) involve high
 * complexity, which is why we are placing these types into a dedicated
 * header.
 **/

CLUES_DEFAULT_VISIBILITY_ON;

/// Base class for SendMessageHeader and ReceiveMessageHeader.
/**
 * This type keeps common logic which is shared between the two system calls,
 * most notably dealing with control data and ABI conversion.
 **/
class MessageHeaderBase :
		public PointerValue {
protected: // functions

	explicit MessageHeaderBase(const ItemCfg &cfg) :
			PointerValue{cfg.applyDefaults(ItemCfg{.label = "msg"})},
			m_msg_control{m_msg_controllen, ItemCfg{
				cfg.type == ItemType::PARAM_IN ? ItemType::PARAM_IN : ItemType::PARAM_OUT,
				"msg_control"}, /*is_binary=*/true},
			m_msg_controllen{ItemCfg{
				cfg.type == ItemType::PARAM_IN ? ItemType::PARAM_IN : ItemType::PARAM_IN_OUT,
				"msg_controllen"}} {
	}

	bool fetchMsgHdr32(const Tracee &proc, std::optional<struct msghdr> &out);

	std::vector<std::byte> convertControlHeader32() const;

	/// Returns a description of contained control messages.
	std::string controlStr(const std::optional<cosmos::ReceiveMessageHeader> &hdr) const;

protected: // data

	BufferPointer m_msg_control;
	IntValue m_msg_controllen;
};

class RecvMessageHeader :
		public MessageHeaderBase {
public: // functions

	explicit RecvMessageHeader(const SystemCallItem &obtained_bytes) :
			MessageHeaderBase{ItemCfg{ItemType::PARAM_IN_OUT}},
			m_msg_name{ItemCfg{ItemType::PARAM_OUT}, &m_msg_namelen},
			m_msg_iov{m_msg_iovlen, obtained_bytes},
			m_msg_iovlen{ItemCfg{.label = "num_iovs"}} {
	}

	std::string str() const override;

	/// Provides access to message control data and flags.
	/**
	 * This is only valid after system call exit, else std::nullopt
	 * will be returned. The returned object will contain a copy of the
	 * control data as well as a copy of the receive flags observed in the
	 * tracee. You can use the ControlMessage iterators to inspect
	 * individual messages.
	 *
	 * \warning when 32-bit cross ABI tracing is in effect then accessing
	 * control data is a very messy endeavour. This is because the binary
	 * data in the control data can also be subject to ABI differences.
	 * This function will return a control data structure converted from
	 * 32-bit to 64-bit representation such that the 64-bit tracer can
	 * safely iterate over individual control messages.
	 *
	 * Regarding control message payload libclues currently only considers
	 * UNIX domain socket ancillary messages for this scenario.
	 **/
	std::optional<cosmos::ReceiveMessageHeader> header() const;

	/// Provides access to the raw payload data which was received.
	/*
	 * This is only valid after system call exit. The buffer contents will
	 * be truncated if buffer fetch limits are in effect.
	 */
	const ReadVector::BufferVector& ioVector() const {
		return m_msg_iov.buffers();
	}

	/// Provides access to the raw control data which was received.
	/**
	 * This is only valid after system call exit. This type will always
	 * fetch the complete control data regardless of buffer fetch limits
	 * in effect.
	 **/
	const std::vector<std::byte>& controlData() const {
		return m_msg_control.data();
	}

protected: // functions

	void processData(const Tracee &) override;

	void updateData(const Tracee &) override;

	void resetSubItems(const Tracee &proc);

	void fillSubItems(const Tracee &);

	void updateSubItems(const Tracee &);

protected: // data

	/* let's reuse items as sub-items for this complex structure */
	SocketAddress m_msg_name;
	AddressLength m_msg_namelen;
	ReadVector m_msg_iov;
	SizeValue m_msg_iovlen;
	SendRecvFlags m_msg_flags;

	///! Header as observed during system call entry.
	std::optional<struct msghdr> m_in_header;
	///! Header as observed during system call exit.
	std::optional<struct msghdr> m_out_header;
};

/// Extended variant of `struct msghdr` used with RecvMessageHeaderVector for `recvmmsg()`.
/**
 * This structure basically carries an additional `unsigned int` to
 * communicate back the individual amount of received bytes.
 **/
class RecvMultiMessageHeader :
		public RecvMessageHeader {

	// allow to set protected members
	friend class RecvMessageHeaderVector;
	// allow to fill sub-items
	template <typename HDR_ITEM>
	friend class MessageHeaderVectorBase;

public: // functions

	/// Create a new header based on `hdr` for the input header part.
	/**
	 * The given `hdr` will be assigned to the input header part of
	 * RecvMessageHeader.
	 **/
	explicit RecvMultiMessageHeader(const SystemCall *call,
			const struct msghdr &hdr);

	/// Number of bytes received.
	/**
	 * Upon system call exit of recvmmsg() this contains the number of
	 * bytes received into the msghdr. In other states or when a tracing
	 * error occurred, std::nullopt is returned.
	 **/
	std::optional<unsigned long> bytesReceived() const {
		if (!m_have_bytes_received)
			return {};

		return m_bytes_received.value();
	}

protected: // functions

	using RecvMessageHeader::fillSubItems;
	using RecvMessageHeader::updateSubItems;

	void setBytesReceived(const unsigned int received, const Tracee &proc) {
		m_bytes_received.fill(proc, Word{received});
		m_have_bytes_received = true;
	}

	/// Apply the output header information as found in `hdr`.
	/**
	 * This will also trigger a call to updateSubItems() to reflect the
	 * changes.
	 **/
	void setOutHeader(const struct msghdr &hdr, const Tracee &);

protected: // data

	// contrary to SendMultiMessageHeader we need a fully-fledged
	// SystemCallItem here, because the RecvMessageHeader base class
	// expects a reference to one to determine the amount of received
	// bytes.

	bool m_have_bytes_received = false;
	UintValue m_bytes_received;
};

class SendMessageHeader :
		public MessageHeaderBase {
public: // functions

	explicit SendMessageHeader() :
			MessageHeaderBase{ItemCfg{ItemType::PARAM_IN}},
			m_msg_name{ItemCfg{ItemType::PARAM_IN}, &m_msg_namelen},
			m_msg_iov{m_msg_iovlen},
			m_msg_iovlen{ItemCfg{.label = "num_iovs"}} {
	}

	std::string str() const override;

	/// Provides access to message control data and flags.
	/**
	 * The returned object will contain a copy of the control data as well
	 * as a copy of the receive flags observed in the tracee. You can use
	 * the ControlMessage iterators to inspect individual messages. This
	 * uses cosmos::ReceiveMessageHeader instead of
	 * cosmos::SendMessageHeader, because the latter is intended for
	 * constructing a new outgoing message, while we are dealing with an
	 * already assembled messages used by the tracee.
	 *
	 * \warning See RecvMessageHeader::header() for limitations of
	 * cross-ABI tracing.
	 **/
	std::optional<cosmos::ReceiveMessageHeader> header() const;

	/// Provides access to the raw payload data which is to be sent out.
	/*
	 * The buffer contents will be truncated if buffer fetch limits are in
	 * effect.
	 */
	const WriteVector::BufferVector& ioVector() const {
		return m_msg_iov.buffers();
	}

	/// Provides access to the raw control data which is to be sent out.
	/**
	 * This type will always fetch the complete control data regardless of
	 * buffer fetch limits in effect.
	 **/
	const std::vector<std::byte>& controlData() const {
		return m_msg_control.data();
	}

protected: // functions

	void processData(const Tracee &) override;

	void resetSubItems(const Tracee &proc);

	void fillSubItems(const Tracee &);

protected: // data

	/* let's reuse items as sub-items for this complex structure */
	SocketAddress m_msg_name;
	AddressLength m_msg_namelen;
	WriteVector m_msg_iov;
	SizeValue m_msg_iovlen;
	SendRecvFlags m_msg_flags;

	std::optional<struct msghdr> m_header;
};

/// Extended variant of `struct msghdr` used with SendMessageHeaderVector for `sendmmsg()`.
/**
 * This structure basically carries an additional `unsigned int` to
 * communicate back the individual amount of sent bytes.
 **/
class SendMultiMessageHeader :
		public SendMessageHeader {

	// allow to set bytes set
	friend class SendMessageHeaderVector;

	// allow to fill sub-items
	template <typename HDR_ITEM>
	friend class MessageHeaderVectorBase;

public: // functions

	/// Assign the given `hdr` to the SendMessageHeader part of the object.
	explicit SendMultiMessageHeader(const SystemCall *call,
			const struct msghdr &hdr);

	/// Number of bytes sent out.
	/**
	 * Upon system call exit of sendmmsg() this contains the number of
	 * bytes actually sent out. In other states or when tracing errors
	 * occurred then std::nullopt is returned.
	 **/
	std::optional<unsigned long> bytesSent() const {
		return m_bytes_sent;
	}

protected: // functions

	using SendMessageHeader::fillSubItems;

	void setBytesSent(const unsigned int sent) {
		m_bytes_sent = sent;
	}

protected: // data

	std::optional<unsigned int> m_bytes_sent;
};

/// Base class for vectors of `struct mmsghdr` in `recvmmsg()` and `sendmmsg()`.
/**
 * The `struct mmsghdr` is the same for both `recvmmsg()` and `sendmmsg()`,
 * but we need somewhat different logic due to the different update logic in
 * the calls. This base class covers the shared logic, while the
 * specializations take care of the send/recv-specific logic.
 *
 * `HDR_ITEM` is either RecvMultiMessageHeader or SendMultiMessageHeader.
 *
 * This type holds two vectors: one for the raw `struct mmsghdr` and one
 * containing the corresponding `HDR_ITEM` instances. This is because we want
 * to reuse the logic from RecvMessageHeader and SendMessageHeaderVector for
 * the nearly identical `struct mmsghdr`. This is not ideal for performance,
 * but these system calls are rather rare and a lot of redundant code for this
 * would be bad.
 **/
template <typename HDR_ITEM>
class MessageHeaderVectorBase :
		public PointerValue {
public: // functions

	/// Create a new MessageHeaderVector based on `num_msgs`.
	/**
	 * `num_msgs` must refer to the accompanying system call argument
	 * which defines the number of `struct mmsghdr` found in the array
	 * this parameter points to.
	 **/
	explicit MessageHeaderVectorBase(const SystemCallItem &num_msgs) :
			PointerValue{ItemCfg{ItemType::PARAM_IN_OUT,
				"msgvec", "struct mmsghdr[]"}},
			m_num_msgs{num_msgs} {
		/* the `num_msgs` argument generally comes after the `msgvec` */
		m_flags.set(Flag::DEFER_FILL);
	}

	std::string str() const override;

protected: // functions

	/// Fetch the raw `struct mmsghdr` from the tracee and store them in `m_raw_headers`.
	/**
	 * This can only be called when a valid value is stored in
	 * `m_num_msgs`.
	 *
	 * The return value indicates whether reading the data from the Tracee
	 * succeeded, otherwise `m_raw_headers` will be empty.
	 **/
	bool fetchRawHeaders(const Tracee &);

	void processData(const Tracee &) override;

	/// Returns a string description of the `msg_len` parameter.
	/**
	 * This needs to be implemented by the specialization of this type,
	 * because RecvMultiMessageHeader and SendMultiMessageHeader use
	 * different types for storing this information.
	 **/
	virtual std::string getMsgLenStr(const HDR_ITEM &item) const = 0;

protected: // data

	const SystemCallItem &m_num_msgs;
	std::vector<struct mmsghdr> m_raw_headers;
	std::vector<HDR_ITEM> m_headers;
};

class RecvMessageHeaderVector :
		public MessageHeaderVectorBase<RecvMultiMessageHeader> {
public: // functions

	explicit RecvMessageHeaderVector(const SystemCallItem &num_msgs) :
			MessageHeaderVectorBase{num_msgs} {
	}

	const std::vector<RecvMultiMessageHeader>& headers() const {
		return m_headers;
	}

protected: // functions

	void updateData(const Tracee &) override;

	std::string getMsgLenStr(const RecvMultiMessageHeader &item) const override;
};

class SendMessageHeaderVector :
		public MessageHeaderVectorBase<SendMultiMessageHeader> {
public: // functions

	explicit SendMessageHeaderVector(const SystemCallItem &num_msgs) :
			MessageHeaderVectorBase{num_msgs} {
	}

	const std::vector<SendMultiMessageHeader>& headers() const {
		return m_headers;
	}

protected: // functions

	void updateData(const Tracee &) override;

	std::string getMsgLenStr(const SendMultiMessageHeader &item) const override;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
