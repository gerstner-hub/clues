// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/fs/types.hxx>

// clues
#include <clues/items/FileDescriptor.hxx>

namespace clues::item {

std::string FileDescriptor::str() const {
	const auto fd = valueAs<cosmos::FileNum>();

	if (m_at_semantics && fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";
	else
		return std::to_string(cosmos::to_integral(fd));
}

std::string FileDescriptorReturnValue::str() const {
	const auto fd = cosmos::to_integral(valueAs<cosmos::FileNum>());

	if (fd >= 0)
		return std::to_string(fd);
	else
		return std::string{"Failed: "} + cosmos::ApiError::msg(cosmos::Errno{fd * -1});
}

} // end ns
