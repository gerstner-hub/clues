// libclues
#include <clues/ptrace.hxx>

// libcosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/iovector.hxx>

namespace {

	long raw_ptrace(
			const cosmos::TraceRequest request,
			cosmos::ProcessID pid,
			void *addr = nullptr, void *data = nullptr,
			const std::string_view error_label = {}) {
		auto res = ::ptrace(
				static_cast<__ptrace_request>(request),
				cosmos::to_integral(pid),
				addr,
				data);

		if (!error_label.empty() && res == -1) {
			cosmos_throw(cosmos::ApiError(error_label));
		}

		return res;
	}
}

namespace clues::ptrace {

void cont(cosmos::ProcessID proc,
		const cosmos::ContinueMode mode, const std::optional<cosmos::Signal> signal) {

	raw_ptrace(
			static_cast<cosmos::TraceRequest>(mode),
			proc,
			nullptr,
			(void*)(signal ? signal->raw() : cosmos::signal::NONE.raw()),
			"ptrace-continue");
}

unsigned long get_event_msg(const cosmos::ProcessID proc) {
	unsigned long ret = 0;

	raw_ptrace(
			cosmos::TraceRequest::GETEVENTMSG,
			proc,
			nullptr,
			&ret,
			"ptrace-event-msg");

	return ret;
}

void interrupt(const cosmos::ProcessID proc) {
	raw_ptrace(cosmos::TraceRequest::INTERRUPT, proc, nullptr, nullptr, "ptrace-interrupt");
}

void seize(const cosmos::ProcessID proc) {
	raw_ptrace(cosmos::TraceRequest::SEIZE, proc, nullptr, nullptr, "ptrace-seize");
}

void set_options(const cosmos::ProcessID proc, const cosmos::TraceFlags flags) {
	raw_ptrace(cosmos::TraceRequest::SETOPTIONS, proc, nullptr, reinterpret_cast<void*>(flags.raw()));
}

void get_register_set(const cosmos::ProcessID proc, const cosmos::RegisterType type, cosmos::InputMemoryRegion &iovec) {
	raw_ptrace(cosmos::TraceRequest::GETREGSET, proc, reinterpret_cast<void*>(cosmos::to_integral(type)), &iovec, "ptrace-get-register-set");
}

} // end ns
