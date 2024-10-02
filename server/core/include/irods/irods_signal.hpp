#ifndef IRODS_SIGNAL_HPP
#define IRODS_SIGNAL_HPP

#include <string>
#include <string_view>

namespace irods
{
    /// A special tag that instructs the stacktrace file processor to not
    /// touch the file.
    ///
    /// \since 4.3.0
    extern const char* const STACKTRACE_NOT_READY_FOR_LOGGING_SUFFIX;

    /// TODO
    ///
    /// The logging system MUST be initialized before calling this function.
    ///
    /// \since 5.0.0
    auto set_stacktrace_directory(std::string_view _path) -> void;

    /// TODO
    ///
    /// \since 5.0.0
    auto get_stacktrace_directory_path() -> std::string_view;

    /// Sets signal handlers for the following signals:
    /// - SIGSEGV
    /// - SIGABRT
    /// - SIGILL
    /// - SIGFPE
    /// - SIGBUG
    ///
    /// The logging system MUST be initialized before calling this function.
    ///
    /// \since 4.3.0
    auto setup_unrecoverable_signal_handlers() -> void;
} // namespace irods

#endif // IRODS_SIGNAL_HPP
