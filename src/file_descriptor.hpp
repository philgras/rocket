#ifndef ROCKET_FILE_DESCRIPTOR_HPP
#define ROCKET_FILE_DESCRIPTOR_HPP

#include "event.hpp"

#include <memory>
#include <chrono>
#include <system_error>

#include <unistd.h>


namespace rocket {


    class file_descriptor {

    public:

        static constexpr int INVALID_FD = -1;

        explicit file_descriptor(int fd = INVALID_FD)
                : m_fd(fd) {}

        file_descriptor(const file_descriptor &) = delete;

        file_descriptor(file_descriptor &&descriptor) noexcept
                : m_fd(descriptor.m_fd) {
            descriptor.m_fd = INVALID_FD;
        }

        file_descriptor &operator=(const file_descriptor &) = delete;

        file_descriptor &operator=(file_descriptor &&descriptor) noexcept {
            this->silent_close();
            std::swap(m_fd, descriptor.m_fd);
            return *this;
        }

        virtual ~file_descriptor() {
            silent_close();
        }

        int get_fd() const { return m_fd; }

        void close(bool throw_on_error = true) {
            int rc;
            if (m_fd != INVALID_FD) {
                rc = ::close(m_fd);
                m_fd = INVALID_FD;

                if (rc == -1 && throw_on_error) {
                    throw std::system_error(errno, std::system_category());
                }
            }
        }

        void silent_close() noexcept {
            close(false);
        }

    protected:

        int m_fd;

    };

    using time_type = decltype(std::chrono::steady_clock::now());

    constexpr std::chrono::milliseconds INFINITE_TIMEOUT(-1);

    class async_descriptor : public file_descriptor {
    public:

        async_descriptor(int fd, const std::shared_ptr<event_handler> &handler,
                                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : file_descriptor(fd), m_handler(handler), m_timeout(timeout) {

        }

        const std::shared_ptr<event_handler> &get_handler() const {
            return m_handler;
        }

        std::chrono::milliseconds get_timeout() const { return m_timeout; }

        const time_type &get_last_action() const { return m_last_action; }

        void set_last_action(const time_type &t) { m_last_action = t; }

    private:

        std::shared_ptr<event_handler> m_handler;
        std::chrono::milliseconds m_timeout;
        time_type m_last_action;


    };
}

#endif //ROCKET_FILE_DESCRIPTOR_HPP
