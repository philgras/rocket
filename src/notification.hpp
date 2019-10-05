#ifndef ROCKET_NOTIFICATION_HPP
#define ROCKET_NOTIFICATION_HPP

#include "file_descriptor.hpp"

#include <system_error>
#include <memory>

#include <sys/eventfd.h>

namespace rocket {

    struct default_notification_handler;


    class notify_descriptor : public async_descriptor {

    public:

        notify_descriptor(const std::shared_ptr<event_handler> &handler,
                          std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : async_descriptor(::eventfd(0, EFD_NONBLOCK), handler, timeout) {

            if (m_fd == -1) {
                throw std::system_error(errno, std::system_category());
            }

        }

        explicit notify_descriptor(std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : notify_descriptor(std::static_pointer_cast<event_handler>(
                std::make_shared<default_notification_handler>()), timeout) {}

        bool read(uint64_t *buf) {
            int rc = ::eventfd_read(m_fd, buf);
            if (rc == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    throw std::system_error(errno, std::system_category());
                } else {
                    return false;
                }
            } else {
                return true;
            }
        }

        bool write(uint64_t msg) {
            int rc = ::eventfd_write(m_fd, msg);
            if (rc == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    throw std::system_error(errno, std::system_category());
                } else {
                    return false;
                }
            } else {
                return true;
            }
        }


    };


    template<class subclass_type>
    class notification_handler : public event_handler {
    public:

        notification_handler()
                : event_handler(static_cast<io_events>(IO_IN | IO_ET)) {}

        void on_io(io_loop &loop, const std::shared_ptr<async_descriptor> &fd, bool read, bool write) override {
            if (read) {
                auto notifier_ptr = std::static_pointer_cast<notify_descriptor>(fd);
                uint64_t message;
                if (notifier_ptr->read(&message)) {
                    static_cast<subclass_type *>(this)->on_notification(loop, notifier_ptr, message);
                }
            }
        }

    };


    struct default_notification_handler : notification_handler<default_notification_handler> {
        void on_notification(io_loop &loop, const std::shared_ptr<async_descriptor> &fd, uint64_t message) {}
    };


}

#endif //ROCKET_NOTIFICATION_HPP
