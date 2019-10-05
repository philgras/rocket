#include "event.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"

namespace rocket {

    void event_handler::on_lifecycle_events(io_loop &loop,
                                            const std::shared_ptr<async_descriptor> &fd,
                                            lifecycle_events events) {

        if (events & LC_LOOP_REMOVE) {
            this->on_removed(loop, fd);
        } else if (events & LC_LOOP_ADD) {
            this->on_added(loop, fd);
        } else if (events & LC_TIMEOUT) {
            this->on_timeout(loop, fd);
        } else if (events & LC_EXCEPTION) {
            this->on_exception(loop, fd, std::current_exception());
        }


    }

    void event_handler::on_io_events(io_loop &loop,
                                     const std::shared_ptr<async_descriptor> &fd,
                                     io_events events) {

        if (events & IO_ERR) {
            this->on_io_error(loop, fd);
            return;
        }
        if (events & IO_HUP) {
            this->on_hungup(loop, fd);
            return;
        }
        if (events & IO_IN || events & IO_OUT) {
            this->on_io(loop, fd, (events & IO_IN) == IO_IN, (events & IO_OUT) == IO_OUT);
        }
        if (events & IO_RDHUP) {
            this->on_read_hungup(loop, fd);
        }

    }


    void event_handler::on_timeout(io_loop &loop, const std::shared_ptr<async_descriptor> &fd) {
        loop.request_removal(fd);
    }

    void event_handler::on_removed(io_loop &loop, const std::shared_ptr<async_descriptor> &fd) {
        fd->close();
    }

    void event_handler::on_io_error(io_loop & loop, const std::shared_ptr<async_descriptor> & fd) {
        loop.request_removal(fd);
    }

    void event_handler::on_hungup(io_loop &loop, const std::shared_ptr<async_descriptor> &fd) {
        loop.request_removal(fd);
    }

    void event_handler::on_read_hungup(io_loop &loop, const std::shared_ptr<async_descriptor> &fd) {
        this->on_hungup(loop, fd);
    }


}