#include "event.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"

#include <iostream>

namespace rocket {

void event_handler::on_lifecycle_events(
    io_loop &loop, const std::shared_ptr<async_descriptor> &fd,
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
  if (events & IO_RDHUP) {
    this->on_read_hungup(loop, fd);
  }
  if (events & IO_IN || events & IO_OUT) {
    this->on_io(loop, fd, (events & IO_IN) == IO_IN,
                (events & IO_OUT) == IO_OUT);
  }
}

void event_handler::on_timeout(io_loop &loop,
                               const std::shared_ptr<async_descriptor> &fd) {
  std::cerr << "Timeout occured on descriptor: " << fd->get_fd() << std::endl;
  loop.request_remove(fd);
}

void event_handler::on_removed(io_loop &loop,
                               const std::shared_ptr<async_descriptor> &fd) {
  fd->silent_close();
}

void event_handler::on_io_error(io_loop &loop,
                                const std::shared_ptr<async_descriptor> &fd) {
  std::cerr << "IO error occured on descriptor: " << fd->get_fd() << std::endl;
  loop.request_remove(fd);
}

void event_handler::on_exception(io_loop &loop,
                                 const std::shared_ptr<async_descriptor> &fd,
                                 const std::exception_ptr &e_ptr) {
  if (e_ptr) {
    try {
      std::rethrow_exception(e_ptr);
    } catch (const std::system_error &err) {
      // TODO handle out of memory system errors here
      std::cerr << "Caught exception when handling descriptor " << fd->get_fd()
                << ": " << err.what() << std::endl;
    } catch (const std::bad_alloc &err) {
      throw err;
    } catch (const std::exception &err) {
      std::cerr << "Caught exception when handling descriptor " << fd->get_fd()
                << ": " << err.what() << std::endl;
    }
    loop.request_remove(fd);
  }
}

void event_handler::on_hungup(io_loop &loop,
                              const std::shared_ptr<async_descriptor> &fd) {
  loop.request_remove(fd);
}

}
