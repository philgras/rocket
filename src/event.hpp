#ifndef ROCKET_EVENT_HPP
#define ROCKET_EVENT_HPP

#include <memory>
#include <exception>
#include <sys/epoll.h>

namespace rocket {

enum io_events : uint32_t {
  IO_IN = EPOLLIN,
  IO_OUT = EPOLLOUT,
  IO_RDHUP = EPOLLRDHUP,
  IO_HUP = EPOLLHUP,
  IO_ERR = EPOLLERR,
  IO_ET = EPOLLET,
  IO_EXCLUSIVE = EPOLLEXCLUSIVE
};

enum lifecycle_events : u_int8_t {
  LC_TIMEOUT = 0x1,
  LC_LOOP_REMOVE = 0x2,
  LC_LOOP_ADD = 0x4,
  LC_EXCEPTION = 0x8
};

class io_loop;

class async_descriptor;

class event_handler {

public:
  explicit event_handler(io_events config) : m_config(config) {}

  virtual ~event_handler() = default;

  io_events get_io_event_config() const { return m_config; }

  void on_lifecycle_events(io_loop &, const std::shared_ptr<async_descriptor> &,
                           lifecycle_events);

  void on_io_events(io_loop &, const std::shared_ptr<async_descriptor> &,
                    io_events);

  virtual void on_timeout(io_loop &, const std::shared_ptr<async_descriptor> &);

  virtual void on_added(io_loop &, const std::shared_ptr<async_descriptor> &){};

  virtual void on_removed(io_loop &, const std::shared_ptr<async_descriptor> &);

  virtual void on_exception(io_loop &,
                            const std::shared_ptr<async_descriptor> &fd_ptr,
                            const std::exception_ptr &e_ptr);

  virtual void on_io_error(io_loop &,
                           const std::shared_ptr<async_descriptor> &);

  virtual void on_hungup(io_loop &, const std::shared_ptr<async_descriptor> &);

  virtual void on_read_hungup(io_loop &,
                              const std::shared_ptr<async_descriptor> &) {}

  virtual void on_io(io_loop &, const std::shared_ptr<async_descriptor> &,
                     bool read, bool write) = 0;

private:
  io_events m_config;
};
}

#endif //ROCKET_EVENT_HPP
