#include "loop.hpp"
#include "file_descriptor.hpp"

#include <system_error>
#include <chrono>
#include <cerrno>

#include <sys/epoll.h>


namespace rocket {

io_loop::io_loop(int max_ready_events)
    : m_epoll_fd(::epoll_create1(0)), m_registered_fds(), m_add_queue(),
      m_remove_queue(), m_max_ready_events(max_ready_events),
      m_wakeup_notifier(std::make_shared<notify_descriptor>()),
      m_request_shutdown(false), m_start_mutex() {

  if (m_epoll_fd.get_fd() == file_descriptor::INVALID_FD) {
    throw std::system_error(errno, std::system_category());
  }
}

void io_loop::add(const std::shared_ptr<async_descriptor> &descriptor_ptr) {

  int rc;
  struct epoll_event config;
  int fd = descriptor_ptr->get_fd();
  auto &handler = descriptor_ptr->get_handler();

  config.events = handler->get_io_event_config();
  config.data.fd = fd;

  rc = ::epoll_ctl(m_epoll_fd.get_fd(), EPOLL_CTL_ADD, fd, &config);
  if (rc) {
    throw std::system_error(errno, std::system_category());
  }

  m_registered_fds.emplace(fd, descriptor_ptr);
  this->call_handler(descriptor_ptr, static_cast<io_events>(0), LC_LOOP_ADD);
}

void io_loop::remove(
    const std::shared_ptr<rocket::async_descriptor> &descriptor_ptr) {

  if (!this->is_registered(descriptor_ptr))
    return;

  int rc;

  rc = ::epoll_ctl(m_epoll_fd.get_fd(), EPOLL_CTL_DEL, descriptor_ptr->get_fd(),
                   nullptr);
  if (rc) {
    throw std::system_error(errno, std::system_category());
  }

  m_registered_fds.erase(descriptor_ptr->get_fd());
  this->call_handler(descriptor_ptr, static_cast<io_events>(0), LC_LOOP_REMOVE);
}

void io_loop::call_handler(
    const std::shared_ptr<async_descriptor> &descriptor_ptr, io_events io,
    lifecycle_events lc) {

  auto &handler = descriptor_ptr->get_handler();

  try {
    if (lc) {
      handler->on_lifecycle_events(*this, descriptor_ptr, lc);
    } else if (io) {
      handler->on_io_events(*this, descriptor_ptr, io);
    }
  } catch (...) {
    handler->on_lifecycle_events(*this, descriptor_ptr, LC_EXCEPTION);
  }

  descriptor_ptr->set_last_action(std::chrono::steady_clock::now());
}

void io_loop::start() {
  std::scoped_lock lock(m_start_mutex);

  int rc;
  int timeout;
  bool expected = true;
  std::shared_ptr<async_descriptor> descriptor;
  std::unique_ptr<struct epoll_event[]> ready_fds(
      new struct epoll_event[m_max_ready_events]);
  this->add(std::static_pointer_cast<async_descriptor>(m_wakeup_notifier));

  do {
    expected = true;

    // add all new descriptors from the request queue
    while (m_add_queue.pop_into(descriptor)) {
      this->add(descriptor);
    }

    // remove all descriptors from the request queue
    while (m_remove_queue.pop_into(descriptor)) {
      this->remove(descriptor);
    }

    timeout = this->check_timeout();
    rc = ::epoll_wait(m_epoll_fd.get_fd(), ready_fds.get(), m_max_ready_events,
                      timeout);

    if (rc == -1 && errno != EINTR) {
      throw std::system_error(errno, std::system_category());

    } else if (rc >= 0) { // handle io events
      for (int i = 0; i < rc; ++i) {
        auto &descriptor_ptr = m_registered_fds[ready_fds[i].data.fd];
        auto events = static_cast<io_events>(ready_fds[i].events);
        this->call_handler(descriptor_ptr, events,
                           static_cast<lifecycle_events>(0));
      }
    }

  } while (!m_request_shutdown.compare_exchange_strong(expected, false));

  for (auto iter = m_registered_fds.cbegin();
       iter != m_registered_fds.cend();) {
    this->remove((iter++)->second);
  }
}

int io_loop::check_timeout() {
  int earliest_timeout = -1;

  auto now = std::chrono::steady_clock::now();
  for (const auto &pair : m_registered_fds) {
    auto timeout = pair.second->get_timeout();
    if (timeout.count() >= 0) {
      auto &last_action = pair.second->get_last_action();
      auto diff = timeout - (now - last_action);
      auto expiration =
          std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();

      if (expiration <= 0) {
        this->call_handler(pair.second, static_cast<io_events>(0), LC_TIMEOUT);
        expiration = timeout.count();
      }

      if (earliest_timeout == -1 || earliest_timeout > expiration) {
        earliest_timeout = static_cast<int>(expiration);
      }
    }
  }

  return earliest_timeout;
}
}
