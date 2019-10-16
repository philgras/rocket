#ifndef ROCKET_SOCKET_HPP
#define ROCKET_SOCKET_HPP

#include "event.hpp"
#include "file_descriptor.hpp"
#include "io_loop.hpp"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <system_error>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#define WHILE_EINTR(func, rc)                            \
                do{                                      \
                    rc = func;                           \
                }while( rc == -1&& errno == EINTR)


namespace rocket {

class address_iter {
public:
  address_iter(const struct addrinfo *addr_ptr) : m_addr_ptr(addr_ptr) {}

  void next() {
    if (m_addr_ptr) {
      m_addr_ptr = m_addr_ptr->ai_next;
    }
  }

  bool has_next() const { return m_addr_ptr != nullptr; }

  const sockaddr *get_sock_addr() const { return m_addr_ptr->ai_addr; }

  socklen_t get_addr_len() const { return m_addr_ptr->ai_addrlen; }

  int get_address_family() const { return m_addr_ptr->ai_family; }

  int get_protocol() const { return m_addr_ptr->ai_protocol; }

  int get_socktype() const { return m_addr_ptr->ai_socktype; }

private:
  const struct addrinfo *m_addr_ptr;
};

class address_info {
public:
  address_info(const char *hostname, const char *service,
               int address_family = 0, int socket_type = 0,
               int address_protocol = 0, int flags = 0)
      : m_res(nullptr) {

    struct addrinfo hints;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = socket_type;
    hints.ai_protocol = address_protocol;
    hints.ai_flags = flags;

    rc = ::getaddrinfo(hostname, service, &hints, &m_res);
    if (rc != 0) {
      const char *error_str = ::gai_strerror(rc);
      throw std::runtime_error(error_str);
    }
  }

  address_iter iter() const { return address_iter(m_res); }

  void free() {
    if (m_res) {
      ::freeaddrinfo(m_res);
    }
  }

  ~address_info() { free(); }

private:
  struct addrinfo *m_res;
};

template <typename handler_type>
class socket_descriptor : public async_descriptor {

public:
  socket_descriptor(int address_family, int socket_type, int address_protocol,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : async_descriptor(INVALID_FD, std::make_shared<handler_type>(),
                         timeout) {

    m_fd =
        ::socket(address_family, socket_type | SOCK_NONBLOCK, address_protocol);
    if (m_fd == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  socket_descriptor(int fd,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : async_descriptor(fd, std::make_shared<handler_type>(), timeout) {}
};

template <typename handler_type>
class stream_connection : public socket_descriptor<handler_type> {
public:
  stream_connection(const sockaddr *addr, socklen_t socklen,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : socket_descriptor<handler_type>(addr->sa_family, SOCK_STREAM,
                                        addr->sa_family, timeout),
        m_addr_cache() {

    m_addr_cache = std::make_unique<std::pair<socklen_t, sockaddr_storage>>();
    m_addr_cache->first = socklen;
    std::memcpy(&m_addr_cache->second, addr, socklen);
  }

  stream_connection(int fd, const sockaddr *addr, socklen_t socklen,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : socket_descriptor<handler_type>(fd, timeout), m_addr_cache() {

    m_addr_cache = std::make_unique<std::pair<socklen_t, sockaddr_storage>>();
    m_addr_cache->first = socklen;
    std::memcpy(&m_addr_cache->second, addr, socklen);
  }

  bool connect() {
    int rc;
    const sockaddr *addr =
        reinterpret_cast<const sockaddr *>(&m_addr_cache->second);
    WHILE_EINTR(::connect(m_fd, addr, m_addr_cache->first), rc);

    if (rc == -1) {
      if (errno == EINPROGRESS) {
        return false;
      } else {
        throw std::system_error(errno, std::system_category());
      }
    }

    return true;
  }

  bool check_connect() {
    int connected;
    socklen_t size = sizeof(connected);

    if (::getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &connected, &size) == -1) {
      throw std::system_error(errno, std::system_category());

    } else if (connected != 0) {
      if (connected == EINPROGRESS) {
        return false;
      } else {
        throw std::system_error(connected, std::system_category());
      }
    }

    return true;
  }

  const char *read(char *begin, char *end) {
    int rc;
    WHILE_EINTR(recv(m_fd, begin, std::distance(begin, end), 0), rc);

    if (rc > 0) {
      begin += rc;
    } else if (rc == 0) {
      begin = nullptr;
    } else {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        throw std::system_error(errno, std::system_category());
      }
    }

    return begin;
  }

  const char *write(const char *cbegin, const char *cend) {
    int rc;

    while (cbegin != cend) {
      WHILE_EINTR(send(m_fd, cbegin, std::distance(cbegin, cend), 0), rc);

      if (rc >= 0) {
        cbegin += rc;
      } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          throw std::system_error(errno, std::system_category());
        }
        break;
      }
    }

    return cbegin;
  }

  void release_cached_peer_address() { m_addr_cache.release(); }

  const std::unique_ptr<std::pair<socklen_t, sockaddr_storage>> &
  get_peer_address() const {
    return m_addr_cache;
  }

private:
  std::unique_ptr<std::pair<socklen_t, sockaddr_storage>> m_addr_cache;
};

template <typename handler_type>
class stream_listener : public socket_descriptor<handler_type> {
public:
  using connection_type = typename handler_type::connection_type;

  stream_listener(const sockaddr *addr, socklen_t addr_len, int max_conns,
                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT,
                  std::chrono::milliseconds timeout_accepted = INFINITE_TIMEOUT)
      : socket_descriptor<handler_type>(addr->sa_family, SOCK_STREAM,
                                        addr->sa_family, timeout),
        m_max_conns(max_conns), m_timeout_accepted(timeout_accepted) {

    int yes = 1;
    if (::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
      throw std::system_error(errno, std::system_category());
    }

    if (::bind(m_fd, addr, addr_len) == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  void listen() {
    if (::listen(m_fd, m_max_conns) == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  std::vector<std::shared_ptr<connection_type>> accept(bool accept_once) {
    int socket_fd;
    std::vector<std::shared_ptr<connection_type>> accept_buffer;
    sockaddr_storage address;
    sockaddr *address_ptr = reinterpret_cast<sockaddr *>(&address);
    socklen_t address_len;

    do {
      WHILE_EINTR(::accept4(m_fd, address_ptr, &address_len, SOCK_NONBLOCK),
                  socket_fd);

      if (socket_fd == INVALID_FD) {
        if (errno == ECONNABORTED) {
          continue;
        } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
          break;
        } else {
          throw std::system_error(errno, std::system_category());
        }
      } else {
        auto conn_ptr = std::make_shared<connection_type>(
            socket_fd, address_ptr, address_len, m_timeout_accepted);
        accept_buffer.push_back(conn_ptr);
      }
    } while (!accept_once);

    return accept_buffer;
  }

private:
  int m_max_conns;
  std::chrono::milliseconds m_timeout_accepted;
};

template <typename subclass_type, typename connection_handler_type>
class accept_handler : public event_handler {
public:
  using connection_type = stream_connection<connection_handler_type>;
  using listener_type = stream_listener<accept_handler<subclass_type>>;
  accept_handler() : event_handler(static_cast<io_events>(IO_IN | IO_ET)) {}

  void on_added(io_loop &loop,
                const std::shared_ptr<async_descriptor> &fd_ptr) override {

    auto &listener = static_cast<listener_type &>(*fd_ptr);
    listener.listen();
  }

  void on_io(io_loop &loop, const std::shared_ptr<async_descriptor> &fd_ptr,
             bool read, bool write) override {

    if (read) {
      auto &listener = static_cast<listener_type &>(*fd_ptr);
      auto accept_buffer = listener.accept(false);
      for (const auto &connection : accept_buffer) {
        static_cast<subclass_type *>(this)->on_accept(loop, fd_ptr, connection);
      }
    }
  }
};

template <typename connection_handler_type>
struct default_accept_handler
    : public accept_handler<default_accept_handler, connection_handler_type> {
  void on_accept(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &listener_ptr,
                 const std::shared_ptr<async_descriptor> &connection_ptr) {
    loop.request_add(connection_ptr);
  }
};

using template <connection_handler_type>
default_stream_listener =
    stream_listener<default_accept_handler<connection_handler_type>>;

} // namespace rocket

#endif //ROCKET_SOCKET_HPP
