#ifndef ROCKET_SOCKET_HPP
#define ROCKET_SOCKET_HPP

#include "event.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <system_error>
#include <type_traits>
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
  address_iter(const std::shared_ptr<struct addrinfo> &addr_ptr)
      : m_resource(addr_ptr), m_addr_ptr(addr_ptr.get()) {}

  void next() {
    if (m_addr_ptr) {
      m_addr_ptr = m_addr_ptr->ai_next;
    }
  }

  bool has_next() const { return m_addr_ptr != nullptr; }

  const sockaddr *get_addr() const { return m_addr_ptr->ai_addr; }

  socklen_t get_addrlen() const { return m_addr_ptr->ai_addrlen; }

  int get_address_family() const { return m_addr_ptr->ai_family; }

  int get_protocol() const { return m_addr_ptr->ai_protocol; }

  int get_socktype() const { return m_addr_ptr->ai_socktype; }

private:
  std::shared_ptr<struct addrinfo> m_resource;
  struct addrinfo *m_addr_ptr;
};

class address_info {
public:
  address_info(const char *hostname, const char *service,
               int address_family = 0, int socket_type = 0,
               int address_protocol = 0, int flags = 0)
      : m_res(nullptr, address_info::free) {

    struct addrinfo hints;
    struct addrinfo *res;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = socket_type;
    hints.ai_protocol = address_protocol;
    hints.ai_flags = flags;

    rc = ::getaddrinfo(hostname, service, &hints, &res);
    if (rc != 0) {
      const char *error_str = ::gai_strerror(rc);
      throw std::runtime_error(error_str);
    }
    m_res.reset(res);
  }

  static address_iter tcp_bind(const char *service,
                               int address_family = AF_UNSPEC) {
    auto ainfo = address_info(nullptr, service, address_family, SOCK_STREAM,
                              IPPROTO_TCP, AI_PASSIVE);
    return ainfo.iter();
  }

  static address_iter tcp_connect(const char *host, const char *service,
                                  int address_family = AF_UNSPEC) {
    auto ainfo = address_info(host, service, address_family, SOCK_STREAM,
                              IPPROTO_TCP, 0);
    return ainfo.iter();
  }

  ~address_info() = default;

  address_iter iter() const { return address_iter(m_res); }

private:
  static void free(struct addrinfo *ptr) { ::freeaddrinfo(ptr); }
  std::shared_ptr<struct addrinfo> m_res;
};

// TODO implement shutdown of read and write channels
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

  stream_listener(const sockaddr *addr, socklen_t addr_len, int max_connx,
                  std::chrono::milliseconds timeout_accepted = INFINITE_TIMEOUT,
                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
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
  using listener_type =
      stream_listener<accept_handler<subclass_type, connection_handler_type>>;
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
    : public accept_handler<default_accept_handler<connection_handler_type>,
                            connection_handler_type> {
  void on_accept(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &listener_ptr,
                 const std::shared_ptr<async_descriptor> &connection_ptr) {
    loop.request_add(connection_ptr);
  }
};

template <typename connection_handler_type>
using default_stream_listener =
    stream_listener<default_accept_handler<connection_handler_type>>;

template <typename subclass, typename protocol, std::size_t buffer_size>
class connection_handler : public event_handler {
public:
  using server_message = typename protocol::server_message_type;
  using client_message = typename protocol::client_message_type;
  using parser = typename protocol::parser_type;
  using stream = typename protocol::stream_type;
  using connection = stream_connection<subclass>;

  connection_handler(bool connect_on_add)
      : event_handler(
            static_cast<io_events>(IO_IN | IO_OUT | IO_ET | IO_RDHUP)),
        m_server_message(), m_client_message(), m_parser(), m_stream(),
        m_io_buffer(), m_last_end(nullptr), m_content_end(nullptr),
        m_wait_state(connect_on_add ? WAIT_CONN : NO_WAIT) {}

  void on_added(io_loop &loop,
                const std::shared_ptr<async_descriptor> &fd_ptr) override {
    auto &conn = static_cast<connection &>(*fd_ptr);
    if (m_wait_state == WAIT_CONN && conn.connect()) {
      this->reset_wait_state();
      static_cast<subclass *>(this)->on_connect(loop, fd_ptr);
    } else {
      static_cast<subclass *>(this)->on_accept(loop, fd_ptr);
    }
  }

  void on_io(io_loop &loop, const std::shared_ptr<async_descriptor> &fd_ptr,
             bool read, bool write) override {

    auto &conn = static_cast<connection &>(*fd_ptr);
    auto subclass_ptr = static_cast<subclass *>(this);
    if (m_wait_state == WAIT_CONN && write) {
      if (conn.check_connect()) {
        this->reset_wait_state();
        subclass_ptr->on_connect(loop, fd_ptr);
      }
    } else if (m_wait_state == WAIT_WRITE && write) {
      if (this->write_loop(conn)) {
        subclass_ptr->on_message_sent(loop, fd_ptr);
      }
    } else if (m_wait_state == WAIT_READ && read) {
      if (this->read_loop(conn)) {
        subclass_ptr->on_message_received(loop, fd_ptr);
      } else if (m_peer_hungup) {
        // when still waiting for input data but read hung up was detected
        // the socket will wait until it timeouts
        loop.request_remove(fd_ptr);
      }
    }
  }

  void on_read_hungup(io_loop &loop,
                      const std::shared_ptr<async_descriptor> &fd_ptr) {
    m_peer_hungup = true;
  }

protected:

  bool is_read_hungup() const { return m_peer_hungup; }

  template <typename message_type>
  bool read_message(connection &conn, message_type &message) {

    m_parser.start(message);
    m_last_end = m_content_end = m_io_buffer.begin();
    return this->read_loop(conn);
  }

  template <typename message_type>
  bool write_message(connection &conn, const message_type &message) {

    m_stream.start(message);
    m_last_end = m_content_end = m_io_buffer.begin();
    return this->write_loop(conn);
  }

  server_message m_server_message;
  client_message m_client_message;
  parser m_parser;
  stream m_stream;

private:
  enum wait_state {
    WAIT_CONN = 1,
    WAIT_READ = 1 << 1,
    WAIT_WRITE = 1 << 2,
    NO_WAIT = 1 << 3
  };

  bool read_loop(connection &conn) {
    bool finished = false;

    while (!(finished = m_parser.done())) {
      m_last_end = conn.read(m_io_buffer.begin(), m_io_buffer.end());
      if (m_last_end == nullptr) {
        m_peer_hungup = true;
        break;
      } else if (m_last_end == m_io_buffer.cbegin()) {
        break;
      } else {
        m_parser.next(m_io_buffer.cend(), m_last_end);
      }
    }
    m_wait_state = finished ? NO_WAIT : WAIT_READ;
    return finished;
  }

  bool write_loop(connection &conn) {
    bool finished = false;

    // first continue writing when previous write has been set to wait
    if (m_last_end != m_content_end) {
      m_last_end = conn.write(m_last_end, m_content_end);
      if (m_last_end != m_content_end) {
        m_wait_state = WAIT_WRITE;
        return finished;
      }
    }
    // stream the message
    while (!(finished = m_stream.done())) {
      m_content_end = m_stream.next(m_io_buffer.begin(), m_io_buffer.end());
      m_last_end = conn.write(m_io_buffer.begin(), m_content_end);
      if (m_last_end != m_content_end) {
        break;
      }
    }
    m_wait_state = finished ? NO_WAIT : WAIT_WRITE;

    return finished;
  }

  std::array<char, buffer_size> m_io_buffer;
  char *m_last_end;
  char *m_content_end;
  bool m_peer_hungup;
  wait_state m_wait_state;
};

template <typename subclass, typename protocol, std::size_t buffer_size = 1024>
class client_handler
    : public connection_handler<subclass, protocol, buffer_size> {
public:
  client_handler()
      : connection_handler<subclass, protocol, buffer_size>(true),
        m_shutdown_requested(false) {}

  void on_connect(io_loop &loop,
                  const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    auto subclass_ptr = static_cast<subclass *>(this);
    m_client_message.clear();
    subclass_ptr->on_connect(m_client_message);
    this->lifecycle(loop, fd_ptr);
  }

  void on_message_received(io_loop &loop,
                           const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    this->response_callback();
    this->lifecycle(loop, fd_ptr);
  }

  void on_message_sent(io_loop &loop,
                       const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    if (this->read_message(conn, m_server_message)) {
      this->response_callback();
      this->lifecycle(loop, fd_ptr);
    } else if (this->is_read_hungup()) {
      loop.request_remove(fd_ptr);
    }
  }

protected:
  void shutdown() { m_shutdown_requested = true; }

private:
  void lifecycle(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &fd_ptr) {
    while (true) {
      if (m_shutdown_requested) {
        // Directly after a callback invokation, it must be checked
        // if shutdown was called. If so, close socket.
        loop.request_remove(fd_ptr);
      }
      if (!this->is_read_hungup() &&
          this->write_message(conn, m_client_message)) {
        // if the read channel is not hung up it is reasonable to write,
        // because an answer is expected. If the message can e written
        // rigth away, start reading
        if (this->read_message(conn, m_server_message)) {
          // if the message can be read completely, continue with
          // processing it and start the loop again
          this->response_callback();
          continue;
        } else if (this->is_read_hungup()) {
          // otherwise check if the reading could not be completed
          // due to a read hungup. As we need to read more to obtain
          // a message object, which is not going to happen, we are
          // lost. Thus, close the connection.
          loop.request_remove(fd_ptr);
        }
      }
      break;
    }
  }

  void response_callback() {
    auto subclass_ptr = static_cast<subclass *>(this);
    m_client_message.clear();
    subclass_ptr->on_response(m_server_message, m_client_message);
    m_server_message.clear();
  }

  bool m_shutdown_requested;
};

template <typename subclass, typename protocol, std::size_t buffer_size = 1024>
class server_handler
    : public connection_handler<subclass, protocol, buffer_size> {
public:
  server_handler()
      : connection_handler<subclass, protocol, buffer_size>(false),
        m_shutdown_requested(false) {}

  void on_accept(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    if (this->read_message(conn, m_client_message)) {
      this->request_callback();
      this->lifecycle(loop, fd_ptr);
    } else if (this->is_read_hungup()) {
      loop.request_remove(fd_ptr);
    }
  }

  void on_message_received(io_loop &loop,
                           const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    this->request_callback();
    this->lifecycle(loop, fd_ptr);
  }

  void on_message_sent(io_loop &loop,
                       const std::shared_ptr<async_descriptor> &fd_ptr) {

    auto &conn = static_cast<connection &>(*fd_ptr);
    if (!this->is_read_hungup() && this->read_message(conn, m_client_message)) {
      this->request_callback();
      this->lifecycle(loop, fd_ptr);
    } else if (this->is_read_hungup()) {
      loop.request_remove(fd_ptr);
    }
  }

protected:
  void shutdown() { m_shutdown_requested = true; }

private:
  void lifecycle(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &fd_ptr) {
    while (true) {
      if (m_shutdown_requested) {
        // Directly after a callback invokation, it must be checked
        // if shutdown was called. If so, close socket.
        loop.request_remove(fd_ptr);
      }
      if (this->write_message(conn, m_server_message)) {
        // send even if the read channel is hung up because, the client
        // expects only the response and you expect no further requests
        if (!this->is_read_hungup() &&
            this->read_message(conn, m_client_message)) {
          // if no read hungups were detected before and the message can be
          // read completely, continue with processing it and start the loop
          // again
          this->request_callback();
          continue;
        } else if (this->is_read_hungup()) {
          // otherwise check if the reading task could not be completed
          // due to a read hungup. As we need to read more to obtain
          // a message object, which is not going to happen, we are
          // lost. Thus, close the connection.
          loop.request_remove(fd_ptr);
        }
      }
      break;
    }
  }

  void request_callback() {
    auto subclass_ptr = static_cast<subclass *>(this);
    m_server_message.clear();
    sublass_ptr->on_request(m_client_message, m_server_message);
    m_client_message.clear();
  }

  bool m_shutdown_requested;
};
} // namespace rocket
#endif //ROCKET_SOCKET_HPP
