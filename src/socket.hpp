#ifndef ROCKET_SOCKET_HPP
#define ROCKET_SOCKET_HPP

#include "event.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"

#include <array>
#include <iostream>
#include <algorithm>
#include <system_error>
#include <type_traits>
#include <vector>

#include <cerrno>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>


#define WHILE_EINTR(func, rc)                            \
                do{                                      \
                    rc = func;                           \
                }while( rc == -1&& errno == EINTR)


namespace rocket {

class address_iter {
public:

  address_iter()
  : m_resource(), m_addr_ptr(nullptr){
  }

  explicit address_iter(const std::shared_ptr<struct addrinfo> &addr_ptr)
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

  const char* get_canonical_name() const { return m_resource->ai_canonname; }

private:
  std::shared_ptr<struct addrinfo> m_resource;
  struct addrinfo *m_addr_ptr;
};

class address_info {
public:
  address_info(const char *hostname, const char *service,
               int address_family = 0, int socket_type = 0,
               int address_protocol = 0, int flags = 0)
      : m_res(nullptr) {

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
    m_res.reset(res, address_info::free);
  }

  static address_iter tcp_bind(const char *host, const char *service,
                               int address_family = AF_UNSPEC) {
    auto ainfo = address_info(host, service, address_family, SOCK_STREAM, IPPROTO_TCP,
                              AI_PASSIVE);
    return ainfo.iter();
  }

  static address_iter tcp_connect(const char *host, const char *service,
                                  int address_family = AF_UNSPEC) {
    auto ainfo = address_info(host, service, address_family, SOCK_STREAM, IPPROTO_TCP, 0);
    return ainfo.iter();
  }

  ~address_info() = default;

  address_iter iter() const { return address_iter(m_res); }

private:
  static void free(struct addrinfo *ptr) {
      ::freeaddrinfo(ptr);
  }
  std::shared_ptr<struct addrinfo> m_res;
};

// TODO implement shutdown of read and write channels
class socket_descriptor : public async_descriptor {

public:
  socket_descriptor(int address_family, int socket_type, int address_protocol,
                    const std::shared_ptr<event_handler>& handler,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : async_descriptor(INVALID_FD, handler, timeout) {

    m_fd =
        ::socket(address_family, socket_type | SOCK_NONBLOCK, address_protocol);
    if (m_fd == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  socket_descriptor(const address_iter& addr,
                    const std::shared_ptr<event_handler>& handler,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
            : socket_descriptor(addr.get_address_family(), addr.get_socktype(),
                                addr.get_protocol(), handler,  timeout){}

  socket_descriptor(int fd, const std::shared_ptr<event_handler>& handler,
                    std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : async_descriptor(fd, handler, timeout) {}

};

class stream_socket : public socket_descriptor{

public:
    stream_socket(const address_iter& addr,
                  const std::shared_ptr<event_handler>& handler,
                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
            : socket_descriptor(addr, handler,  timeout),
              m_sockaddr(), m_hostname(addr.get_canonical_name()), m_ip(), m_port(){

        m_sockaddr.first = addr.get_addrlen();
        std::memcpy(&m_sockaddr.second, addr.get_addr(), addr.get_addrlen());
        this->fill_ip_and_port();
    }

    stream_socket(int fd, const sockaddr *addr, socklen_t socklen,
                  const std::shared_ptr<event_handler>& handler,
                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
        : socket_descriptor(fd, handler, timeout),
          m_sockaddr(), m_hostname(), m_ip(), m_port(){

        m_sockaddr.first = socklen;
        std::memcpy(&m_sockaddr.second, addr, socklen);
        this->fill_ip_and_port();
    }

    const std::pair<socklen_t, sockaddr_storage>& get_sockaddr() const {
        return m_sockaddr;
    }

    const std::string& retrieve_hostname() {
        char namebuf[NI_MAXHOST];
        int rc = ::getnameinfo(reinterpret_cast<const ::sockaddr*>(&m_sockaddr.second),
                               m_sockaddr.first, namebuf, sizeof(namebuf),
                               NULL, 0, NI_NAMEREQD);
        if (rc == 0){
            m_hostname = namebuf;
        }

        return m_hostname;
    }

    const std::string& get_hostname() const {
        return m_hostname;
    }

    const std::string& get_ip() const {
        return m_ip;
    }

    uint16_t get_port() const {
        return m_port;
    }

private:

    void fill_ip_and_port(){
        switch(reinterpret_cast<::sockaddr*>(&m_sockaddr.second)->sa_family){
            case AF_INET:
                {
                    char ipstr[INET_ADDRSTRLEN];
                    m_ip = inet_ntop(AF_INET, &m_sockaddr.second,
                                     ipstr, m_sockaddr.first);
                    m_port = ntohs(reinterpret_cast<::sockaddr_in*>(&m_sockaddr.second)->sin_port);
                }
                break;
            case AF_INET6:
                {
                    char ipstr[INET6_ADDRSTRLEN];
                    m_ip = inet_ntop(AF_INET, &m_sockaddr.second,
                                     ipstr, m_sockaddr.first);
                    m_port = ntohs(reinterpret_cast<::sockaddr_in6*>(&m_sockaddr.second)->sin6_port);
                }
                break;
            default:
                throw std::runtime_error("An invalid address family was encountered");
        }

    }

    std::pair<socklen_t, sockaddr_storage> m_sockaddr;
    std::string m_hostname;
    std::string m_ip;
    uint16_t m_port;
};


class stream_connection : public stream_socket{
public:

  using stream_socket::stream_socket;

  bool connect() {
    int rc;
    const sockaddr *addr =
        reinterpret_cast<const sockaddr *>(&this->get_sockaddr().second);
    WHILE_EINTR(::connect(this->m_fd, addr, m_addr_cache->first), rc);
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
    if (::getsockopt(this->m_fd, SOL_SOCKET, SO_ERROR, &connected, &size) ==
        -1) {
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
    WHILE_EINTR(recv(this->m_fd, begin, std::distance(begin, end), 0), rc);
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
      WHILE_EINTR(send(this->m_fd, cbegin, std::distance(cbegin, cend), 0), rc);
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

};


class stream_listener : public stream_socket {
public:

  stream_listener(const address_iter& bind_addr, int max_conns,
                  const std::shared_ptr<event_handler>& handler,
                  std::chrono::milliseconds timeout_accepted = INFINITE_TIMEOUT,
                  std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
      : stream_socket(bind_addr, handler, timeout),
        m_max_conns(max_conns), m_timeout_accepted(timeout_accepted) {

    int yes = 1;
    if (::setsockopt(this->m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ==
        -1) {
      throw std::system_error(errno, std::system_category());
    }

    if (::bind(this->m_fd, bind_addr.get_addr(), bind_addr.get_addrlen()) == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  void listen() {
    if (::listen(this->m_fd, m_max_conns) == -1) {
      throw std::system_error(errno, std::system_category());
    }
  }

  template<typename connection_handler>
  std::vector<std::shared_ptr<stream_connection>> accept(bool accept_once) {

    int socket_fd;
    std::vector<std::shared_ptr<stream_connection>> accept_buffer;
    sockaddr_storage address;
    sockaddr *address_ptr = reinterpret_cast<sockaddr *>(&address);
    socklen_t address_len;

    do {
      WHILE_EINTR(
          ::accept4(this->m_fd, address_ptr, &address_len, SOCK_NONBLOCK),
          socket_fd);

      if (socket_fd == file_descriptor::INVALID_FD) {
        if (errno == ECONNABORTED) {
          continue;
        } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
          break;
        } else {
          throw std::system_error(errno, std::system_category());
        }
      } else {
        auto conn_ptr = std::make_shared<stream_connection>(
            socket_fd, address_ptr, address_len,
            std::make_shared<connection_handler>(),
            m_timeout_accepted);
        accept_buffer.push_back(conn_ptr);
      }
    } while (!accept_once);

    return accept_buffer;
  }

private:
  int m_max_conns;
  std::chrono::milliseconds m_timeout_accepted;
};

template <typename subclass, typename connection_handler>
class accept_handler : public event_handler {
public:

  accept_handler() : event_handler(static_cast<io_events>(IO_IN | IO_ET)) {}

  void on_added(io_loop &loop,
                const std::shared_ptr<async_descriptor> &fd_ptr) override {

    auto &listener = static_cast<stream_listener &>(*fd_ptr);
    listener.listen();
  }

  void on_io(io_loop &loop, const std::shared_ptr<async_descriptor> &fd_ptr,
             bool read, bool write) override {

    if (read) {
      auto &listener = static_cast<stream_listener &>(*fd_ptr);
      auto accept_buffer = listener.accept<connection_handler>(false);
      for (const auto &connection : accept_buffer) {
        static_cast<subclass *>(this)->on_accept(loop, fd_ptr, connection);
      }
    }
  }
};

template <typename connection_handler>
struct default_accept_handler
    : public accept_handler<default_accept_handler<connection_handler>,
                            connection_handler> {
  void on_accept(io_loop &loop,
                 const std::shared_ptr<async_descriptor> &listener_ptr,
                 const std::shared_ptr<async_descriptor> &connection_ptr) {
    loop.request_add(connection_ptr);
  }
};

enum wait_state {
    WAIT_CONN = 1,
    WAIT_READ = 1 << 1,
    WAIT_WRITE = 1 << 2,
    WAIT_SHUTDOWN = 1 << 3,
    NO_WAIT = 1 << 4
};

template<typename subclass>
class connection_handler : public event_handler {
public:

  connection_handler(bool connect_on_add, std::size_t buffer_size)
      : event_handler(
            static_cast<io_events>(IO_IN | IO_OUT | IO_ET | IO_RDHUP)),
        m_buffer(buffer_size), m_last_end(nullptr), m_content_end(nullptr),
        m_read_hungup(false), m_wait_state(connect_on_add ? WAIT_CONN : NO_WAIT) {}

  void on_added(io_loop &loop,
                const std::shared_ptr<async_descriptor> &fd_ptr) override {
    auto &conn = static_cast<stream_connection &>(*fd_ptr);
    if (m_wait_state == WAIT_CONN) {
        if(conn.connect()) {
            m_wait_state = NO_WAIT;
            static_cast<subclass *>(this)->on_connect();
            on_io(loop,fd_ptr, true, true);
        }
    } else {
      static_cast<subclass *>(this)->on_accept();
      on_io(loop,fd_ptr, true, true);
    }
  }

  void on_io(io_loop &loop, const std::shared_ptr<async_descriptor> &fd_ptr,
             bool read, bool write) override {

    auto &conn = static_cast<stream_connection &>(*fd_ptr);
    auto subclass_ptr = static_cast<subclass *>(this);
    while(true) {
        if (m_wait_state == WAIT_SHUTDOWN) {
            loop.request_remove(fd_ptr);
            break;
        } else if (m_wait_state == WAIT_CONN && write) {
            if (conn.check_connect()) {
                m_wait_state = NO_WAIT;
                subclass_ptr->on_connect(loop, conn);
            }else{
                // if this is reached, the connection will timeout
                break;
            }
        } else if (m_wait_state == WAIT_WRITE && write) {
            if (this->send(conn)) {
                m_wait_state = NO_WAIT;
                subclass_ptr->on_sent(loop, conn);
            }else{
                // return to io loop, when send task can not be completed
                break;
            }
        } else if (m_wait_state == WAIT_READ && read) {
            if (this->receive(conn)) {
                m_wait_state = NO_WAIT;
                // call higher protocol handler and passing the receive buffer
                subclass_ptr->on_received(loop, conn, m_buffer.data(),
                                          m_content_end - m_buffer.data());
            } else if (m_read_hungup) {
                // when still waiting for input data but read hung up was detected
                // the socket will wait until it timeouts
                loop.request_remove(fd_ptr);
                break;
            } else {
                // return to io loop, when recv task can not be completed
                break;
            }
        }
    }
  }

  void on_read_hungup(io_loop &loop,
                      const std::shared_ptr<async_descriptor> &fd_ptr) override{
    m_read_hungup = true;
  }

protected:

  bool is_read_hungup() const { return m_read_hungup; }

  void recv_after_return() {
    if(m_read_hungup) {
      throw std::runtime_error("Try to read from socket after read hung-up was detected.");
    }
      m_content_end = m_buffer.data();
      m_wait_state = WAIT_READ;
  }

  void send_after_return(std::vector<char>& data){
      std::swap(data, m_buffer);
      m_last_end = m_buffer.begin();
      m_content_end = m_last_end + m_buffer.size();
      m_wait_state = WAIT_WRITE;
  }

  void shutdown_after_return(){
     m_wait_state = WAIT_SHUTDOWN;
  }

private:

  bool receive(stream_connection &conn) {
    bool finished = false;
    char *begin = m_buffer.data();
    char *end = begin + m_buffer.size();
      m_content_end = conn.read(begin, end);
    if (m_content_end != begin) {
      if (m_content_end == nullptr){
          m_read_hungup = true;
        }
      finished = true;
    }

    return finished;
  }

  bool send(stream_connection &conn) {
    bool finished = false;
    m_last_end = conn.write(m_last_end, m_content_end);
    if(m_last_end == m_content_end){
        finished = true;
    }
    return finished;
  }

  std::vector<char> m_buffer;
  const char *m_last_end, *m_content_end;
  bool m_read_hungup;
  wait_state m_wait_state;
};


} // namespace rocket
#endif //ROCKET_SOCKET_HPP
