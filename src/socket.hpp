#ifndef ROCKET_SOCKET_HPP
#define ROCKET_SOCKET_HPP

#include <file_descriptor.hpp>

#include <system_error>
#include <cerrno>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


namespace rocket {


    class address_iter {
    public:
        address_iter(const struct addrinfo *addr_ptr)
                : m_addr_ptr(addr_ptr) {}

        void next() {
            if (m_addr_ptr) {
                m_addr_ptr = m_addr_ptr->next;
            }
        }

        bool has_next() const {
            return m_addr_ptr != nullptr;
        }

        const sockaddr *get_sock_addr() const {
            return m_addr_ptr->ai_addr;
        }

        socklen_t get_addr_len() const {
            return m_addr_ptr->ai_addrlen;
        }

        int get_address_family() const {
            return m_addr_ptr->ai_family;
        }

        int get_protocol() const {
            return m_addr_ptr->ai_protocol;
        }

        intn get_socktype() const {
            return m_addr_ptr->ai_socktype;
        }

    private:
        const struct addrinfo *m_addr_ptr;

    };


    class address_info {
    public:
        address_info(const char *hostname, const char *service, int address_family = 0, int socket_type = 0,
                     int address_protocol = 0, int flags = 0) : m_res(nullptr) {

            struct addrinfo hints;
            int rc;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = address_family;
            hints.ai_socktype = socket_type;
            hints.ai_protocol = address_protocol;
            hints.ai_flags = flags;

            rc = ::getaddrinfo(ip, port, &hints, &m_res);
            if (rc != 0) {
                const char *error_str = ::gai_strerror(rc);
                throw std::runtime_error(error_str);
            }

        }

        address_iter iter() const {
            return address_iter(m_res);
        }

        void free() {
            if (m_res) {
                ::freeaddrinfo(m_ref);
            }
        }

        ~address_info() {
            free();
        }

    private:
        struct addrinfo *m_res;
    }

    class socket_descriptor : public async_descriptor {

    public:

        socket_descriptor(int address_family, int socket_type, int address_protocol,
                          const std::shared_ptr<rocket::event_handler> &handler,
                          std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : async_descriptor(INVALID_FD, handler, timeout) {

            m_fd = ::socket(address_family, socket_type | SOCK_NONBLOCK, address_protocol);
            if (m_fd == -1) {
                throw std::system_error(errno, std::system_category());
            }

        }

    protected:

        socket_descriptor(const std::shared_ptr<rocket::event_handler> &handler,
                          std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : async_descriptor(INVALID_FD, handler, timeout) {

        }

        void acquire(const address_iter& iter){

        }

    };

    class tcp_listener : public socket_descriptor {
    public:
        listener_socket(const char *service,
                        const std::shared_ptr<rocket::event_handler> &handler,
                        std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
                : socket_descriptor(handler, timeout) {

            address_info lookup(nullptr, service, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, AI_PASSIVE);
            for (auto iter = lookup.iter(); iter.has_next(); iter.next()) {

            }

        }

    };


    class tcp_socket : public socket_descriptor {
    public:
        tcp_socket(const char *hostname, const char *service,
                   const std::shared_ptr<rocket::event_handler> &handler,
                   std::chrono::milliseconds timeout = INFINITE_TIMEOUT)
    };


};


#endif //ROCKET_SOCKET_HPP
