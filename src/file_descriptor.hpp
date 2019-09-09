//
// Created by philgras on 04.09.19.
//

#ifndef ROCKET_FILE_DESCRIPTOR_HPP
#define ROCKET_FILE_DESCRIPTOR_HPP

#include <system_error>
#include <unistd.h>


namespace rocket {

class file_descriptor {

public:

    static constexpr int INVALID_FD = -1;

    explicit file_descriptor(int fd)
            : m_fd(fd) {}

    file_descriptor(const file_descriptor &) = delete;

    file_descriptor &operator=(const file_descriptor &) = delete;

    virtual ~file_descriptor() {
        silent_close();
    }

    int get_fd() const { return m_fd; }

    void close() {
        int rc;
        if (m_fd != INVALID_FD) {
            rc = ::close(m_fd);
            m_fd = INVALID_FD;

            if (rc) {
                throw std::system_error(rc, std::system_category());
            }
        }
    }


private:

    void silent_close() noexcept {
        if (m_fd != INVALID_FD) {
            ::close(m_fd);
        }
    }

    int m_fd;

};


class async_descriptor : public file_descriptor {
    
public:
    
    using file_descriptor::file_descriptor;
    
    virtual void on_io_event(uint32_t events) = 0;

};

}

#endif //ROCKET_FILE_DESCRIPTOR_HPP
