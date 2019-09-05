//
// Created by philgras on 04.09.19.
//

#ifndef LUNA_FILE_DESCRIPTOR_HPP
#define LUNA_FILE_DESCRIPTOR_HPP

#include <system_error>
#include <unistd.h>

namespace luna {

    class FileDescriptor {

    public:

        constexpr int INVALID_FD = -1;

        explicit FileDescriptor(int fd)
                : fd(fd) {}

        FileDescriptor(const FileDescriptor &) = delete;

        FileDescriptor &operator=(const FileDescriptor &) = delete;

        virtual ~FileDescriptor() {
            silent_close();
        }

        void on_io_event(uint32_t events){
            // to be filled by subclasses
        }

        int get_fd() const { return this->fd; }

        void close() {
            int rc;
            if (this->fd != INVALID_FD) {
                rc = ::close(this->fd);
                this->fd = INVALID_FD;

                if (rc) {
                    throw std::system_error(rc, std::system_category());
                }
            }
        }


    private:

        void silent_close() noexcept {
            if (this->fd != INVALID_FD) {
                ::close(this->fd);
            }
        }

        int fd;

    };

}

#endif //LUNA_FILE_DESCRIPTOR_HPP
