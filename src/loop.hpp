//
// Created by philgras on 04.09.19.
//

#ifndef LUNA_LOOP_HPP
#define LUNA_LOOP_HPP

#include "file_descriptor.hpp"

#include <unordered_map>
#include <memory>
#include <cstdint>

#include <sys/epoll.h>

namespace luna {

enum Events : uint32_t { 
    IN = EPOLLIN,
    OUT = EPOLLOUT,
    RDHUP = EPOLLRDHUP,
    HUP = EPOLLHUP,
    ERR = EPOLLERR,
    PRI = EPOLLPRI,
//  ONESHOT = EPOLLONESHOT,
    ET = EPOLLET,
    EXCLUSIVE = EPOLLEXCLUSIVE
};

class Loop {

public:

    Loop(int max_ready_events, int wait_timeout);

    void add_file_descriptor(std::shared_ptr<FileDescriptor>&, uint32_t events);

    void remove_file_descriptor(std::shared_ptr<FileDescriptor>&);

    void start();

    void stop();

private:

    std::unordered_map<int, std::shared_ptr<FileDescriptor>> registered_fds;
    FileDescriptor epoll_fd;
    int max_ready_events;
    int wait_timeout;

};


}

#endif //LUNA_LOOP_HPP
