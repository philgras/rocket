#ifndef ROCKET_LOOP_HPP
#define ROCKET_LOOP_HPP

#include "file_descriptor.hpp"

#include <unordered_map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <cstdint>

#include <sys/epoll.h>


namespace rocket {


enum io_events : uint32_t { 
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


class async_descriptor : public file_descriptor {

public:

    async_descriptor(int fd, io_events events)
        : file_descriptor(fd), m_events(events){ }

    virtual void on_io_event(io_events events) = 0;

    io_events get_io_events() const { return m_events; }

private:

    io_events m_events;
    std::mutex m_mutex;

};


class io_loop {

public:

    io_loop(int max_ready_events, int wait_timeout);

    void add_file_descriptor(std::shared_ptr<async_descriptor>&); 

    void remove_file_descriptor(std::shared_ptr<async_descriptor>&);

    void start();

    void stop();

private:
    std::unordered_map<int, std::shared_ptr<async_descriptor>> registered_fds;
    std::shared_mutex m_mapmutex;
    file_descriptor epoll_fd;
    int max_ready_events;
    int wait_timeout;

};


}

#endif //ROCKET_LOOP_HPP
