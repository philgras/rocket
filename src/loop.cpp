//
// Created by philgras on 04.09.19.
//

#include "loop.hpp"
#include "file_descriptor.hpp"

#include <system_error>
#include <cerrno>


namespace luna {

Loop::Loop(int max_ready_events, int wait_timeout)
: registered_fds(), epoll_fd(::epoll_create1(0)),
  max_ready_events(max_ready_events), wait_timeout(wait_timeout) {

    if(this->epoll_fd.get_fd() == FileDescriptor::INVALID_FD){
        throw std::system_error(errno, std::system_category());
    }

}

void Loop::add_file_descriptor(std::shared_ptr<FileDescriptor>& file_descriptor,
                               uint32_t events) {

    int rc;
    struct epoll_event config;
    config.events = events;
    config.data.fd = file_descriptor->get_fd();

    rc = epoll_ctl(this->epoll_fd.get_fd(), EPOLL_CTL_ADD, file_descriptor->get_fd(), &events);
    if(rc){
        throw std::system_error(errno, std::system_category());
    }

    this->registered_fds.emplace(file_descriptor->get_fd(), file_descriptor);

}

void Loop::remove_file_descriptor(const std::shared_ptr<FileDescriptor> & file_descriptor) {
    
    int rc;

    rc = epoll_ctl(this->epoll_fd.get_fd(), EPOLL_CTL_DEL, file_descriptor->get_fd(), nullptr); 
    if(rc){
        throw std::system_error(errno, std::system_category());
    }
    
    this->registered_fds.erase(file_descriptor->get_fd());

}

void Loop::start() {

    int rc;
    struct epoll_event ready_fds[max_events]; 

    while(true){
    
        rc = epoll_wait(this->epoll_fd.get_fd(), &ready_fds,
                        this->max_ready_events, this->wait_timeout);    
        if(rc == -1){
            throw std::system_error(errno, std::system_category());
        }

        for(int i = 0; i < rc; ++i){
            auto& fd_ptr = this->registered_fds[ready_fds[i].data.fd];
            fd_ptr->on_io_event(ready_fds[i].events]);
        }
     
    }

}

void Loop::stop() {}

}
