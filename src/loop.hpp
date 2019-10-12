#ifndef ROCKET_LOOP_HPP
#define ROCKET_LOOP_HPP

#include "event.hpp"
#include "file_descriptor.hpp"
#include "sync_queue.hpp"
#include "notification.hpp"

#include <unordered_map>
#include <memory>
#include <utility>
#include <atomic>
#include <mutex>


namespace rocket {


    class io_loop {

    public:

        io_loop(int max_ready_events=48);

        io_loop(const io_loop &) = delete;

        io_loop operator=(const io_loop &) = delete;

        void start();

        void request_add(const std::shared_ptr<async_descriptor> &descriptor) {
            m_add_queue.push(descriptor);
            m_wakeup_notifier->write(1);
        }

        void request_removal(const std::shared_ptr<async_descriptor> &descriptor) {
            m_remove_queue.push(descriptor);
            m_wakeup_notifier->write(1);
        }

        void request_shutdown() {
            bool expected = false;
            if(m_request_shutdown.compare_exchange_strong(expected, true)){
                m_wakeup_notifier->write(1);
            }
        }

        void clear_requests() {
            m_add_queue.clear();
            m_remove_queue.clear();
            m_request_shutdown = false;
        }

    private:

        void add(const std::shared_ptr<async_descriptor> &);

        void remove(const std::shared_ptr<async_descriptor> &);

        int check_timeout();

        void call_handler(const std::shared_ptr<async_descriptor> &, io_events, lifecycle_events);

        bool is_registered(const std::shared_ptr<async_descriptor> & fd_ptr){
            return m_registered_fds.find(fd_ptr->get_fd()) != m_registered_fds.end();
        }

        file_descriptor m_epoll_fd;
        std::unordered_map<int, std::shared_ptr<async_descriptor>> m_registered_fds;
        sync_queue<std::shared_ptr<async_descriptor>> m_add_queue;   // queue to schedule add-tasks
        sync_queue<std::shared_ptr<async_descriptor>> m_remove_queue;  // queue to schedule remove-tasks

        int m_max_ready_events;

        std::shared_ptr<notify_descriptor> m_wakeup_notifier;
        std::atomic_bool m_request_shutdown;
        std::mutex m_start_mutex;

    };


}

#endif //ROCKET_LOOP_HPP
