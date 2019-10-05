#ifndef ROCKET_SYNC_QUEUE
#define ROCKET_SYNC_QUEUE

#include <list>
#include <mutex>

namespace rocket {


    template<typename T>
    class sync_queue {

    public:

        sync_queue() = default;

        void push(const T &element) {
            std::scoped_lock lock(m_mutex);
            m_queue.push_back(element);
        }

        bool pop_into(T &t_into) {
            std::scoped_lock lock(m_mutex);
            if (m_queue.empty()) {
                return false;
            } else {
                t_into = m_queue.front();
                m_queue.pop_front();
                return true;
            }
        }

        void clear() {
            std::scoped_lock lock(m_mutex);
            m_queue.clear();
        }

    private:

        std::list<T> m_queue;
        std::mutex m_mutex;

    };

}

#endif //ROCKET_SYNC_QUEUE
