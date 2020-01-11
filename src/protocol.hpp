#ifndef ROCKET_PROTOCOL_HPP
#define ROCKET_PROTOCOL_HPP

namespace rocket {

    enum protocol_state {
        PS_WAIT_SEND,
        PS_WAIT_READ,
        PS_SHUTDOWN,
        PS_SLEEP
    };

    class protocol {
    public:

        virtual void on_connect() = 0;

        virtual void on_bytes_received() = 0;

        virtual void on_bytes_sent() = 0;

        void wait_for_read() {
            m_state = PS_WAIT_READ;
        }

        void wait_for_send() {
            m_state = PS_WAIT_SEND;
        }

        void wait_for_shutdown() {
            m_state = PS_SHUTDOWN;
        }

        const protocol_state get_state() const {
            return m_state;
        }

    protected:
        std::vector<char> m_buffer;

    private:
        protocol_state m_state;

    };

    class intermediate_protocol : public protocol {
    public:
        intermediate_protocol(protocol& next_protocol)
                : m_next_protocol(next_protocol) {}

    protected:
        protocol& m_next_protocol;
    };
}

#endif //ROCKET_PROTOCOL_HPP
