#ifndef ROCKET_TLS_HANDLER_HPP
#define ROCKET_TLS_HANDLER_HPP

#include "socket.hpp"

#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor_system.h>


namespace rocket {

    class client_credentials : public Botan::Credentials_Manager {
    public:
        client_credentials() {
            // Here we base trust on the system managed trusted CA list
            m_stores.push_back(new Botan::System_Certificate_Store);
        }

        std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
                const std::string &type,
                const std::string &context) override {
            // return a list of certificates of CAs we trust for tls server certificates
            // ownership of the pointers remains with Credentials_Manager
            return m_stores;
        }

        std::vector<Botan::X509_Certificate> cert_chain(
                const std::vector<std::string> &cert_key_types,
                const std::string &type,
                const std::string &context) override {
            // when using tls client authentication (optional), return
            // a certificate chain being sent to the tls server,
            // else an empty list
            return std::vector<Botan::X509_Certificate>();
        }

        Botan::Private_Key *private_key_for(const Botan::X509_Certificate &cert,
                                            const std::string &type,
                                            const std::string &context) override {
            // when returning a chain in cert_chain(), return the private key
            // associated with the leaf certificate here
            return nullptr;
        }

    private:
        std::vector<Botan::Certificate_Store *> m_stores;
    };

    template <typename subclass>
    class tls_client : public connection_handler<tls_client<subclass>>, public Botan::TLS::Callbacks {
    public:

        void on_connect(io_loop& loop, stream_connection& connection) override{
            Botan::AutoSeeded_RNG rng;
            Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
            client_credentials creds;
            Botan::TLS::Strict_Policy policy;
            auto& hostname = connection.get_hostname();
            auto port = connection.get_port();

            // open the tls connection
            m_client_ptr =
                    std::make_unique<Botan::TLS::Client>(*this, session_mgr, creds,
                                                         policy, rng,
                                                         Botan::TLS::Server_Information(hostname, port),
                                                         Botan::TLS::Protocol_Version::TLS_V12);

            this->io_cycle();
        }

        void on_received(io_loop& loop, stream_connection& connection, const char* data, size_t size) {
            m_client_ptr->received_data(reinterpret_cast<const uint8_t *>(data), size);
            this->io_cycle();
        }

        void on_sent(io_loop& loop, stream_connection& connection) {
            if(!m_client_ptr->is_active()){
                this->recv_after_return();
            }else{
                if (m_wait_state != WAIT_WRITE){

                }
                auto subclass_ptr = static_cast<subclass *>(this);
                subclass_ptr->on_sent();
            }
        }

        void tls_emit_data(const uint8_t data[], size_t size) override {
            auto begin = reinterpret_cast<const char*>(data);
            m_out_buffer.insert(m_out_buffer.end(), begin, begin + size);
        }

        void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override {
            auto begin = reinterpret_cast<const char*>(data);
            m_in_buffer.insert(m_in_buffer.end(), begin, begin + size);
        }

        void tls_alert(Botan::TLS::Alert alert) override {
            // handle a tls alert received from the tls server
        }

        bool tls_session_established(const Botan::TLS::Session &session) override {
            // the session with the tls server was established
            // return false to prevent the session from being cached, true to
            // cache the session in the configured session manager
            return false;
        }

    protected:
        void tls_recv_after_return() {
            m_wait_state = WAIT_READ;
        }

        void tls_send_after_return(const char* data, size_t size){
            m_client_ptr->send(reinterpret_cast<const uint8_t *>(data), size);
            m_wait_state = WAIT_WRITE;
        }

        void tls_shutdown_after_return() {
            m_wait_state = WAIT_SHUTDOWN;
        }

    private:

        void io_cycle(){
            while(true) {
                if (m_out_buffer.size() > 0) {
                    this->send_after_return(m_out_buffer);
                    m_out_buffer.clear();
                    return;
                }

                if (m_in_buffer.size() > 0) {
                    auto subclass_ptr = static_cast<subclass *>(this);
                    subclass_ptr->on_received(m_in_buffer.data(), m_in_buffer.size());
                    if (m_wait_state == WAIT_SHUTDOWN){
                        m_client_ptr->close();
                    } else if(m_wait_state == WAIT_READ){
                        this->recv_after_return();
                        return;
                    }
                    continue;
                }
                break;
            }
        }

        std::unique_ptr<Botan::TLS::Client> m_client_ptr;
        std::vector<char> m_in_buffer;
        std::vector<char> m_out_buffer;
        wait_state m_wait_state;
    };

}

#endif //ROCKET_TLS_HANDLER_HPP
