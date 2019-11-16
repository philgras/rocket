#include "http.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"
#include "socket.hpp"

#include <chrono>
#include <exception>
#include <iostream>
#include <thread>

struct test_client_handler
        : rocket::echo_stream_client_handler<test_client_handler> {

    test_client_handler()
            : rocket::echo_stream_client_handler<test_client_handler>(20) {}

    void on_connect(rocket::echo_message &request) { this->say_hello(request); }

    void on_response(const rocket::echo_message &response,
                     rocket::echo_message &request) {
        std::cout << "Response: " << response.get_content() << std::endl;
        if (response.get_content() != TEXT) {
            throw std::runtime_error("Invalid echo");
        }
        this->say_hello(request);
    }

    void say_hello(rocket::echo_message &msg) {
        if (++count <= MAX) {
            msg.set_content(TEXT);
        } else {
            this->shutdown();
        }
    }

    int count = 0;
    static constexpr int MAX = 5;
    static constexpr const char *TEXT = "hello#";
};

struct test_server_handler
        : rocket::echo_stream_server_handler<test_server_handler> {

    test_server_handler()
            : rocket::echo_stream_server_handler<test_server_handler>(1000) {}

    void on_request(const rocket::echo_message &request,
                    rocket::echo_message &response) {
        std::cout << "Request: " << request.get_content() << std::endl;
        response.set_content(request.get_content());
    }
};

using echo_client = rocket::stream_connection<test_client_handler>;
using echo_server = rocket::default_stream_listener<test_server_handler>;

int main(int nargs, char **vargs) {

    rocket::io_loop loop;
    std::chrono::milliseconds timeout = rocket::INFINITE_TIMEOUT; //(5000);
    auto host_addr = rocket::address_info::tcp_bind("localhost", "9090");
    auto remote_addr = rocket::address_info::tcp_connect("localhost", "9090");
    auto connection = std::make_shared<echo_client>(remote_addr, timeout);
    auto server = std::make_shared<echo_server>(host_addr, 10, timeout);

    loop.request_add(server);
    loop.request_add(connection);

    std::thread thread([&loop] { loop.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    loop.request_shutdown();
    thread.join();
}


