#include "echo.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"
#include "socket.hpp"

#include <chrono>
#include <exception>
#include <iostream>
#include <thread>

struct echo_client_handler
    : rocket::client_handler<echo_client_handler, rocket::echo_protocol,
                             rocket::stream_connection<echo_client_handler>> {

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

struct echo_server_handler
    : rocket::server_handler<echo_server_handler, rocket::echo_protocol,
                             rocket::stream_connection<echo_server_handler>> {
  void on_request(const rocket::echo_message &request,
                  rocket::echo_message &response) {
    std::cout << "Request: " << request.get_content() << std::endl;
    response.set_content(request.get_content());
  }
};

using echo_client = rocket::stream_connection<echo_client_handler>;
using echo_server = rocket::default_stream_listener<echo_server_handler>;

int main(int nargs, char **vargs) {

  rocket::io_loop loop;
  std::chrono::milliseconds timeout(5000);
  auto hostaddr = rocket::address_info::tcp_bind("9090");
  auto remoteaddr = rocket::address_info::tcp_connect("localhost", "9090");
  auto connection = std::make_shared<echo_client>(
      remoteaddr.get_addr(), remoteaddr.get_addrlen(), timeout);
  auto server = std::make_shared<echo_server>(
      hostaddr.get_addr(), hostaddr.get_addrlen(), 10, timeout);

  loop.request_add(server);
  loop.request_add(connection);
  loop.start();
}
