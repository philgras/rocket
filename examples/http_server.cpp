#include "http.hpp"
#include "file_descriptor.hpp"
#include "loop.hpp"
#include "socket.hpp"
#include "tls_handler.hpp"

#include <chrono>
#include <exception>
#include <iostream>
#include <thread>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

struct static_http_handler : rocket::http_response_handler<static_http_handler> {

    static_http_handler()
    : rocket::http_response_handler<static_http_handler>(1024) {}

    void on_request(const rocket::http_request &request,
                    rocket::http_response &response) {

        rocket::Url url(request.get_url_str());
        std::string path (".");
        path += url.get_path();

        if(request.get_method() == rocket::http_method::HTTP_GET &&
            fs::exists(path)){
            std::string line, file;
            response.set_status(rocket::http_status::HTTP_STATUS_OK);
            response.set_header("Content-Type", "text/html");
            std::ifstream f(path);
            while(std::getline(f, line)) {
                file += line;
            }
            response.set_body(file);
        }else{
            response.set_status(rocket::http_status::HTTP_STATUS_NOT_FOUND);
            response.set_header("Content-Type", "text/html");
            response.set_body(std::string("<h1>404 Not found</h1>"));
        }
    }
};

using http_server = rocket::default_stream_listener<static_http_handler>;

int main(int nargs, char **vargs) {

    rocket::io_loop loop;
    std::chrono::milliseconds server_timeout = rocket::INFINITE_TIMEOUT;
    std::chrono::milliseconds connection_timeout(5000);
    auto host_addr = rocket::address_info::tcp_bind("localhost", "9090");
    auto server = std::make_shared<http_server>(host_addr, 10, connection_timeout, server_timeout);

    loop.request_add(server);

    loop.start();

    return 0;
}



