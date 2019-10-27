#include "loop.hpp"
#include "file_descriptor.hpp"

#include <iostream>
#include <thread>
#include <chrono>
#include <exception>

struct test_notificatio_handler
    : rocket::notification_handler<test_notificatio_handler> {
  void on_notification(rocket::io_loop &loop,
                       const std::shared_ptr<rocket::async_descriptor> &fd,
                       uint64_t message) {
    std::cout << "Received message: " << message << std::endl;
    if (message == 4) {
      // loop.request_shutdown();
    }
  }

  void
  on_timeout(rocket::io_loop &loop,
             const std::shared_ptr<rocket::async_descriptor> &fd_ptr) override {
    std::cout << "Timeout occured on " << fd_ptr->get_fd() << std::endl;
    throw std::runtime_error("Timout occured");
  }

  void
  on_added(rocket::io_loop &loop,
           const std::shared_ptr<rocket::async_descriptor> &fd_ptr) override {
    std::cout << "Added " << fd_ptr->get_fd() << std::endl;
  }

  void
  on_removed(rocket::io_loop &loop,
             const std::shared_ptr<rocket::async_descriptor> &fd_ptr) override {
    std::cout << "Removed " << fd_ptr->get_fd() << std::endl;
    fd_ptr->close();
  }

  void on_exception(rocket::io_loop &loop,
                    const std::shared_ptr<rocket::async_descriptor> &fd_ptr,
                    const std::exception_ptr &e_ptr) override {
    if (e_ptr) {
      try {
        std::rethrow_exception(e_ptr);
      } catch (const std::exception &e) {
        std::cerr << "Caught exception: " << e.what() << std::endl;
        loop.request_remove(fd_ptr);
      }
    }
  }
};

int main(int nargs, char **vargs) {

    rocket::io_loop loop;
    auto handler = std::make_shared<test_notificatio_handler>();
    auto test1 = std::make_shared<rocket::notify_descriptor>(
        handler, std::chrono::milliseconds(5000));
    auto test2 = std::make_shared<rocket::notify_descriptor>(
        handler, std::chrono::milliseconds(10));

    loop.request_add(test1);
    loop.request_add(test2);

    std::thread thread([&loop] { loop.start(); });

    test1->write(1);
    test2->write(2);

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    test1->write(12);
    try{
        test2->write(1L << 63);
    }catch (const std::exception& e){
        std::cerr<<"Caught exception while writing: "<<e.what()<<std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    loop.request_shutdown();

    thread.join();

}


