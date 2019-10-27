#ifndef ROCKET_ECHO_HPP
#define ROCKET_ECHO_HPP

#include <algorithm>
#include <string>
#include <utility>

namespace rocket {
class echo_message {

public:
  echo_message() = default;
  echo_message(const echo_message &) = default;
  ~echo_message() = default;

  template <typename T> void set_content(T &&content) {
    m_content = std::forward<T>(content);
  }
  const std::string &get_content() const { return m_content; }

  void clear() { m_content.clear(); }

private:
  std::string m_content;
};

class echo_parser {
public:
  echo_parser() = default;
  echo_parser(const echo_parser &) = default;
  ~echo_parser() = default;

  void start(echo_message &message) {
    m_state = false;
    m_message = &message;
    m_content.clear();
  }
  void next(const char *begin, const char *end) {
    m_content.append(begin, end);
    if (*(end - 1) == '#') {
      std::string tmp;
      std::swap(m_content, tmp);
      m_message->set_content(std::move(tmp));
      m_state = true;
    }
  }

  bool done() const { return m_state; }

private:
  echo_message *m_message = nullptr;
  std::string m_content;
  bool m_state = false;
};

class echo_stream {
public:
  echo_stream() = default;
  echo_stream(const echo_stream &) = default;
  ~echo_stream() = default;

  void start(const echo_message &message) {
    m_state = false;
    m_begin = message.get_content().cbegin();
    m_end = message.get_content().cend();
  }
  char *next(char *begin, char *end) {
    auto n = std::min(std::distance(begin, end), std::distance(m_begin, m_end));
    auto last = std::copy_n(m_begin, n, begin);
    m_begin += n;
    if (m_begin == m_end) {
      m_state = true;
    }
    return last;
  }

  bool done() const { return m_state; }

private:
  using itertype = typename std::string::const_iterator;

  itertype m_begin;
  itertype m_end;
  bool m_state = false;
};

struct echo_protocol {
  using server_message_type = echo_message;
  using client_message_type = echo_message;
  using parser_type = echo_parser;
  using stream_type = echo_stream;
};
}

#endif // ROCKET_ECHO_HPP
