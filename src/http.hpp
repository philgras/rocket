#ifndef ROCKET_HTTP_HPP
#define ROCKET_HTTP_HPP

#include "http-parser/http_parser.h"
#include "socket.hpp"

#include <string>
#include <array>
#include <map>
#include <exception>
#include <algorithm>

#include <cstring>
#include <cstdio>

namespace rocket {

    class http_message {

    public:

        using header_map = std::map<std::string, std::string>;

        short get_version_major() const {
            return m_version_major;
        }

        void set_version_major(short version_major) {
            m_version_major = version_major;
        }

        short get_version_minor() const {
            return m_version_minor;
        }

        void set_version_minor(short version_minor) {
            m_version_minor = version_minor;
        }

        const std::string &get_header(const std::string &field) const {
            return m_headers.at(field);
        }

        template<typename String>
        void set_header(const std::string &field, String &&value) {
            m_headers[field] = std::forward<String>(value);
        }

        bool has_header(const std::string &field) const {
            return m_headers.find(field) != m_headers.cend();
        }

        const std::string &get_body() const {
            return m_body;
        }

        template<typename String>
        void set_body(String &&body) {
            m_body.assign(std::forward<String>(body));
            this->set_header("Content-Length", std::to_string(m_body.size()));
        }

        void clear() {
            for (auto &pair : m_headers) {
                pair.second.clear();
            }
            m_body.clear();
        }

        const header_map &get_headers() const {
            return m_headers;
        }

    private:
        short m_version_major = 1;
        short m_version_minor = 1;
        header_map m_headers;
        std::string m_body;
    };


    class Url {

    public:

        Url(std::string url_string, bool is_connect = false) :
                m_url_string(std::move(url_string)), m_fields() {
            ::http_parser_url url_parser;
            ::http_parser_url_init(&url_parser);

            const char* url_cstr = m_url_string.c_str();
            int rv = http_parser_parse_url(url_cstr,
                                           m_url_string.size(),
                                           is_connect, &url_parser);
            if (rv != 0){
                throw std::runtime_error("Error while parsing url string");
            }

            for (auto field : {UF_SCHEMA, UF_HOST, UF_PORT, UF_PATH,
                               UF_QUERY, UF_FRAGMENT, UF_USERINFO}){
                if(1u<<field & url_parser.field_set){
                    const char* begin = url_cstr + url_parser.field_data[field].off;
                    m_fields[field].assign(begin, url_parser.field_data[field].len);
                }
            }

        }

        const std::string& get_schema() const { return m_fields[UF_SCHEMA]; }
        const std::string& get_host() const { return m_fields[UF_HOST]; }
        const std::string& get_port() const { return m_fields[UF_PORT]; }
        const std::string& get_path() const { return m_fields[UF_PATH]; }
        const std::string& get_query() const { return m_fields[UF_QUERY]; }
        const std::string& get_fragment() const { return m_fields[UF_FRAGMENT]; }
        const std::string& get_userinfo() const { return m_fields[UF_USERINFO]; }

    private:
        std::string m_url_string;
        std::string m_fields[UF_MAX];

    };


    using http_method = ::http_method;
    using http_status = ::http_status;

    class http_request : public http_message {

    public:

        http_method get_method() const {
            return m_method;
        }

        const char *get_method_str() const {
            return ::http_method_str(m_method);
        }

        void set_method(http_method method) {
            m_method = method;
        }

        const std::string &get_url_str() const {
            return m_url_string;
        }

        template<typename String>
        void set_url_str(String &&url_string) {
            m_url_string = std::forward<String>(url_string);
        }

    private:
        http_method m_method = ::HTTP_GET;
        std::string m_url_string;
    };

    class http_response : public http_message {
    public:

        http_status get_status() const {
            return m_status;
        }

        const char *get_status_str() const {
            return ::http_status_str(m_status);
        }

        void set_status(http_status status) {
            m_status = status;
        }

    private:
        http_status m_status = ::HTTP_STATUS_OK;
    };


    class http_parser {

    public:

        http_parser() : m_internal_parser(), m_settings(), m_message(nullptr),
                        m_url(), m_field(), m_value(), m_finished(false) {

            ::http_parser_settings_init(&m_settings);
            m_settings.on_url = on_url;
            m_settings.on_header_field = on_header_field;
            m_settings.on_header_value = on_header_value;
            m_settings.on_body = on_body;
            m_settings.on_message_complete = on_message_complete;
        }

        void start(http_response &response) {
            m_message = &response;
            ::http_parser_init(&m_internal_parser, ::HTTP_RESPONSE);
            m_internal_parser.data = this;
            m_settings.on_headers_complete = on_response_headers_complete;
            this->clear_all();
        }

        void start(http_request &request) {
            m_message = &request;
            ::http_parser_init(&m_internal_parser, ::HTTP_REQUEST);
            m_internal_parser.data = this;
            m_settings.on_headers_complete = on_request_headers_complete;
            this->clear_all();
        }

        const char *next(const char *begin, const char *end) {
            auto len = std::distance(begin, end);
            auto nread = ::http_parser_execute(&m_internal_parser, &m_settings,
                                               begin, len);

            if (nread != len) {
                throw std::runtime_error("Error while parsing http message");
            }

            return begin + nread;
        }

        bool done() const { return m_finished; }

    private:

        void clear_all() {
            m_url.clear();
            m_field.clear();
            m_value.clear();
            m_body.clear();
            m_finished = false;
        }


        static int on_url(::http_parser *internal_parser, const char *data, size_t size) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            parser.m_url.append(data, size);
            return 0;
        }

        static int on_header_field(::http_parser *internal_parser, const char *data, size_t size) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            if (!parser.m_value.empty()) {
                parser.m_message->set_header(parser.m_field, parser.m_value);
                parser.m_field.clear();
                parser.m_value.clear();
            }
            parser.m_field.append(data, size);
            return 0;
        }

        static int on_header_value(::http_parser *internal_parser, const char *data, size_t size) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            parser.m_value.append(data, size);
            return 0;
        }

        static int on_headers_complete(::http_parser *internal_parser) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            if (!parser.m_value.empty()) {
                parser.m_message->set_header(parser.m_field, parser.m_value);
                parser.m_field.clear();
                parser.m_value.clear();
            }
            parser.m_message->set_version_major(internal_parser->http_major);
            parser.m_message->set_version_minor(internal_parser->http_minor);
            return 0;
        }

        static int on_response_headers_complete(::http_parser *internal_parser) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            auto &response = *static_cast<http_response *>(parser.m_message);
            response.set_status(static_cast<http_status >(internal_parser->status_code));
            return on_headers_complete(internal_parser);
        }

        static int on_request_headers_complete(::http_parser *internal_parser) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            auto &request = *static_cast<http_request *>(parser.m_message);
            request.set_method(static_cast<http_method>(internal_parser->method));
            request.set_url_str(parser.m_url);
            parser.m_url.clear();
            return on_headers_complete(internal_parser);
        }

        static int on_body(::http_parser *internal_parser, const char *data, size_t size) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            parser.m_body.append(data, size);
            return 0;
        }

        static int on_message_complete(::http_parser *internal_parser) {
            auto &parser = *static_cast<http_parser *>(internal_parser->data);
            parser.m_message->set_body(std::move(parser.m_body));
            parser.m_body = "";
            parser.m_finished = true;
            return 0;
        }

        ::http_parser m_internal_parser;
        ::http_parser_settings m_settings;
        http_message *m_message;
        std::string m_url;
        std::string m_field;
        std::string m_value;
        std::string m_body;
        bool m_finished;

    };

    class http_stream {

    public:

        void start(const http_request &request) {

            std::array<char, 32> version_buffer;
            const char *method;
            size_t nversion, nmethod, nurl;

            this->reset_fields();
            m_message = &request;

            nversion = insert_version(version_buffer.data(), version_buffer.size(),
                                      request.get_version_major(),
                                      request.get_version_minor());
            method = request.get_method_str();
            nmethod = std::strlen(method);
            nurl = request.get_url_str().size();

            // all lenghts + 2 spaces
            // m_status_line.reserve(nversion + nmethod + nurl + 2);

            m_status_line.insert(m_status_line.cend(), method, method + nmethod);
            m_status_line.push_back(' ');
            m_status_line.insert(m_status_line.cend(),
                                 request.get_url_str().cbegin(),
                                 request.get_url_str().cend());
            m_status_line.push_back(' ');
            m_status_line.insert(m_status_line.cend(),
                                 version_buffer.data(),
                                 version_buffer.data() + nversion);

            m_current_data_begin = m_status_line.data();
            m_current_data_end = m_current_data_begin + m_status_line.size();
            m_separator = LINE_SEP;
        }

        void start(const http_response &response) {
            std::array<char, 32> version_buffer;
            std::array<char, 16> status_buffer;
            const char *status_message;
            size_t nversion, nstatus, nstatus_message;

            this->reset_fields();
            m_message = &response;

            nversion = insert_version(version_buffer.data(), version_buffer.size(),
                                      response.get_version_major(),
                                      response.get_version_minor());

            nstatus = insert_status_code(status_buffer.data(), status_buffer.size(),
                                         static_cast<int>(response.get_status()));

            status_message = response.get_status_str();
            nstatus_message = std::strlen(status_message);

            m_status_line.insert(m_status_line.cend(),
                                 version_buffer.data(),
                                 version_buffer.data() + nversion);
            m_status_line.push_back(' ');
            m_status_line.insert(m_status_line.cend(),
                                 status_buffer.data(),
                                 status_buffer.data() + nstatus);
            m_status_line.push_back(' ');
            m_status_line.insert(m_status_line.cend(),
                                 status_message,
                                 status_message + nstatus_message);

            m_current_data_begin = m_status_line.data();
            m_current_data_end = m_current_data_begin + m_status_line.size();
            m_separator = LINE_SEP;
        }

        char *next(char *begin, char *end) {

            while (begin != end) {
                begin = this->copy_current(begin, end);

                // determine if current data has been written
                if (m_current_data_begin == m_current_data_end) {
                    if (m_separator) {
                        // if a separator is set, send it first
                        this->set_current(m_separator, 2);
                        m_separator = nullptr;
                    } else {
                        // if no separator needs to be sent, continue
                        if (!m_finished_statusline) {
                            // this branch is only entered once
                            m_finished_statusline = true;
                            m_current_header = m_message->get_headers().cbegin();
                            if (m_current_header == m_message->get_headers().cend()) {
                                // headers finished
                                m_finished_headers = true;
                                this->set_current(LINE_SEP, 2);
                            } else {
                                this->set_current(m_current_header->first);
                                m_current_is_field = true;
                                m_separator = HEADER_SEP;
                            }
                        } else if (!m_finished_headers) {
                            if (m_current_is_field) {
                                m_current_is_field = false;
                                this->set_current(m_current_header->second);
                                m_separator = LINE_SEP;
                            } else {
                                m_current_is_field = true;
                                ++m_current_header;
                                if (m_current_header == m_message->get_headers().cend()) {
                                    // headers finished
                                    m_finished_headers = true;
                                    this->set_current(LINE_SEP, 2);
                                } else {
                                    this->set_current(m_current_header->first);
                                    m_separator = HEADER_SEP;
                                }
                            }
                        } else {
                            if (m_body_started) {
                                m_finished_body = true;
                                break;
                            } else {
                                this->set_current(m_message->get_body());
                                m_body_started = true;
                            }
                        }
                    }
                }
            }

            return begin;
        }

        bool done() const { return m_finished_statusline && m_finished_headers && m_finished_body; }

    private:

        using header_iter = typename http_message::header_map::const_iterator;

        static constexpr const char *HEADER_SEP = ": ";
        static constexpr const char *LINE_SEP = "\r\n";

        static size_t insert_version(char *buffer, size_t bufflen, short major, short minor) {
            size_t bytes_written = std::snprintf(buffer, bufflen, "HTTP/%d.%d", major, minor);
            if (bytes_written >= bufflen - 1 || bytes_written <= 0) {
                throw std::runtime_error("Error while parsing http version codes");
            }

            return bytes_written;
        }

        static size_t insert_status_code(char *buffer, size_t bufflen, int status_code) {
            size_t bytes_written = std::snprintf(buffer, bufflen, "%d", status_code);
            if (bytes_written >= bufflen - 1 || bytes_written <= 0) {
                throw std::runtime_error("Error while parsing http status code");
            }

            return bytes_written;
        }

        char *copy_current(char *begin, char *end) {
            auto n = std::min(std::distance(begin, end),
                              std::distance(m_current_data_begin, m_current_data_end));
            auto last = std::copy_n(m_current_data_begin, n, begin);
            m_current_data_begin += n;
            return last;
        }

        void set_current(const std::string &str) {
            m_current_data_begin = str.data();
            m_current_data_end = m_current_data_begin + str.size();
        }

        void set_current(const char *str, int len) {
            m_current_data_begin = str;
            m_current_data_end = str + len;
        }

        void reset_fields() {
            m_status_line.clear();
            m_finished_statusline = m_finished_headers = m_finished_body = m_body_started = false;
            m_current_data_begin = m_current_data_end = m_separator = nullptr;
            m_message = nullptr;
        }

        const http_message *m_message;

        const char *m_current_data_begin;
        const char *m_current_data_end;
        const char *m_separator;

        std::vector<char> m_status_line;
        header_iter m_current_header;
        bool m_finished_statusline;
        bool m_current_is_field;
        bool m_finished_headers;
        bool m_finished_body;
        bool m_body_started;
    };

    struct http_protocol {
        using server_message_type = http_response;
        using client_message_type = http_request;
        using parser_type = http_parser;
        using stream_type = http_stream;
    };


    template<typename subclass>
    using http_request_handler = request_handler<subclass, http_protocol, stream_connection<subclass>>;

    template<typename subclass>
    using http_response_handler = response_handler<subclass, http_protocol, stream_connection<subclass>>;

}

#endif //ROCKET_HTTP_HPP
