#include <iostream>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4443

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Error creating SSL context" << std::endl;
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int create_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    return sock;
}

void receive_messages(SSL* ssl) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break;
        std::cout << "\nServer: " << buffer << "\n> ";
        std::cout.flush();
    }
}

int main() {
    initialize_openssl();
    SSL_CTX* ctx = create_context();
    int server_fd = create_socket();

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);
    SSL_connect(ssl);

    std::cout << "Connected to TLS server!\n";

    std::thread recv_thread(receive_messages, ssl);

    std::string input;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);
        if (input == "exit") break;
        SSL_write(ssl, input.c_str(), input.size());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
