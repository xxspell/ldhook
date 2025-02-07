#include <dlfcn.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/inotify.h>

#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#define MAX_SSL_CONNECTIONS 100
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

typedef struct {
    SSL *ssl_ptr;
    unsigned char client_random[32];
    unsigned char master_secret[512];
    char sni[256];
    pid_t pid;
    pid_t tid;
    int socket_fd;
    char remote_ip[INET6_ADDRSTRLEN];
    int remote_port;
    time_t timestamp;
} SSLConnectionInfo;

typedef struct {
    void* base_addr;
    size_t size;
    char* pattern;
    size_t pattern_len;
} PatternSearchContext;

static FILE *keylog_file = NULL;
static FILE *debug_log = NULL;
static FILE *external_keylog_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t monitor_thread;
static int inotify_fd = -1;
static int watch_fd = -1;
static char *sslkeylog_path = NULL;

static SSLConnectionInfo ssl_connections[MAX_SSL_CONNECTIONS];
static int connection_count = 0;

void bin2hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        snprintf(hex + (i * 2), 3, "%02x", bin[i]);  // safer than sprintf
    }
}

void log_openssl_errors() {
    if (!debug_log) return;

    unsigned long err;
    char errbuf[256];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        fprintf(debug_log, "OpenSSL Error: %s\n", errbuf);
    }
    fflush(debug_log);
}

void extract_network_details(SSL *ssl, SSLConnectionInfo *conn_info) {
    int socket_fd = SSL_get_fd(ssl);
    conn_info->socket_fd = socket_fd;

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getpeername(socket_fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), conn_info->remote_ip, INET6_ADDRSTRLEN);
            conn_info->remote_port = ntohs(ipv4->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), conn_info->remote_ip, INET6_ADDRSTRLEN);
            conn_info->remote_port = ntohs(ipv6->sin6_port);
        }
    }
}

void log_tls_secrets(SSL *ssl) {
    if (!keylog_file || !ssl) return;

    pthread_mutex_lock(&log_mutex);

    if (connection_count >= MAX_SSL_CONNECTIONS) {
        connection_count = 0;
    }

    SSLConnectionInfo *conn_info = &ssl_connections[connection_count++];
    memset(conn_info, 0, sizeof(SSLConnectionInfo));
    conn_info->ssl_ptr = ssl;
    conn_info->pid = getpid();
    conn_info->tid = syscall(SYS_gettid);
    conn_info->timestamp = time(NULL);

    size_t random_len = SSL_get_client_random(ssl, conn_info->client_random, sizeof(conn_info->client_random));
    
    if (random_len == 0) {
        log_openssl_errors();
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    SSL_SESSION *session = SSL_get_session(ssl);
    if (!session) {
        log_openssl_errors();
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    size_t master_len = SSL_SESSION_get_master_key(session, conn_info->master_secret, sizeof(conn_info->master_secret));
    
    if (master_len > 0) {
        char random_hex[65];
        char master_hex[1025];
        
        bin2hex(conn_info->client_random, random_len, random_hex);
        bin2hex(conn_info->master_secret, master_len, master_hex);

        const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (sni) {
            snprintf(conn_info->sni, sizeof(conn_info->sni), "%s", sni); // safer
        }

        extract_network_details(ssl, conn_info);

        fprintf(keylog_file, "CLIENT_RANDOM %s %s\n", random_hex, master_hex);
        fprintf(keylog_file, "# PID: %d\n", conn_info->pid);
        fprintf(keylog_file, "# Thread: %d\n", conn_info->tid);
        
        if (conn_info->sni[0] != '\0') {
            fprintf(keylog_file, "# SNI: %s\n", conn_info->sni);
        }

        fprintf(keylog_file, "# Remote IP: %s\n", conn_info->remote_ip);
        fprintf(keylog_file, "# Remote Port: %d\n", conn_info->remote_port);
        
        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            fprintf(keylog_file, "# Cipher: %s\n", SSL_CIPHER_get_name(cipher));
        }

        if (debug_log) {
            fprintf(debug_log, "SSL Secret Extracted:\n");
            fprintf(debug_log, "  SSL Pointer: %p\n", (void*)ssl);
            fprintf(debug_log, "  Socket FD: %d\n", conn_info->socket_fd);
            fprintf(debug_log, "  Random Length: %zu\n", random_len);
            fprintf(debug_log, "  Master Key Length: %zu\n", master_len);
        }
        
        if (external_keylog_file) {
            fprintf(external_keylog_file, "CLIENT_RANDOM %s %s\n", random_hex, master_hex);
            fflush(external_keylog_file);
        }
        
        fflush(keylog_file);
        if (debug_log) fflush(debug_log);
    }

    pthread_mutex_unlock(&log_mutex);
}
