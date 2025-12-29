// Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <pthread.h>
#include <gtk/gtk.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ui/interface.h"
#include "client.h"

// Constants
#define CONFIG_FILE "config.txt"
#define SERVER_PORT 8000
#define BUFFER_SIZE 8192
#define MAX_SHARED_FILES 256
#define MAX_PEERS 128

// Structs
typedef struct {
    char filename[256];
    int peer_count;
    PeerInfo peers[MAX_PEERS];
} SearchResult;

// Global client variable
ClientState g_client;
SharedFileList g_shared_files = {0};

// Print response message accordingly
void print_response_message(const char *response) {
    if (strncmp(response, "100", 3) == 0) {
        printf("[SUCCESS] Connected to server successfully\n");
    }
    else if (strncmp(response, "101", 3) == 0) {
        printf("[SUCCESS] Registered successfully\n");
    }
    else if (strncmp(response, "102", 3) == 0) {
        printf("[SUCCESS] Logged in successfully\n");
    }
    else if (strncmp(response, "103", 3) == 0) {
        printf("[SUCCESS] Client info sent successfully\n");
    }
    else if (strncmp(response, "104", 3) == 0) {
        printf("[SUCCESS] Logged out successfully\n");
    }
    else if (strncmp(response, "201", 3) == 0) {
        printf("[SUCCESS] File published for sharing successfully\n");
    }
    else if (strncmp(response, "202", 3) == 0) {
        printf("[SUCCESS] File removed from publishing successfully\n");
    }
    else if (strncmp(response, "210", 3) == 0) {
        printf("[SUCCESS] File found\n");
    }
    else if (strncmp(response, "211", 3) == 0) {
        printf("[SUCCESS] File download started\n");
    }
    else if (strncmp(response, "212", 3) == 0) {
        printf("[SUCCESS] File list retrieved\n");
    }
    else if (strncmp(response, "220", 3) == 0) {
        printf("[SUCCESS] File downloaded successfully\n");
    }
    else if (strncmp(response, "300", 3) == 0) {
        printf("[ERROR] Invalid message format\n");
    }
    else if (strncmp(response, "301", 3) == 0) {
        printf("[ERROR] Invalid port number\n");
    }
    else if (strncmp(response, "400", 3) == 0) {
        printf("[ERROR] Username already exists or invalid password\n");
    }
    else if (strncmp(response, "401", 3) == 0) {
        printf("[ERROR] Username does not exist or incorrect password\n");
    }
    else if (strncmp(response, "402", 3) == 0) {
        printf("[ERROR] Invalid filename\n");
    }
    else if (strncmp(response, "403", 3) == 0) {
        printf("[ERROR] User not logged in yet\n");
    }
    else if (strncmp(response, "404", 3) == 0) {
        printf("[ERROR] File not found\n");
    }
    else if (strncmp(response, "405", 3) == 0) {
        printf("[ERROR] Client ID already exists\n");
    }
    else if (strncmp(response, "410", 3) == 0) {
        printf("[ERROR] Cannot connect to peer / Download failed\n");
    }
    else if (strncmp(response, "500", 3) == 0) {
        printf("[ERROR] Server error\n");
    }
    else {
        printf("[RESPONSE] %s", response);
    }
}

static void ensure_shared_directory(void);

// Initiate client state
void init_client_state() {
    uint32_t saved_id = g_client.client_id;
    memset(&g_client, 0, sizeof(ClientState));
    g_client.p2p_port = 0;
    g_client.server_socket = -1;
    g_client.p2p_socket = -1;
    g_client.is_logged_in = 0;
    strcpy(g_client.shared_directory, "./shared");
    g_client.client_id = saved_id;
    ensure_shared_directory();
}

// Load files from index.txt
int load_shared_files() {
    FILE *fp = fopen("index.txt", "r");
    if (!fp) {
        printf("[INFO] index.txt not found, no files to share\n");
        return 0;
    }
    
    g_shared_files.count = 0;
    char line[768];

    while (fgets(line, sizeof(line), fp) && g_shared_files.count < MAX_SHARED_FILES) {
        line[strcspn(line, "\r\n")] = 0;
        
        char *token = strtok(line, "|");
        if (token) {
            strncpy(g_shared_files.files[g_shared_files.count].filename, token, 255);
            token = strtok(NULL, "|");
            if (token) {
                strncpy(g_shared_files.files[g_shared_files.count].filepath, token, 511);
                g_shared_files.count++;
            }
        }
    }

    fclose(fp);
    printf("[INFO] Loaded %d shared files from index.txt\n", g_shared_files.count);
    return g_shared_files.count;
}

// Add published file to index.txt
void add_to_local_index(const char *filename, const char *filepath) {
    FILE *fp = fopen("index.txt", "a");
    if (fp == NULL) {
        perror("[ERROR] Could not open index.txt for writing");
        return;
    }
    
    fprintf(fp, "%s|%s\n", filename, filepath);
    fclose(fp);
    
    load_shared_files();
}

// Remove file from index.txt
void remove_from_local_index(const char *filename) {
    FILE *fp = fopen("index.txt", "r");
    if (!fp) return;

    FILE *temp = fopen("index.tmp", "w");
    if (!temp) {
        fclose(fp);
        return;
    }

    char line[768];
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[768];
        strcpy(line_copy, line);
        
        char *token = strtok(line_copy, "|");
        if (token && strcmp(token, filename) != 0) {
            fputs(line, temp);
        }
    }

    fclose(fp);
    fclose(temp);
    
    remove("index.txt");
    rename("index.tmp", "index.txt");
    
    load_shared_files();
}

// Get local path from second half of index
int get_local_path(const char *filename, char *path_out) {
    for (int i = 0; i < g_shared_files.count; i++) {
        if (strcmp(g_shared_files.files[i].filename, filename) == 0) {
            strcpy(path_out, g_shared_files.files[i].filepath);
            return 1;
        }
    }
    return 0;
}

// Extract the first 3 digits of response => The code itself
int get_status_code(const char *response) {
    if (response == NULL || strlen(response) < 3) {
        return 0;
    }
    if (isdigit(response[0]) && isdigit(response[1]) && isdigit(response[2])) {
        return atoi(response);
    }
    return 0;
}

// Make sure that the ./shared directory is present for file sharing
static void ensure_shared_directory(void)
{
    struct stat st;
    if (stat(g_client.shared_directory, &st) == -1) {
        mkdir(g_client.shared_directory, 0755);
        printf("[INFO] Created shared directory: %s\n",
               g_client.shared_directory);
    }
}

// Copy published file to shared for easier tracking
static int copy_file_to_shared(const char *src_path,
                               const char *filename,
                               char *out_shared_path)
{
    char dst[512];
    snprintf(dst, sizeof(dst), "%s/%s",
             g_client.shared_directory, filename);

    FILE *fs = fopen(src_path, "rb");
    if (!fs) return -1;

    FILE *fd = fopen(dst, "wb");
    if (!fd) {
        fclose(fs);
        return -1;
    }

    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fs)) > 0) {
        fwrite(buf, 1, n, fd);
    }

    fclose(fs);
    fclose(fd);

    strcpy(out_shared_path, dst);
    return 0;
}

// Load client ID from config.txt
int load_client_id(uint32_t *client_id) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        return 0;
    }
    
    char line[256];
    *client_id = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        
        if (strncmp(line, "ClientID=", 9) == 0) {
            *client_id = strtoul(line + 9, NULL, 10);
            fclose(fp);
            return 1;
        }
    }
    
    fclose(fp);
    return 0;
}

// Save client id into config.txt
int save_client_id(uint32_t client_id) {
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        return 0;
    }
    
    fprintf(fp, "ClientID=%u\n", client_id);
    fclose(fp);
    return 1;
}

// Generate 32-bit random number
uint32_t generate_client_id() {
    srand(time(NULL));
    return (uint32_t)(rand() % 0xFFFFFFFF);
}

// LINE-BY-LINE PROCESSING
ssize_t send_all(int sock, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sock, buf + total, len - total, 0);
        if (sent <= 0) {
            return -1;
        }
        total += sent;
    }
    return (ssize_t)total;
}

ssize_t find_crlf(const char *buf, size_t len) {
    if (len < 2) return -1;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return (ssize_t)i;
    }
    return -1;
}

int read_line(int sock, char *line, int maxlen) {
    int i = 0;
    char c;

    while (i < maxlen - 1) {
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) return -1;

        if (c == '\r') continue;
        if (c == '\n') break;

        line[i++] = c;
    }

    line[i] = '\0';
    return i;
}

// Send command
int send_command(int sock, const char *cmd, char *response, int resp_size) {
    if (send_all(sock, cmd, strlen(cmd)) < 0) {
        perror("[ERROR] Failed to send command");
        return -1;
    }
    
    int read_status = read_line(sock, response, resp_size);
    
    if (read_status < 0) {
        return -1;
    } else if (read_status == 0) {
        return -1;
    }
    
    return 0;
}

// Handle SENDINFO
int handle_sendinfo(int sock) {
    char command[512];
    char response[BUFFER_SIZE];
    int status_code;

    snprintf(command, sizeof(command), "SENDINFO %u %d\r\n", 
             g_client.client_id, g_client.p2p_port);
    
    if (send_command(sock, command, response, sizeof(response)) < 0) {
        perror("[ERROR] Failed to send SENDINFO command or receive response");
        return -1;
    }
    
    print_response_message(response);
    status_code = get_status_code(response);
    
    if (status_code == 103) {
        return 0;
    } else {
        return -1;
    }
}

void send_client_info(void) {
    if (g_client.server_socket >= 0) {
        handle_sendinfo(g_client.server_socket);
    }
}

// Handle SEARCH
int handle_search(int sock, const char *filename, PeerInfo peers_out[], int max_peers) {
    memset(peers_out, 0, sizeof(PeerInfo) * max_peers);
    if (!g_client.is_logged_in) {
        printf("[ERROR] You must be logged in to search.\n");
        return -1;
    }
    
    char command[512];
    char line[BUFFER_SIZE];
    
    snprintf(command, sizeof(command), "SEARCH %s\r\n", filename);
    if (send_all(sock, command, strlen(command)) < 0) {
        perror("[ERROR] Failed to send SEARCH command");
        return -1;
    }
    
    if (read_line(sock, line, sizeof(line)) <= 0) {
        return -1;
    }

    if (strncmp(line, "210", 3) != 0) {
        print_response_message(line);
        return 0;
    }
    
    printf("[INFO] Peers holding '%s':\n", filename);

    int peer_count = 0;
    while (peer_count < max_peers) {
        int n = read_line(sock, line, sizeof(line));
        
        if (n < 0) return -1;
        
        if (strlen(line) == 0) {
            break;
        }
        
        if (sscanf(line, "%u %15s %d", &peers_out[peer_count].client_id, peers_out[peer_count].ip_address, &peers_out[peer_count].port) == 3) {
            peer_count++;
        }
    }
    return peer_count;
}

// Handle REGISTER
int handle_register(int sock, const char *username, const char *password) {
    char command[512];
    char response[BUFFER_SIZE];
    int status_code;
    
    if (g_client.is_logged_in) {
        return -1;
    }

    snprintf(command, sizeof(command), "REGISTER %s %s\r\n", username, password);
    
    if (send_command(sock, command, response, sizeof(response)) < 0) {
        perror("[ERROR] Failed to send REGISTER command or receive response");
        return -1;
    }
    
    print_response_message(response);
    status_code = get_status_code(response);

    if (status_code == 101) {
        return 0;
    } else {
        return -1;
    }
}

// Handle LOGIN
int handle_login(int sock, const char *username, const char *password) {
    char command[512];
    char response[BUFFER_SIZE];
    int status_code;

    if (g_client.is_logged_in) {
        return 0;
    }

    snprintf(command, sizeof(command),
             "LOGIN %s %s\r\n", username, password);

    if (send_command(sock, command, response, sizeof(response)) < 0) {
        perror("[ERROR] LOGIN failed");
        return -1;
    }

    print_response_message(response);
    status_code = get_status_code(response);

    if (status_code != 102) {
        return -1;
    }

    g_client.is_logged_in = 1;
    strncpy(g_client.username, username, sizeof(g_client.username) - 1);
    g_client.username[sizeof(g_client.username) - 1] = '\0';

    printf("[INFO] Login successful for user: %s\n", username);
    printf("[INFO] Sending client info to server...\n");
    printf("[INFO] ClientID: %u, P2P Port: %d\n",
           g_client.client_id, g_client.p2p_port);

    if (handle_sendinfo(sock) != 0) {
        printf("[ERROR] SENDINFO failed after LOGIN, rolling back login\n");
        g_client.is_logged_in = 0;
        memset(g_client.username, 0, sizeof(g_client.username));
        return -1;
    }

    return 0;
}

// Handle PUBLISH filename
int handle_publish(int sock, const char *filename, const char *filepath)
{
    char command[512];
    char response[BUFFER_SIZE];
    char shared_path[512];

    if (!g_client.is_logged_in)
        return -1;

    if (copy_file_to_shared(filepath, filename, shared_path) < 0) {
        printf("[ERROR] Failed to copy file to shared directory\n");
        return -1;
    }

    snprintf(command, sizeof(command),
             "PUBLISH %s\r\n",
             filename);

    if (send_command(sock, command, response, sizeof(response)) < 0)
        return -1;

    int status = get_status_code(response);

    if (status == 201) {
        add_to_local_index(filename, shared_path);
        print_response_message(response);
        return 0;
    }

    print_response_message(response);
    return -1;
}

// Handle UNPUBLISH
int handle_unpublish(int sock, const char *filename) {
    char command[512];
    char response[BUFFER_SIZE];

    if (!g_client.is_logged_in) return -1;

    snprintf(command, sizeof(command), "UNPUBLISH %s\r\n", filename);

    if (send_command(sock, command, response, sizeof(response)) < 0)
        return -1;

    int status = get_status_code(response);

    if (status == 200 || status == 202) {
        remove_from_local_index(filename);
        print_response_message(response);
        return 0;
    }

    print_response_message(response);
    return -1;
}

// LOGOUT function
void client_logout(void)
{
    char response[BUFFER_SIZE];

    if (!g_client.is_logged_in) {
        printf("[WARN] Client not logged in\n");
        return;
    }

    if (send_command(g_client.server_socket,
                     "LOGOUT\r\n",
                     response,
                     sizeof(response)) < 0) {
        printf("[ERROR] Failed to send LOGOUT\n");
        return;
    }

    print_response_message(response);

    int code = get_status_code(response);
    if (code == 104) {
        g_client.is_logged_in = 0;
        memset(g_client.username, 0, sizeof(g_client.username));
        printf("[INFO] Client logout completed\n");
    }
}

// Handle download (Downloader side)
int create_handshake(const char* peer_ip, int peer_port, const char* filename, long *filesize_out);
void handle_download(const char* peer_ip, int peer_port, const char* filename)
{
    long filesize;
    int sock = create_handshake(peer_ip, peer_port, filename, &filesize);
    if (sock < 0) {
        printf("[ERROR] Download failed\n");
        return;
    }

    char save_path[512];
    snprintf(save_path, sizeof(save_path), "%s/%s", g_client.shared_directory, filename);

    FILE *fp = fopen(save_path, "wb");
    if (!fp) {
        perror("fopen");
        close(sock);
        return;
    }

    char buf[BUFFER_SIZE];
    long received = 0;

    while (received < filesize) {
        ssize_t n = recv(sock, buf,
                         (filesize - received) < BUFFER_SIZE ?
                         (filesize - received) : BUFFER_SIZE,
                         0);
        if (n <= 0) break;

        fwrite(buf, 1, n, fp);
        received += n;
    }

    fclose(fp);
    close(sock);

    if (received == filesize)
        printf("[P2P] Download completed: %s\n", filename);
    else
        printf("[P2P] Download incomplete (%ld/%ld)\n", received, filesize);
}

// Handle incoming message from the downloader
void* handle_handshake(void* arg) {
    int peer_sock = *(int*)arg;
    free(arg);

    char line[BUFFER_SIZE];
    char cmd[16], filename[256];

    if (read_line(peer_sock, line, sizeof(line)) <= 0) {
        printf("[P2P] Failed to read request from peer\n");
        close(peer_sock);
        return NULL;
    }

    if (sscanf(line, "%15s %255s", cmd, filename) != 2 ||
        strcmp(cmd, "DOWNLOAD") != 0) {
        printf("[P2P] Invalid request format: %s\n", line);
        close(peer_sock);
        return NULL;
    }
    
    handle_download_request(peer_sock, filename);
    close(peer_sock);
    return NULL;
}

// Handle incoming download request
void handle_download_request(int peer_sock, const char* filename) {
    char real_path[512];
    
    load_shared_files();
    
    if (!get_local_path(filename, real_path)) {
        printf("[P2P-ERR] File not found in local index: %s\n", filename);
        const char *err = "FILE_NOT_FOUND\r\n";
        send_all(peer_sock, err, strlen(err));
        close(peer_sock);
        return;
    }
    
    struct stat st;
    if (stat(real_path, &st) != 0) {
        printf("[P2P-ERR] Cannot stat file: %s\n", real_path);
        const char *err = "FILE_NOT_FOUND\r\n";
        send_all(peer_sock, err, strlen(err));
        close(peer_sock);
        return;
    }
    
    char ok_msg[128];
    snprintf(ok_msg, sizeof(ok_msg), "FILE_OK %ld\r\n", st.st_size);
    send_all(peer_sock, ok_msg, strlen(ok_msg));
    
    char ack[32];
    if (read_line(peer_sock, ack, sizeof(ack)) <= 0 || strcmp(ack, "READY") != 0) {
        close(peer_sock);
        return;
    }
    
    FILE *fp = fopen(real_path, "rb");
    if (!fp) {
        close(peer_sock);
        return;
    }
    
    char buffer[BUFFER_SIZE];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (send_all(peer_sock, buffer, n) < 0) {
            break;
        }
    }
    
    fclose(fp);
    printf("[P2P] Sent file: %s (%ld bytes)\n", filename, st.st_size);
}


// Connect to a server
int connect_to_server(const char *server_ip, int server_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }

    char response[BUFFER_SIZE];
    int response_len = 0;

    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0 && FD_ISSET(sock, &read_fds)) {
        response_len = read_line(sock, response, sizeof(response));
    }

    if (response_len <= 0 || strncmp(response, "100", 3) != 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

void disconnect_from_server(int sock) {
    if (sock >= 0) {
        close(sock);
        printf("[INFO] Disconnected from server\n");
    }
}

// Initialize listener thread for client
void* initialize_listener() {
    int server_fd, *new_sock;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        return NULL;
    }
    
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = 0;

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(server_fd);
        return NULL;
    }
    
    getsockname(server_fd, (struct sockaddr *)&address, &addrlen);
    g_client.p2p_port = ntohs(address.sin_port);
    
    if (listen(server_fd, 10) < 0) {
        perror("[P2P] Listen failed");
        close(server_fd);
        return NULL;
    }

    printf("[P2P] Listener started on port %d\n", g_client.p2p_port);

    while (1) {
        new_sock = malloc(sizeof(int));
        *new_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (*new_sock >= 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, handle_handshake, (void*)new_sock);
            pthread_detach(tid);
        } else {
            free(new_sock);
        }
    }
    
    close(server_fd);
    return NULL;
}

// Create handshake to a client
int create_handshake(const char* peer_ip, int peer_port, const char* filename, long *filesize_out)
{
    int sock;
    struct sockaddr_in addr;
    char line[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "DOWNLOAD %s\r\n", filename);
    send_all(sock, cmd, strlen(cmd));
    
    if (read_line(sock, line, sizeof(line)) <= 0) {
        close(sock);
        return -1;
    }
    
    if (sscanf(line, "FILE_OK %ld", filesize_out) == 1) {
        send_all(sock, "READY\r\n", 7);
        return sock;
    }
    
    close(sock);
    return -1;
}

// MAIN
int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);
    
    init_client_state();

    if (!load_client_id(&g_client.client_id)) {
        g_client.client_id = generate_client_id();
        save_client_id(g_client.client_id);
        printf("[INFO] Generated new ClientID: %u\n", g_client.client_id);
    } else {
        printf("[INFO] Loaded existing ClientID: %u from config.txt\n", g_client.client_id);
    }
    
    pthread_t p2p_tid;
    pthread_create(&p2p_tid, NULL, initialize_listener, NULL);
    pthread_detach(p2p_tid);
    
    sleep(1);
    
    g_client.server_socket = connect_to_server("127.0.0.1", 8000);
    if (g_client.server_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to connect to server\n");
        return 1;
    }

    // Send client info upon connection
    handle_sendinfo(g_client.server_socket);
    
    g_client.is_logged_in = 0;

    show_auth_screen();

    gtk_main();
    return 0;
}