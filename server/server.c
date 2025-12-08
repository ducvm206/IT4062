#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "../config.h"
#include <pthread.h>

// Windows networking
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Windows threading + sleep
#include <windows.h>

// =============================================================================
// CONSTANTS
// =============================================================================

#define SERVER_PORT 8000
#define P2P_PORT 6000
#define BUFF_SIZE 8192
#define MAX_SHARED_FILES 256
#define MAX_CLIENTS 128
#define MAX_TOTAL_FILES 4096 // Maximum total files in system
#define BACKLOG 20
// =============================================================================
// STRUCTURES AND TYPE DEFINITIONS
// =============================================================================

// Structure for account information
typedef struct
{
    char username[64];
    char password[64];
} Account;

// Structure for session information
typedef struct
{
    int socket_fd;                  // Socket FD of client
    struct sockaddr_in client_addr; // Connection address
    int account_id;                 // User ID (mapped from Account list), -1 if not logged in
    char username[64];              // Username after login
    int is_active;                  // Is connected?
    int is_logged_in;               // Is logged in?
    time_t last_active;             // For timeout / alive check
    char recv_buffer[BUFF_SIZE];
    size_t buffer_len;
} Session;

// Information about a client's P2P connection details
typedef struct
{
    uint32_t client_id;  // Client's unique ID
    char ip_address[16]; // Client's IP
    int p2p_port;        // Client's P2P port
    int session_index;   // Index in sessions array
    int is_active;       // Is this connection active?
} ClientConnection;

// Server's file index entry
typedef struct
{
    char filename[256];    // File name
    uint32_t client_id;    // Owner ClientID
    char ip_address[16];   // Owner IP
    int port;              // Owner P2P port
    uint64_t filesize;     // File size (optional)
    time_t published_time; // When file was published
    int is_active;         // Is file still available?
} FileIndexEntry;

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

// Account management
Account accounts[MAX_CLIENTS];
int account_count = 0;
pthread_mutex_t account_mutex = PTHREAD_MUTEX_INITIALIZER;

// Session management
Session sessions[MAX_CLIENTS];
int session_count = 0;
pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Client connection management (for GETINFO mapping)
ClientConnection client_connections[MAX_CLIENTS];
int connection_count = 0;
pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;

// File index management
FileIndexEntry file_index[MAX_TOTAL_FILES];
int file_index_count = 0;
pthread_mutex_t file_index_mutex = PTHREAD_MUTEX_INITIALIZER;
// xử lý gửi toàn bộ dữ liệu qua socket
ssize_t send_all(SOCKET sock, const char *buf, size_t len)
{
    size_t total = 0;
    while (total < len)
    {
        ssize_t sent = send(sock, buf + total, (int)(len - total), 0);
        if (sent <= 0)
            return -1;
        total += sent;
    }
    return (ssize_t)total;
}
// tìm chuỗi "\r\n" trong buffer
ssize_t find_crlf(const char *buf, size_t len)
{
    if (len < 2)
        return -1;
    for (size_t i = 0; i + 1 < len; ++i)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return (ssize_t)i;
    }
    return -1;
}
// đọc dữ liệu từ socket và tách dòng
void *session_loop(void *arg)
{
    Session *session = (Session *)arg;
    int sockfd = session->socket_fd;
    session->buffer_len = 0;
    session->is_active = 1;
    session->is_logged_in = 0;
    session->account_id = -1;
    session->last_active = time(NULL);

    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &(session->client_addr.sin_addr), client_ip, sizeof(client_ip));
    printf("[INFO] New connection: socket=%d ip=%s port=%d\n", sockfd, client_ip, ntohs(session->client_addr.sin_port));

    send_response(sockfd, "100\r\n");

    while (session->is_active)
    {

        size_t cap = sizeof(session->recv_buffer);
        if (session->buffer_len >= cap - 1)
            break;

        size_t max_read = cap - session->buffer_len - 1;
        ssize_t avail = recv(sockfd, session->recv_buffer + session->buffer_len, max_read, 0);

        if (avail == 0)
        {
            printf("[INFO] Client disconnected gracefully: %s\n", client_ip);
            break;
        }
        else if (avail < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            { // chưa có dữ liệu.
                usleep(10 * 1000);
                continue;
            }
            if (errno == EINTR)
                continue; // bị gián đoạn
            perror("[ERROR] recv failed");
            break;
        }
        else
        {
            session->buffer_len += (size_t)avail;
            session->recv_buffer[session->buffer_len] = '\0';
            session->last_active = time(NULL);

            while (1)
            {
                ssize_t idx = find_crlf(session->recv_buffer, session->buffer_len);
                if (idx < 0)
                    break;

                size_t line_len = (size_t)idx; // xác định độ dài dòng hoàn chỉnh
                char *line = (char *)malloc(line_len + 1);
                if (!line)
                {
                    session->is_active = 0;
                    break;
                }

                memcpy(line, session->recv_buffer, line_len);
                line[line_len] = '\0';

                size_t remain = session->buffer_len - (line_len + 2);
                if (remain > 0)
                    memmove(session->recv_buffer, session->recv_buffer + line_len + 2, remain);

                session->buffer_len = remain;
                session->recv_buffer[session->buffer_len] = '\0';

                process_request(session, line);
                free(line);

                if (!session->is_active)
                    break;
            }
        }
    }

    cleanup_session(session);
    close(sockfd);
    session->is_active = 0;

    printf("[INFO] Session thread exiting for socket=%d\n", sockfd);
    return NULL;
}
// =============================================================================
// MESSAGE HANDLING FUNCTIONS
// =============================================================================

// Send response to client
void send_response(int socket_fd, const char *response)
{
    send(socket_fd, response, strlen(response), 0);
}

void process_request(Session *session, char *request)
{
    // Remove trailing "\r\n"
    int len = strlen(request);
    if (len >= 2 && request[len - 2] == '\r' && request[len - 1] == '\n')
    {
        request[len - 2] = '\0';
    }

    char command[20];
    char argument[BUFF_SIZE];
    memset(argument, 0, sizeof(argument));

    // Parse command
    if (sscanf(request, "%s %[^\r\n]", command, argument) < 1)
    {
        send_response(session->socket_fd, "300\r\n");
        return;
    }

    // Handle REGISTER command
    if (strcmp(command, "REGISTER") == 0)
    {
        char username[64], password[64];

        // Parse arguments
        if (sscanf(argument, "%s %s", username, password) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Check password length (minimum 6 characters)
        if (strlen(password) < 6)
        {
            send_response(session->socket_fd, "400\r\n");
            return;
        }

        // Check if username already exists
        pthread_mutex_lock(&account_mutex);
        for (int i = 0; i < account_count; i++)
        {
            if (strcmp(accounts[i].username, username) == 0)
            {
                pthread_mutex_unlock(&account_mutex);
                send_response(session->socket_fd, "400\r\n");
                return;
            }
        }

        // Register successful
        strcpy(accounts[account_count].username, username);
        strcpy(accounts[account_count].password, password);
        account_count++;
        pthread_mutex_unlock(&account_mutex);

        send_response(session->socket_fd, "101\r\n");
        printf("[INFO] User registered: %s\n", username);
    }

    // Handle LOGIN command
    else if (strcmp(command, "LOGIN") == 0)
    {
        char username[64], password[64];

        // Parse arguments
        if (sscanf(argument, "%s %s", username, password) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Check if username and password match
        pthread_mutex_lock(&account_mutex);
        int found = 0;
        int account_id = -1;
        for (int i = 0; i < account_count; i++)
        {
            if (strcmp(accounts[i].username, username) == 0 &&
                strcmp(accounts[i].password, password) == 0)
            {
                found = 1;
                account_id = i;
                break;
            }
        }
        pthread_mutex_unlock(&account_mutex);

        if (!found)
        {
            send_response(session->socket_fd, "401\r\n");
            return;
        }

        // Login successful
        pthread_mutex_lock(&session_mutex);
        session->is_logged_in = 1;
        session->account_id = account_id;
        strcpy(session->username, username);
        pthread_mutex_unlock(&session_mutex);

        send_response(session->socket_fd, "102\r\n");
        printf("[INFO] User logged in: %s\n", username);
    }

    // Handle SENDINFO command
    else if (strcmp(command, "SENDINFO") == 0)
    {
        // Check if logged in
        if (!session->is_logged_in)
        {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        uint32_t client_id;
        int port;

        // Parse arguments: SENDINFO <ClientID> <Port>
        if (sscanf(argument, "%u %d", &client_id, &port) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Get client IP from session
        char client_ip[16];
        inet_ntop(AF_INET, &(session->client_addr.sin_addr), client_ip, sizeof(client_ip));

        // Store or update client connection info
        pthread_mutex_lock(&connection_mutex);

        int found = 0;
        for (int i = 0; i < connection_count; i++)
        {
            if (client_connections[i].client_id == client_id)
            {
                // Update existing connection
                strcpy(client_connections[i].ip_address, client_ip);
                client_connections[i].p2p_port = port;
                client_connections[i].is_active = 1;
                found = 1;
                break;
            }
        }

        if (!found && connection_count < MAX_CLIENTS)
        {
            // Add new connection
            client_connections[connection_count].client_id = client_id;
            strcpy(client_connections[connection_count].ip_address, client_ip);
            client_connections[connection_count].p2p_port = port;
            client_connections[connection_count].session_index = session - sessions;
            client_connections[connection_count].is_active = 1;
            connection_count++;
        }

        pthread_mutex_unlock(&connection_mutex);

        send_response(session->socket_fd, "103\r\n");
        printf("[INFO] Client info updated: ID=%u, IP=%s, Port=%d\n", client_id, client_ip, port);
    }

    // Handle PUBLISH command
    else if (strcmp(command, "PUBLISH") == 0)
    {
        // Check if logged in
        if (!session->is_logged_in)
        {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        uint32_t client_id;
        char filename[256];

        // Parse arguments: PUBLISH <ClientID> <filename>
        if (sscanf(argument, "%u %255s", &client_id, filename) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Check if filename contains invalid characters (; or \r\n)
        if (strchr(filename, ';') != NULL ||
            strchr(filename, '\r') != NULL ||
            strchr(filename, '\n') != NULL)
        {
            send_response(session->socket_fd, "402\r\n");
            return;
        }

        // Find client connection info
        pthread_mutex_lock(&connection_mutex);
        char client_ip[16] = {0};
        int client_port = 0;
        int found = 0;

        for (int i = 0; i < connection_count; i++)
        {
            if (client_connections[i].client_id == client_id &&
                client_connections[i].is_active)
            {
                strcpy(client_ip, client_connections[i].ip_address);
                client_port = client_connections[i].p2p_port;
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&connection_mutex);

        if (!found)
        {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        // Add file to index
        pthread_mutex_lock(&file_index_mutex);

        if (file_index_count < MAX_TOTAL_FILES)
        {
            strcpy(file_index[file_index_count].filename, filename);
            file_index[file_index_count].client_id = client_id;
            strcpy(file_index[file_index_count].ip_address, client_ip);
            file_index[file_index_count].port = client_port;
            file_index[file_index_count].filesize = 0; // Unknown size
            file_index[file_index_count].published_time = time(NULL);
            file_index[file_index_count].is_active = 1;
            file_index_count++;
        }

        pthread_mutex_unlock(&file_index_mutex);

        // Send response: 201 <ClientID> <Port>
        char response[128];
        snprintf(response, sizeof(response), "201 %u %d\r\n", client_id, client_port);
        send_response(session->socket_fd, response);
        printf("[INFO] File published: %s by ClientID=%u\n", filename, client_id);
    }

    // Handle UNPUBLISH command
    else if (strcmp(command, "UNPUBLISH") == 0)
    {
        // Check if logged in
        if (!session->is_logged_in)
        {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        char filename[256];

        // Parse arguments: UNPUBLISH <filename>
        if (sscanf(argument, "%255s", filename) != 1)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Find and remove file from index
        pthread_mutex_lock(&file_index_mutex);

        int found = 0;
        for (int i = 0; i < file_index_count; i++)
        {
            if (strcmp(file_index[i].filename, filename) == 0 &&
                file_index[i].is_active)
            {
                // Mark as inactive (soft delete)
                file_index[i].is_active = 0;
                found = 1;
                break;
            }
        }

        pthread_mutex_unlock(&file_index_mutex);

        if (!found)
        {
            send_response(session->socket_fd, "404\r\n");
            return;
        }

        send_response(session->socket_fd, "202\r\n");
        printf("[INFO] File unpublished: %s\n", filename);
    }

    // Handle SEARCH command
    else if (strcmp(command, "SEARCH") == 0)
    {
        char filename[256];

        // Parse arguments: SEARCH <filename>
        if (sscanf(argument, "%255s", filename) != 1)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        // Search for file in index
        pthread_mutex_lock(&file_index_mutex);

        char response[BUFF_SIZE];
        strcpy(response, "210\r\n");
        int peer_count = 0;

        for (int i = 0; i < file_index_count; i++)
        {
            if (strcmp(file_index[i].filename, filename) == 0 &&
                file_index[i].is_active)
            {
                // Add peer info to response
                char peer_line[128];
                snprintf(peer_line, sizeof(peer_line), "%s %d %u\r\n",
                         file_index[i].ip_address,
                         file_index[i].port,
                         file_index[i].client_id);
                strcat(response, peer_line);
                peer_count++;
            }
        }

        pthread_mutex_unlock(&file_index_mutex);

        if (peer_count == 0)
        {
            send_response(session->socket_fd, "404\r\n");
            return;
        }

        send_response(session->socket_fd, response);
        printf("[INFO] File search: %s - Found %d peers\n", filename, peer_count);
    }

    // Handle LOGOUT command
    else if (strcmp(command, "LOGOUT") == 0)
    {
        pthread_mutex_lock(&session_mutex);
        session->is_logged_in = 0;
        session->account_id = -1;
        pthread_mutex_unlock(&session_mutex);

        send_response(session->socket_fd, "104\r\n");
        printf("[INFO] User logged out: %s\n", session->username);
    }

    // Unknown command
    else
    {
        send_response(session->socket_fd, "300\r\n");
    }
}
int main()
{
    // Cài đặt cơ chế vào ra socket
    int listenfd;
    struct sockaddr_in server_addr, client_addr;
    int sin_size = sizeof(client_addr);
    pthread_t tid;
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(listenfd, BACKLOG) == -1)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Server listening on port %d\n", SERVER_PORT);
    while (1)
    {
        int new_sock = accept(listenfd, (struct sockaddr *)&client_addr, &sin_size);

        if (new_sock == -1)
        {
            perror("accept failed");
            continue;
        }

        // Lấy thông tin client
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);
        printf("[INFO] Accepted connection from %s:%d\n", client_ip, client_port);

        // Tìm slot trống
        pthread_mutex_lock(&session_mutex);
        int slot_idx = -1;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (!sessions[i].is_active)
            {
                slot_idx = i;
                break;
            }
        }
        pthread_mutex_unlock(&session_mutex);

        // Kiểm tra server đầy
        if (slot_idx == -1)
        {
            printf("[WARNING] Server full, rejecting connection\n");
            close(new_sock);
            continue;
        }

        // Khởi tạo session
        pthread_mutex_lock(&session_mutex);
        sessions[slot_idx].socket_fd = new_sock;
        sessions[slot_idx].client_addr = client_addr;
        sessions[slot_idx].is_active = 1;
        sessions[slot_idx].is_logged_in = 0;
        sessions[slot_idx].account_id = -1;
        sessions[slot_idx].buffer_len = 0;
        sessions[slot_idx].last_active = time(NULL);
        memset(sessions[slot_idx].username, 0, 64);
        memset(sessions[slot_idx].recv_buffer, 0, BUFF_SIZE);
        pthread_mutex_unlock(&session_mutex);

        // Tạo thread
        if (pthread_create(&tid, NULL, session_loop, (void *)&sessions[slot_idx]) != 0)
        {
            perror("pthread_create failed");

            pthread_mutex_lock(&session_mutex);
            sessions[slot_idx].is_active = 0;
            pthread_mutex_unlock(&session_mutex);

            close(new_sock);
            continue;
        }

        // Detach thread
        pthread_detach(tid);
        printf("[INFO] Thread created for slot %d\n", slot_idx);
    }
}