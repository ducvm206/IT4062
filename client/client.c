#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>      // For close(), sleep()
#include <fcntl.h>       // For file operations
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>      // For directory operations
#include <ctype.h>
#include <pthread.h>
#include <gtk/gtk.h>


// Linux networking headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Interface integration
#include "ui/interface.h"
#include "client.h"

// =============================================================================
// CONSTANTS
// =============================================================================

#define CONFIG_FILE "config.txt"
#define SERVER_PORT 8000
#define P2P_PORT 6000
#define BUFF_SIZE 8192
#define MAX_SHARED_FILES 256
#define MAX_PEERS 128
#define BUFFER_SIZE BUFF_SIZE

// =============================================================================
// STRUCTURES AND TYPE DEFINITIONS
// ============================================================================

// Search results for a file
typedef struct {
    char filename[256];              // File being searched
    int peer_count;                  // Number of peers with this file
    PeerInfo peers[MAX_PEERS];       // Array of peers
} SearchResult;

typedef struct {
    char buf[BUFF_SIZE];
    int len;
} LineBuffer;

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

ClientState g_client;                // Global client state
SharedFileList g_shared_files = {0}; // Global shared files list

// =============================================================================
// PROTOCOL RESPONSE FUNCTIONS
// =============================================================================

// Print response messages based on server codes
void print_response_message(const char *response) {
    // 1xx: Connection and authentication responses
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
    // 2xx: File operation responses
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
    // 3xx: Protocol errors
    else if (strncmp(response, "300", 3) == 0) {
        printf("[ERROR] Invalid message format\n");
    }
    else if (strncmp(response, "301", 3) == 0) {
        printf("[ERROR] Invalid port number\n");
    }
    // 4xx: Client errors
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
    // 5xx: Server errors
    else if (strncmp(response, "500", 3) == 0) {
        printf("[ERROR] Server error\n");
    }
    else {
        printf("[RESPONSE] %s", response);
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

static void ensure_shared_directory(void);
// Initialize client state
void init_client_state() {
    uint32_t saved_id = g_client.client_id;
    memset(&g_client, 0, sizeof(ClientState));

    //g_client.p2p_port = P2P_PORT;
    g_client.p2p_port = 0;  // Will be set by p2p_listener_thread
    g_client.server_socket = -1;
    g_client.p2p_socket = -1;
    g_client.is_logged_in = 0;
    strcpy(g_client.shared_directory, "./shared");
    g_client.client_id = saved_id;
    ensure_shared_directory();   
}

// Load shared files from index.txt
int load_shared_files() {
    // Implementation remains the same as it handles local file index.txt
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

// Add a new file entry to the local index.txt
// Format: filename|filepath
void add_to_local_index(const char *filename, const char *filepath) {
    // Open in append mode to add to the end of file
    FILE *fp = fopen("index.txt", "a");
    if (fp == NULL) {
        perror("[ERROR] Could not open index.txt for writing");
        return;
    }
    
    fprintf(fp, "%s|%s\n", filename, filepath);
    fclose(fp);
    
    // Reload memory structure
    load_shared_files();
}

// Remove a file entry from the local index.txt
void remove_from_local_index(const char *filename) {
    FILE *fp = fopen("index.txt", "r");
    if (!fp) return;

    FILE *temp = fopen("index.tmp", "w");
    if (!temp) {
        fclose(fp);
        return;
    }

    char line[768];
    char current_filename[256];
    
    // Read each line and copy to temp file EXCEPT the one to be removed
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
    
    // Replace old index with new index
    remove("index.txt");
    rename("index.tmp", "index.txt");
    
    // Reload memory structure
    load_shared_files();
}

// Find the local physical path of a shared filename
// Returns 1 if found, 0 otherwise
int get_local_path(const char *filename, char *path_out) {
    for (int i = 0; i < g_shared_files.count; i++) {
        if (strcmp(g_shared_files.files[i].filename, filename) == 0) {
            strcpy(path_out, g_shared_files.files[i].filepath);
            return 1;
        }
    }
    return 0;
}

// Extract status code integer from response string
int get_status_code(const char *response) {
    if (response == NULL || strlen(response) < 3) {
        return 0; // Invalid response
    }
    // Check if the first three characters are digits
    if (isdigit(response[0]) && isdigit(response[1]) && isdigit(response[2])) {
        // Convert the status code part to integer
        return atoi(response);
    }
    return 0;
}

static long get_filesize(const char *filepath)
{
    struct stat st;
    if (stat(filepath, &st) != 0)
        return -1;
    return st.st_size;
}

// Ensure shared directory exists, create if not
static void ensure_shared_directory(void)
{
    struct stat st;
    if (stat(g_client.shared_directory, &st) == -1) {
        mkdir(g_client.shared_directory, 0755);
        printf("[INFO] Created shared directory: %s\n",
               g_client.shared_directory);
    }
}

// Copy a file to the shared directory
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



// =============================================================================
// CONFIG FILE MANAGEMENT FUNCTIONS
// =============================================================================

// Load client ID from config.txt file
int load_client_id(uint32_t *client_id) {
    // Implementation remains the same
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

// Save client ID to config.txt file
int save_client_id(uint32_t client_id) {
    // Implementation remains the same
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        return 0;
    }
    
    fprintf(fp, "ClientID=%u\n", client_id);
    fclose(fp);
    return 1;
}

// Generate a random client ID
uint32_t generate_client_id() {
    srand(time(NULL));
    return (uint32_t)(rand() % 0xFFFFFFFF);
}

// =============================================================================
// SOCKET I/O UTILITY FUNCTIONS
// =============================================================================

// Send all data in buffer to socket
ssize_t send_all(int sock, const char *buf, size_t len) {
    // Implementation remains the same
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

// Find \r\n in buffer (Used by read_line)
ssize_t find_crlf(const char *buf, size_t len) {
    // Implementation remains the same
    if (len < 2) return -1;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return (ssize_t)i;
    }
    return -1;
}

// Read a complete line ending with \r\n from socket
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

int read_line_nb(int sock, LineBuffer *lb, char *out, int out_sz, int timeout_sec) {
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return 0;  // timeout hoặc error

    if (FD_ISSET(sock, &rfds)) {
        int n = recv(sock, lb->buf + lb->len,
                     sizeof(lb->buf) - lb->len - 1, 0);
        if (n <= 0) return -1;

        lb->len += n;
        lb->buf[lb->len] = '\0';

        char *crlf = strstr(lb->buf, "\r\n");
        if (!crlf) return 0;

        int line_len = crlf - lb->buf;
        if (line_len >= out_sz) line_len = out_sz - 1;

        memcpy(out, lb->buf, line_len);
        out[line_len] = '\0';

        int remain = lb->len - (line_len + 2);
        memmove(lb->buf, crlf + 2, remain);
        lb->len = remain;

        return 1;
    }

    return 0;
}


// Send command and wait for response (reads only the first line/status code)
// NOTE: This version is only for simple command/status responses (e.g., LOGIN, SENDINFO)
// For multi-line responses (e.g., SEARCH), use read_line directly.
int send_command(int sock, const char *cmd, char *response, int resp_size) {
    // 1. Send command
    if (send_all(sock, cmd, strlen(cmd)) < 0) {
        perror("[ERROR] Failed to send command");
        return -1;
    }
    
    // 2. Read the first line response
    int read_status = read_line(sock, response, resp_size);
    
    if (read_status < 0) {
        // Connection closed or buffer error
        return -1;
    } else if (read_status == 0) {
        // No data available (shouldn't happen in synchronous command mode)
        return -1;
    }
    
    // Success: response contains the status code line
    return 0;
}

// =============================================================================
// COMMAND HANDLING
// =============================================================================

// Handle SENDINFO command: send ClientID and P2P port to server
int handle_sendinfo(int sock) {
    char command[512];
    char response[BUFF_SIZE];
    int status_code;
    
    // Check if the user is logged in
    if (!g_client.is_logged_in) {
        // If not logged in, server should reject this, but client-side check is safer.
        return -1; 
    }

    // 1. Construct the SENDINFO command string
    snprintf(command, sizeof(command), "SENDINFO %u %d\r\n", 
             g_client.client_id, g_client.p2p_port);
    
    // 2. Send command and wait for status response
    if (send_command(sock, command, response, sizeof(response)) < 0) {
        perror("[ERROR] Failed to send SENDINFO command or receive response");
        return -1;
    }
    
    // 3. Print server response (using the dedicated function)
    print_response_message(response);
    status_code = get_status_code(response);
    
    if (status_code == 103) {
        return 0; // Success (Server status code 103 handles success message)
    } else {
        // Failure (Server status codes like 405 handle error messages)
        return -1; 
    }
}

// Wrapper function that auth.c can call
void send_client_info(void) {
    if (g_client.server_socket >= 0) {
        handle_sendinfo(g_client.server_socket);
    }
}


// Handle SEARCH command: search for a file and populate peer list
// Returns: Number of peers found (>= 0), or -1 if command failed.
int handle_search(int sock, const char *filename, PeerInfo peers_out[], int max_peers) {
    // Authorization check
    memset(peers_out, 0, sizeof(PeerInfo) * max_peers);
    if (!g_client.is_logged_in) {
        printf("[ERROR] You must be logged in to search.\n");
        return -1; 
    }
    
    char command[512];
    char line[BUFF_SIZE];
    
    // Send SEARCH command to the central server
    snprintf(command, sizeof(command), "SEARCH %s\r\n", filename);
    if (send_all(sock, command, strlen(command)) < 0) {
        perror("[ERROR] Failed to send SEARCH command");
        return -1;
    }
    
    // Read initial response (Expected "210 File Found")
    if (read_line(sock, line, sizeof(line)) <= 0) {
        return -1;
    }

    // Check if the server returned success code 210
    // Note: We use strncmp because the line might be "210 File Found"
    if (strncmp(line, "210", 3) != 0) {
        print_response_message(line); // Display error like 404 or 403
        return 0; 
    }
    
    printf("[INFO] Peers holding '%s':\n", filename);

    // Read peer list until a blank line is received
    int peer_count = 0;
    while (peer_count < max_peers) {
        int n = read_line(sock, line, sizeof(line));
        
        // Error or connection closed
        if (n < 0) return -1; 
        
        // A blank line (just \r\n) means the end of the peer list
        if (strlen(line) == 0) {
            break;
        }
        // Parse peer info: "ClientID IP Port"
        if (sscanf(line, "%u %15s %d", 
                    &peers_out[peer_count].client_id, 
                    peers_out[peer_count].ip_address, 
                    &peers_out[peer_count].port) == 3) {
            
            // Print for user to see the options
            printf("[%d] ID: %u | IP: %s | Port: %d\n", 
                    peer_count + 1,
                    peers_out[peer_count].client_id, 
                    peers_out[peer_count].ip_address, 
                    peers_out[peer_count].port);
            
            peer_count++;
        }
    }
    return peer_count;
}

// Handle REGISTER command: register a new user
// Returns: 0 on success, -1 on failure
int handle_register(int sock, const char *username, const char *password) {
    char command[512];
    char response[BUFF_SIZE];
    int status_code;
    
    // Check if the user is already logged in (Prevent unnecessary request)
    if (g_client.is_logged_in) {
        return -1; 
    }

    // 1. Construct the REGISTER command string
    snprintf(command, sizeof(command), "REGISTER %s %s\r\n", username, password);
    
    // 2. Send command and wait for status response
    if (send_command(sock, command, response, sizeof(response)) < 0) {
        perror("[ERROR] Failed to send REGISTER command or receive response");
        return -1;
    }
    
    // 3. Print server response (using the dedicated function)
    print_response_message(response);
    status_code = get_status_code(response);

    if (status_code == 101) {
        return 0; // Success (Server status code 101 handles success message)
    } else {
        // Failure (Server status codes like 400 handle error messages)
        return -1; 
    }
}

// Handle LOGIN command: log in an existing user
// Returns: 0 on success, -1 on failure
int handle_login(int sock, const char *username, const char *password) {
    char command[512];
    char response[BUFF_SIZE];
    int status_code;

    if (g_client.is_logged_in) {
        return 0;
    }

    /* 1. Send LOGIN */
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

    /* 2. LOGIN OK → update state */
    g_client.is_logged_in = 1;
    strncpy(g_client.username, username, sizeof(g_client.username) - 1);
    g_client.username[sizeof(g_client.username) - 1] = '\0';

    printf("[INFO] Login successful for user: %s\n", username);
    printf("[INFO] Sending client info to server...\n");
    printf("[INFO] ClientID: %u, P2P Port: %d\n",
           g_client.client_id, g_client.p2p_port);

    /* 3. SENDINFO bắt buộc */
    if (handle_sendinfo(sock) != 0) {
        printf("[ERROR] SENDINFO failed after LOGIN, rolling back login\n");
        g_client.is_logged_in = 0;
        memset(g_client.username, 0, sizeof(g_client.username));
        return -1;
    }

    return 0;
}

int handle_publish(int sock, const char *filename, const char *filepath)
{
    char command[512];
    char response[BUFF_SIZE];
    char shared_path[512];

    if (!g_client.is_logged_in)
        return -1;

    /* 🔒 Copy file vào ./shared */
    if (copy_file_to_shared(filepath, filename, shared_path) < 0) {
        printf("[ERROR] Failed to copy file to shared directory\n");
        return -1;
    }

    long filesize = get_filesize(shared_path);
    if (filesize < 0) {
        printf("[ERROR] Cannot get filesize for %s\n", shared_path);
        return -1;
    }

    snprintf(command, sizeof(command),
             "PUBLISH %s %ld\r\n",
             filename,
             filesize);

    if (send_command(sock, command, response, sizeof(response)) < 0)
        return -1;

    int status = get_status_code(response);

    if (status == 200 || status == 201) {
        add_to_local_index(filename, shared_path);
        print_response_message(response);
        return 0;
    }

    print_response_message(response);
    return -1;
}



// Handle UNPUBLISH command: Remove from server index AND local index.txt
int handle_unpublish(int sock, const char *filename) {
    char command[512];
    char response[BUFF_SIZE];

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

void client_logout(void)
{
    char response[BUFF_SIZE];

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

// Handle DOWNLOAD command: download file from peer
// Format: DOWNLOAD <filename> 
void handle_download(const char* peer_ip,
                     int peer_port,
                     const char* filename)
{
    long filesize;
    int sock = initiate_p2p_handshake(peer_ip, peer_port, filename, &filesize);
    if (sock < 0) {
        printf("[ERROR] Download failed\n");
        return;
    }

    char save_path[512];
    snprintf(save_path, sizeof(save_path),
            "%s/%s", g_client.shared_directory, filename);

    FILE *fp = fopen(save_path, "wb");
    if (!fp) {
        perror("fopen");
        close(sock);
        return;
    }

    char buf[BUFF_SIZE];
    long received = 0;

    while (received < filesize) {
        ssize_t n = recv(sock, buf,
                         (filesize - received) < BUFF_SIZE ?
                         (filesize - received) : BUFF_SIZE,
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

// This function streams the actual file data to the downloader
void handle_download_request(int peer_sock, const char* filename) {
    char real_path[512];
    
    // Reload shared files list to ensure it's current
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
    
    // Send FILE_OK with filesize
    char ok_msg[128];
    snprintf(ok_msg, sizeof(ok_msg), "FILE_OK %ld\r\n", st.st_size);
    send_all(peer_sock, ok_msg, strlen(ok_msg));
    
    // Wait for READY from downloader
    char ack[32];
    if (read_line(peer_sock, ack, sizeof(ack)) <= 0 || 
        strcmp(ack, "READY") != 0) {
        printf("[P2P-ERR] Missing or invalid READY acknowledgment\n");
        close(peer_sock);
        return;
    }
    
    // Now send the file
    FILE *fp = fopen(real_path, "rb");
    if (!fp) {
        perror("[P2P-ERR] fopen failed");
        close(peer_sock);
        return;
    }
    
    char buffer[BUFF_SIZE];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (send_all(peer_sock, buffer, n) < 0) {
            perror("[P2P-ERR] send failed");
            break;
        }
    }
    
    fclose(fp);
    printf("[P2P] Sent file: %s (%ld bytes)\n", filename, st.st_size);
}



// =============================================================================
// SERVER CONNECTION
// =============================================================================

// Connect to the main server
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

    /* 🔥 ĐỌC GREETING */
    char response[BUFF_SIZE];
    LineBuffer lb = {0};

    if (read_line_nb(sock, &lb, response, sizeof(response), 5) == 1) {
        print_response_message(response);  // 100
    }

    return sock;
}

// Disconnect from the main server
void disconnect_from_server(int sock) {
    if (sock >= 0) {
        close(sock);
        printf("[INFO] Disconnected from server\n");
    }
}

// =============================================================================
// P2P CONNECTION FUNCTIONS
// =============================================================================

// Handle incoming P2P connection requests (Uploader side) 
void* handle_p2p_request(void* arg) {
    int peer_sock = *(int*)arg;
    free(arg);

    char line[BUFF_SIZE];
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

    printf("[P2P] Download request for: %s\n", filename);
    
    // Use the unified handler that includes handshake
    handle_download_request(peer_sock, filename);
    close(peer_sock);
    return NULL;
}

/* Background thread to listen for P2P connections on a dynamic port */
void* p2p_listener_thread(void* arg) {
    int server_fd, *new_sock;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int opt = 1;

    // Create a TCP socket for listening
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[P2P] Socket creation failed");
        return NULL;
    }
    
    // Set socket options to allow immediate reuse of the port after restart
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available network interfaces
    address.sin_port = 0;  // KEY: Let OS assign random port automatically

    // Bind the socket to any available port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[P2P] Bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Get the actual port that was assigned by OS
    getsockname(server_fd, (struct sockaddr *)&address, &addrlen);
    g_client.p2p_port = ntohs(address.sin_port);
    
    // Start listening for incoming connections (queue up to 10 clients)
    if (listen(server_fd, 10) < 0) {
        perror("[P2P] Listen failed");
        close(server_fd);
        return NULL;
    }

    printf("[P2P] Listener started on port %d\n", g_client.p2p_port);

    while (1) {
        new_sock = malloc(sizeof(int));
        // Accept a new connection from a peer
        *new_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (*new_sock >= 0) {
            pthread_t tid;
            // Create a dedicated thread to handle each peer so the listener doesn't block
            pthread_create(&tid, NULL, handle_p2p_request, (void*)new_sock);
            pthread_detach(tid); // Automatically reclaim thread resources when finished
        } else {
            free(new_sock);
        }
    }
    
    close(server_fd);
    return NULL;
}

/* Connect to a peer and perform handshake for downloading (Downloader side) */
int initiate_p2p_handshake(const char* peer_ip,
                           int peer_port,
                           const char* filename,
                           long *filesize_out)
{
    int sock;
    struct sockaddr_in addr;
    char line[BUFF_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

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
    printf("[DEBUG] Connecting to %s:%d\n", peer_ip, peer_port);
    printf("[DEBUG] Sending: %s", cmd);
    
    if (read_line(sock, line, sizeof(line)) <= 0) {
        printf("[DEBUG] Failed to read response\n");
        close(sock);
        return -1;
    }
    
    printf("[DEBUG] Received: %s\n", line);
    
    if (sscanf(line, "FILE_OK %ld", filesize_out) == 1) {
        printf("[DEBUG] Sending READY\n");
        send_all(sock, "READY\r\n", 7);
        return sock;
    } else {
        printf("[DEBUG] Server responded with error: %s\n", line);
    }
    
    close(sock);
    return -1;
}

// Main program loop
int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);
    
    // Initialize client state
    init_client_state();

    // Load or generate client ID (port will be assigned dynamically)
    if (!load_client_id(&g_client.client_id)) {
        // If config.txt doesn't exist or doesn't contain ClientID
        g_client.client_id = generate_client_id();
        save_client_id(g_client.client_id);
        printf("[INFO] Generated new ClientID: %u\n", g_client.client_id);
    } else {
        printf("[INFO] Loaded existing ClientID: %u from config.txt\n", g_client.client_id);
    }
    
    // Start P2P listener thread (will assign random port)
    pthread_t p2p_tid;
    pthread_create(&p2p_tid, NULL, p2p_listener_thread, NULL);
    pthread_detach(p2p_tid);
    
    // Give P2P listener a moment to bind to a port
    sleep(1);
    
    // Connect to server
    g_client.server_socket = connect_to_server("127.0.0.1", 8000);
    if (g_client.server_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to connect to server\n");
        return 1;
    }
    
    g_client.is_logged_in = 0;

    show_auth_screen();

    gtk_main();
    return 0;
}