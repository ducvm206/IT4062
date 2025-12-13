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

// Linux networking headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
// =============================================================================

// Client state and connection information
typedef struct {
    uint32_t client_id;              // 32-bit ClientID from config.txt
    int p2p_port;                    // Port for P2P connections (6000)
    int server_socket;               // Socket connected to main server (int on Linux)
    int p2p_socket;                  // Socket for P2P listening (int on Linux)
    char username[64];               // Username after login
    int is_logged_in;                // Login status (0 or 1)
    char shared_directory[256];      // Directory containing shared files
} ClientState;

// Information about a shared file
typedef struct {
    char filename[256];              // File name
    uint64_t filesize;               // File size in bytes
    char filepath[512];              // Full path to file
} FileInfo;

// Information about a peer client
typedef struct {
    uint32_t client_id;              // Peer's ClientID
    char ip_address[16];             // Peer's IP (xxx.xxx.xxx.xxx)
    int port;                        // Peer's P2P port
} PeerInfo;

// Search results for a file
typedef struct {
    char filename[256];              // File being searched
    int peer_count;                  // Number of peers with this file
    PeerInfo peers[MAX_PEERS];       // Array of peers
} SearchResult;

// List of shared files
typedef struct {
    FileInfo files[MAX_SHARED_FILES];
    int count;
} SharedFileList;

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
    // 3xx: Protocol errors
    else if (strncmp(response, "300", 3) == 0) {
        printf("[ERROR] Invalid message format\n");
    }
    else if (strncmp(response, "301", 3) == 0) {
        // Custom code for Invalid port number (Server sends this)
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

// Initialize client state
void init_client_state() {
    memset(&g_client, 0, sizeof(ClientState));          
    g_client.p2p_port = P2P_PORT;
    g_client.server_socket = -1;      
    g_client.p2p_socket = -1;         
    g_client.is_logged_in = 0;
    strcpy(g_client.shared_directory, "./shared");
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
int read_line(int sock, char *line, int line_size) {
    // Implementation remains the same (important for robust line reading)
    static char buffer[BUFF_SIZE];
    static int buffer_pos = 0;
    
    // Try to find complete line in existing buffer
    ssize_t crlf_pos = find_crlf(buffer, buffer_pos);
    if (crlf_pos >= 0) {
        int line_len = (int)crlf_pos;
        if (line_len >= line_size - 1) {
            line_len = line_size - 2;
        }
        
        memcpy(line, buffer, line_len);
        line[line_len] = '\0';
        
        // Remove processed line from buffer
        int remaining = buffer_pos - (line_len + 2);
        if (remaining > 0) {
            memmove(buffer, buffer + line_len + 2, remaining);
        }
        buffer_pos = remaining;
        buffer[buffer_pos] = '\0';
        
        return 1;
    }
    
    // Read more data
    int max_read = sizeof(buffer) - buffer_pos - 1;
    if (max_read <= 0) {
        fprintf(stderr, "[ERROR] Internal buffer full\n");
        return -1;
    }
    
    int bytes_read = recv(sock, buffer + buffer_pos, max_read, 0);
    
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  // No data available
        }
        perror("[ERROR] recv failed");
        return -1;
    }
    
    if (bytes_read == 0) {
        return 0;  // Connection closed
    }
    
    buffer_pos += bytes_read;
    buffer[buffer_pos] = '\0';
    
    // Try again
    return read_line(sock, line, line_size);
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
    if (!g_client.is_logged_in) {
        print_response_message("403"); // User not logged in
        return -1;
    }
    
    // Validation checks
    if (g_client.client_id == 0) {
        printf("[ERROR] Invalid ClientID\n");
        return -1;
    }
    if (g_client.p2p_port < 1024 || g_client.p2p_port > 65535) {
        printf("[ERROR] Invalid P2P port: %d\n", g_client.p2p_port);
        return -1;
    }
    
    char command[256];
    char response[BUFF_SIZE];
    
    // Build SENDINFO command: SENDINFO <ClientID> <Port>\r\n
    snprintf(command, sizeof(command), "SENDINFO %u %d\r\n", 
             g_client.client_id, g_client.p2p_port);
    
    printf("[INFO] Sending client info: ID=%u, Port=%d\n", 
           g_client.client_id, g_client.p2p_port);
    
    // Send command and get response
    if (send_command(sock, command, response, sizeof(response)) < 0) {
        printf("[ERROR] Failed to send/receive SENDINFO command\n");
        return -1;
    }
    
    // Display result using the response message printer
    print_response_message(response);

    // Return status based on the response code
    if (strcmp(response, "103") == 0) {
        return 0; // Success
    } else {
        return -1; // Failure
    }
}

// Handle SEARCH command: search for a file and populate peer list
// Returns: Number of peers found (>= 0), or -1 if command failed.
int handle_search(int sock, const char *filename, PeerInfo peers_out[], int max_peers) {
    if (!g_client.is_logged_in) {
        print_response_message("403"); // Not logged in
        return -1; 
    }
    
    char command[512];
    char line[BUFF_SIZE];
    
    // 1. Send SEARCH command
    snprintf(command, sizeof(command), "SEARCH %s\r\n", filename);
    if (send_all(sock, command, strlen(command)) < 0) {
        perror("[ERROR] Failed to send SEARCH command");
        return -1;
    }
    
    // 2. Read the initial response (Status code: 210, 404, etc.)
    int read_status = read_line(sock, line, sizeof(line));
    
    if (read_status <= 0) {
        // Connection error or closed
        return -1;
    }

    // Display initial status
    print_response_message(line);
    
    // Check for success code '210'
    if (strcmp(line, "210") != 0) {
        // Command failed (e.g., 404 File not found)
        return 0; 
    }
    
    // 3. Read list of peers until termination line "."
    int peer_count = 0;
    while (peer_count < max_peers) {
        // Note: read_line returns 1 on success, 0 on no data (shouldn't happen here), -1 on error
        if (read_line(sock, line, sizeof(line)) != 1) { 
            // Connection error during list reading
            return -1; 
        }
        
        // Check for list termination line "."
        if (strcmp(line, ".") == 0) {
            break;
        }
        
        PeerInfo current_peer;
        
        // Parse peer info: <ClientID> <IP Address> <P2P Port>
        if (sscanf(line, "%u %15s %d", 
                   &current_peer.client_id, 
                   current_peer.ip_address, 
                   &current_peer.port) == 3) {
            
            // Store successful peer info
            peers_out[peer_count] = current_peer;
            peer_count++;
        } else {
            fprintf(stderr, "[WARNING] Invalid peer format received: %s\n", line);
        }
    }
    
    return peer_count; // Return the number of peers found
}

// =============================================================================
// SERVER CONNECTION
// =============================================================================

// Connect to the main server
int connect_to_server(const char *server_ip, int server_port) {
    // Implementation remains the same
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[ERROR] Cannot create socket");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("[ERROR] Invalid server IP address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERROR] Cannot connect to server");
        close(sock);
        return -1;
    }
    
    printf("[INFO] Connected to server %s:%d\n", server_ip, server_port);
    return sock;
}

// Disconnect from the main server
void disconnect_from_server(int sock) {
    if (sock >= 0) {
        close(sock);
        printf("[INFO] Disconnected from server\n");
    }
}


int main(int argc, char *argv[]) {
    // Initialize client state
    init_client_state();

    // Connect to main server
    const char *SERVER_IP = "127.0.0.1";
    g_client.server_socket = connect_to_server(SERVER_IP, SERVER_PORT);
    
    // Load or generate ClientID
    if (!load_client_id(&g_client.client_id)) {
        g_client.client_id = generate_client_id();
        if (!save_client_id(g_client.client_id)) {
            printf("[ERROR] Cannot save client ID to config.txt\n");
            return 1;
        }
        printf("[INFO] First time run. Generated Client ID: %u\n", g_client.client_id);
    } else {
        printf("[INFO] Loaded existing Client ID: %u\n", g_client.client_id);
    }
    
    // Load shared files from index.txt
    load_shared_files();
    
    printf("[INFO] P2P Client initialized successfully\n");
    printf("[INFO] Client ID: %u\n", g_client.client_id);
    printf("[INFO] P2P Port: %d\n", g_client.p2p_port);
    printf("[INFO] Shared files: %d\n", g_shared_files.count);
    
    
    return 0;
}