#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include "../config.h"

#pragma comment(lib, "ws2_32.lib")

// =============================================================================
// CONSTANTS
// =============================================================================

#define CONFIG_FILE "config.txt"
#define SERVER_PORT 8000
#define P2P_PORT 6000
#define BUFF_SIZE 8192
#define MAX_SHARED_FILES 256
#define MAX_PEERS 128

// =============================================================================
// STRUCTURES AND TYPE DEFINITIONS
// =============================================================================

// Client state and connection information
typedef struct {
    uint32_t client_id;              // 32-bit ClientID from config.txt
    int p2p_port;                    // Port for P2P connections (6000)
    SOCKET server_socket;            // Socket connected to main server
    SOCKET p2p_socket;               // Socket for P2P listening
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
    g_client.server_socket = INVALID_SOCKET;
    g_client.p2p_socket = INVALID_SOCKET;
    g_client.is_logged_in = 0;
    strcpy(g_client.shared_directory, "./shared");
}

// Load shared files from index.txt
int load_shared_files() {
    FILE *fp = fopen("index.txt", "r");
    if (!fp) {
        printf("[INFO] index.txt not found, no files to share\n");
        return 0;
    }
    
    g_shared_files.count = 0;
    char line[768];
    
    while (fgets(line, sizeof(line), fp) && g_shared_files.count < MAX_SHARED_FILES) {
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Parse line: filename|filepath
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
// SERVER CONNECTION FUNCTIONS
// =============================================================================
// Connect to server
SOCKET connect_to_server(const char *server_ip, int server_port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] Cannot create socket: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[ERROR] Cannot connect to server %s:%d - %d\n", server_ip, server_port, WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    printf("[INFO] Connected to server %s:%d successfully\n", server_ip, server_port);
    return sock;
}

// Disconnect from server
void disconnect_from_server(SOCKET sock) {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        printf("[INFO] Disconnected from server\n");
    }
}

// =============================================================================
// SOCKET I/O FUNCTIONS
// =============================================================================

// Send message to server (Example: "LOGIN username password\r\n")
// Returns: number of bytes sent, or -1 on error
int send_message(SOCKET sock, const char *message) {
    int len = strlen(message);
    int total_sent = 0;
    
    // Keep sending until entire message is sent
    while (total_sent < len) {
        int sent = send(sock, message + total_sent, len - total_sent, 0);
        
        if (sent == SOCKET_ERROR) {
            printf("[ERROR] Send failed: %d\n", WSAGetLastError());
            return -1;
        }
        
        total_sent += sent;
    }
    
    return total_sent;
}

// Receive response from server
// Returns: number of bytes received, 0 if connection closed, -1 on error
int receive_response(SOCKET sock, char *buffer, int buffer_size) {
    // Clear buffer first
    memset(buffer, 0, buffer_size);
    
    // Receive data
    int received = recv(sock, buffer, buffer_size - 1, 0);
    
    if (received == SOCKET_ERROR) {
        printf("[ERROR] Receive failed: %d\n", WSAGetLastError());
        return -1;
    }
    
    if (received == 0) {
        printf("[INFO] Connection closed by server\n");
        return 0;
    }
    
    // Null-terminate the string
    buffer[received] = '\0';
    
    return received;
}

// Receive complete response (handles multi-line responses like SEARCH results)
// Returns: total bytes received, or -1 on error
int receive_full_response(SOCKET sock, char *buffer, int buffer_size) {
    memset(buffer, 0, buffer_size);
    int total_received = 0;
    
    // Set a timeout for receiving data (optional but recommended)
    DWORD timeout = 5000;  // 5 seconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Keep receiving until we get a complete response
    while (total_received < buffer_size - 1) {
        int received = recv(sock, buffer + total_received, 
                           buffer_size - total_received - 1, 0);
        
        if (received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAETIMEDOUT) {
                // Timeout - assume response is complete
                break;
            }
            printf("[ERROR] Receive failed: %d\n", error);
            return -1;
        }
        
        if (received == 0) {
            // Connection closed
            break;
        }
        
        total_received += received;
        
        // Small delay to allow more data to arrive
        Sleep(10);
        
        // Check if more data is available
        u_long bytes_available = 0;
        ioctlsocket(sock, FIONREAD, &bytes_available);
        if (bytes_available == 0) {
            // No more data available
            break;
        }
    }
    
    buffer[total_received] = '\0';
    return total_received;
}

// =============================================================================
// MAIN PROGRAM
// =============================================================================

int main(int argc, char *argv[]) {
    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("[ERROR] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Initialize client state
    init_client_state();
    
    // Load or generate ClientID
    if (!load_client_id(&g_client.client_id)) {
        // If not found, generate new ClientID
        g_client.client_id = generate_client_id();
        if (!save_client_id(g_client.client_id)) {
            printf("[ERROR] Cannot save client ID to config.txt\n");
            WSACleanup();
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
    
    // TODO: Connect to server
    // TODO: Login/Register
    // TODO: Send GETINFO
    // TODO: Publish files
    // TODO: Handle user commands
    
    WSACleanup();
    return 0;
}