/* =============================================================================
   LIBRARIES
   ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

/* =============================================================================
   CONSTANTS
   ============================================================================= */

#define SERVER_PORT 8000             // Server's listening port for client connections
#define P2P_PORT 6000                // Default P2P port for file transfers
#define BUFF_SIZE 8192               // Buffer size for socket I/O operations
#define MAX_CLIENTS 128              // Maximum number of concurrent client connections
#define MAX_TOTAL_FILES 4096         // Maximum number of files in the index
#define BACKLOG 20                   // Maximum pending connections in listen queue
#define INDEX_FILE "index.txt"       // File name for storing the file index
#define DATABASE_FILE "database"    // SQLite database file for account management
#define PASSWORD_HASH_LENGTH 65      // Length of SHA256 hex string + null terminator

/* =============================================================================
   STRUCTS
   ============================================================================= */

// Structure for session information
typedef struct
{
    int socket_fd;                  // Socket file descriptor of client
    struct sockaddr_in client_addr; // Client connection address information
    int account_id;                 // User ID from database, -1 if not logged in
    char username[64];              // Username after successful login
    int is_active;                  // Is this session currently connected?
    int is_logged_in;               // Is user authenticated in this session?
    time_t last_active;             // Last activity timestamp for timeout checking
    char recv_buffer[BUFF_SIZE];    // Buffer for received data
    size_t buffer_len;              // Current length of data in recv_buffer
} Session;

// Structure for client connection information (from SENDINFO command)
typedef struct
{
    uint32_t client_id;              // Client's unique 32-bit identifier
    char ip_address[16];// Client's IP address for P2P connections
    int port;                        // Client's P2P listening port
    int account_id;                  // Associated account ID for authentication
} ClientInfo;

// Structure for file index entry (maintained in memory and saved to index.txt)
typedef struct
{
    char filename[256];              // Name of the shared file
    uint32_t client_id;              // Client ID of the file owner
    char ip_address[16];// IP address of the file owner
    int port;                        // P2P port of the file owner
    time_t published_time;           // Timestamp when file was published
} FileIndexEntry;

/* =============================================================================
   GLOBAL VARIABLES
   ============================================================================= */

// Session management - tracks all active client sessions
Session sessions[MAX_CLIENTS];
pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Client information management - stores P2P connection details from SENDINFO
ClientInfo client_infos[MAX_CLIENTS];
int client_info_count = 0;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

// File index management - in-memory cache of shared files loaded from index.txt
FileIndexEntry file_index[MAX_TOTAL_FILES];
int file_index_count = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Database connection for account authentication and management
sqlite3 *db = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =============================================================================
   UTILITY FUNCTIONS
   ============================================================================= */

// Hash password using SHA256 algorithm
// Parameters:
//   password: Plain text password to hash
//   hash_output: Buffer to store the resulting hex string (must be at least 65 bytes)
void hash_password(const char *password, char *hash_output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    // Initialize SHA256 context and compute hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    
    // Convert binary hash to hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[64] = '\0';
}

// Send a response string to a client socket
// Parameters:
//   socket_fd: Destination socket file descriptor
//   response: Null-terminated string to send
void send_response(int socket_fd, const char *response)
{
    // Simple send - assumes complete transmission (no partial send handling)
    send(socket_fd, response, strlen(response), 0);
}

// Find the position of "\r\n" (CRLF) in a buffer
// Parameters:
//   buf: Buffer to search
//   len: Length of data in buffer
// Returns: Index of '\r' if found, -1 if not found
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

/* =============================================================================
   DATABASE OPERATIONS
   ============================================================================= */

// Initialize SQLite database connection and create accounts table if needed
// Returns: 0 on success, -1 on failure
int init_database()
{
    int rc = sqlite3_open(DATABASE_FILE, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "[ERROR] Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // Create accounts table with required schema
    char *err_msg = NULL;
    const char *create_table_sql = 
        "CREATE TABLE IF NOT EXISTS accounts ("
        "account_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL,"
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    rc = sqlite3_exec(db, create_table_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "[ERROR] Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    printf("[INFO] Accounts database initialized\n");
    return 0;
}

/* =============================================================================
   FILE INDEX MANAGEMENT FUNCTIONS
   ============================================================================= */

// Load file index from index.txt into memory
// File format: filename client_id ip_address port timestamp
void load_index_file()
{
    FILE *fp = fopen(INDEX_FILE, "r");
    if (!fp)
    {
        printf("[INFO] Index file not found, starting with empty index\n");
        return;
    }
    
    pthread_mutex_lock(&file_mutex);
    file_index_count = 0;
    
    char line[512];
    while (fgets(line, sizeof(line), fp) && file_index_count < MAX_TOTAL_FILES)
    {
        FileIndexEntry *entry = &file_index[file_index_count];
        
        if (sscanf(line, "%255s %u %15s %d %ld",
                   entry->filename,
                   &entry->client_id,
                   entry->ip_address,
                   &entry->port,
                   &entry->published_time) == 5)
        {
            file_index_count++;
        }
    }
    
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
    printf("[INFO] Loaded %d file entries from index.txt\n", file_index_count);
}

// Save current file index from memory to index.txt
void save_index_file()
{
    FILE *fp = fopen(INDEX_FILE, "w");
    if (!fp)
    {
        perror("[ERROR] Failed to open index.txt for writing");
        return;
    }
    
    pthread_mutex_lock(&file_mutex);
    
    for (int i = 0; i < file_index_count; i++)
    {
        FileIndexEntry *entry = &file_index[i];
        fprintf(fp, "%s %u %s %d %ld\n",
                entry->filename,
                entry->client_id,
                entry->ip_address,
                entry->port,
                entry->published_time);
    }
    
    pthread_mutex_unlock(&file_mutex);
    fclose(fp);
    printf("[INFO] Saved %d file entries to index.txt\n", file_index_count);
}

// Add a new file entry to the index and persist to disk
// Parameters:
//   filename: Name of the file being shared
//   client_id: ID of the client sharing the file
//   ip_address: IP address of the client
//   port: P2P port of the client
void add_to_file_index(const char *filename, uint32_t client_id, 
                       const char *ip_address, int port)
{
    pthread_mutex_lock(&file_mutex);
    
    if (file_index_count < MAX_TOTAL_FILES)
    {
        FileIndexEntry *entry = &file_index[file_index_count];
        
        strncpy(entry->filename, filename, sizeof(entry->filename) - 1);
        entry->client_id = client_id;
        strncpy(entry->ip_address, ip_address, sizeof(entry->ip_address) - 1);
        entry->port = port;
        entry->published_time = time(NULL);
        
        file_index_count++;
        
        // Persist changes to disk immediately
        pthread_mutex_unlock(&file_mutex);
        save_index_file();
    }
    else
    {
        pthread_mutex_unlock(&file_mutex);
        printf("[WARNING] File index full, cannot add more entries\n");
    }
}

// Remove a file entry from the index
// Parameters:
//   filename: Name of file to remove
//   client_id: ID of client who owns the file
void remove_from_file_index(const char *filename, uint32_t client_id)
{
    pthread_mutex_lock(&file_mutex);
    
    int found = 0;
    for (int i = 0; i < file_index_count; i++)
    {
        if (strcmp(file_index[i].filename, filename) == 0 &&
            file_index[i].client_id == client_id)
        {
            // Shift remaining entries to remove this one
            for (int j = i; j < file_index_count - 1; j++)
            {
                file_index[j] = file_index[j + 1];
            }
            file_index_count--;
            found = 1;
            break;
        }
    }
    
    if (found)
    {
        pthread_mutex_unlock(&file_mutex);
        save_index_file();
    }
    else
    {
        pthread_mutex_unlock(&file_mutex);
    }
}

/* =============================================================================
   CLIENT INFO MANAGEMENT FUNCTIONS
   ============================================================================= */

// Update or add client connection information (from SENDINFO command)
// Parameters:
//   client_id: Client's unique identifier
//   ip_address: Client's IP address
//   port: Client's P2P listening port
//   account_id: Account ID of authenticated user
void update_client_info(uint32_t client_id, const char *ip_address, int port, int account_id) {
    pthread_mutex_lock(&client_mutex);
    
    int found = 0;
    for (int i = 0; i < client_info_count; i++) {
        if (client_infos[i].client_id == client_id) {
            // Update existing entry ONLY if same account
            if (client_infos[i].account_id == account_id) {
                strncpy(client_infos[i].ip_address, ip_address, INET_ADDRSTRLEN - 1);
                client_infos[i].port = port;
                found = 1;
            }
            break;
        }
    }
    
    if (!found && client_info_count < MAX_CLIENTS) {
        // Add new entry
        client_infos[client_info_count].client_id = client_id;
        strncpy(client_infos[client_info_count].ip_address, ip_address, INET_ADDRSTRLEN - 1);
        client_infos[client_info_count].port = port;
        client_infos[client_info_count].account_id = account_id;
        client_info_count++;
    }
    
    pthread_mutex_unlock(&client_mutex);
}

// Retrieve client connection information by client ID
// Parameters:
//   client_id: Client ID to look up
//   ip_address: Output buffer for IP address
//   port: Output pointer for port number
// Returns: 1 if found, 0 if not found
int get_client_info(uint32_t client_id, char *ip_address, int *port)
{
    pthread_mutex_lock(&client_mutex);
    
    int found = 0;
    for (int i = 0; i < client_info_count; i++)
    {
        if (client_infos[i].client_id == client_id)
        {
            strcpy(ip_address, client_infos[i].ip_address);
            *port = client_infos[i].port;
            found = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&client_mutex);
    return found;
}

/* =============================================================================
   COMMAND HANDLING FUNCTIONS 
   ============================================================================= */

// Handle SENDINFO command from client
// Command format: SENDINFO <ClientID> <Port>
void handle_sendinfo(Session *session, uint32_t client_id, int port) {
    // Check if client is authenticated
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n");
        return;
    }
    
    // Validate port range
    if (port < 1024 || port > 65535) {
        send_response(session->socket_fd, "301\r\n");
        return;
    }
    
    // Extract client IP safely
    char client_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(session->client_addr.sin_addr), client_ip, sizeof(client_ip)) == NULL) {
        send_response(session->socket_fd, "500\r\n");
        return;
    }
    
    // Check if this client_id is already being used by another account
    pthread_mutex_lock(&client_mutex);
    for (int i = 0; i < client_info_count; i++) {
        if (client_infos[i].client_id == client_id && 
            client_infos[i].account_id != session->account_id) {
            pthread_mutex_unlock(&client_mutex);
            send_response(session->socket_fd, "405\r\n"); // Client ID already in use
            return;
        }
    }
    pthread_mutex_unlock(&client_mutex);
    
    // Store client_id in session
    session->client_id = client_id;
    
    // Store or update client connection information
    update_client_info(client_id, client_ip, port, session->account_id);
    
    // Send success response
    send_response(session->socket_fd, "103\r\n");
    printf("[INFO] Client info updated: Account=%d, ID=%u, IP=%s, Port=%d\n", 
           session->account_id, client_id, client_ip, port);
}

// Handle SEARCH command from client
// Command format: SEARCH <Filename>
void handle_search(Session *session, const char *filename) {
    // 1. Check login status
    // The SEARCH command requires the client to be logged in to ensure authorization.
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); // 403: User not logged in (Forbidden)
        return;
    }

    // 2. Prepare response buffer
    char response[BUFF_SIZE * 2]; 
    // Start building the response with the success code (210 - File found, starting list)
    int len = snprintf(response, sizeof(response), "210\r\n"); 
    int file_found = 0; // Counter and flag to track if any peer was found

    // 3. Prepare and execute SQL query
    sqlite3_stmt *stmt;
    const char *tail;
    
    // SQL QUERY: Select DISTINCT ClientID, IP Address, and P2P Port from the clients table 
    // for all files matching the specified filename. This effectively finds all peers
    // who are sharing this file.
    const char *query = 
        "SELECT DISTINCT c.client_id, c.ip_address, c.port "
        "FROM files f "
        "JOIN clients c ON f.client_id = c.client_id "
        "WHERE f.filename = ?;"; // Use '?' as a placeholder for the filename

    // Acquire the database lock to prevent concurrent write/read issues
    pthread_mutex_lock(&db_mutex);

    // Prepare the SQL statement for execution
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, &tail);
    if (rc != SQLITE_OK) {
        // Handle SQL preparation error
        fprintf(stderr, "[ERROR] SQL error on SEARCH prepare: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n"); // 500: Internal server error
        return;
    }
    
    // Bind the filename argument to the placeholder (?) to safely handle user input 
    // and prevent SQL Injection attacks.
    sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
    
    // 4. Iterate over query results
    // Loop through each row returned by the SQL query (i.e., each sharing peer)
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Retrieve data from columns (0-based index: 0=client_id, 1=ip_address, 2=port)
        uint32_t client_id = (uint32_t)sqlite3_column_int(stmt, 0);
        const char *ip_address = (const char *)sqlite3_column_text(stmt, 1);
        int port = sqlite3_column_int(stmt, 2);
        
        // Append the peer information to the response buffer.
        // Format: <ClientID> <IP Address> <P2P Port>\r\n
        int added = snprintf(response + len, sizeof(response) - len, 
                             "%u %s %d\r\n", 
                             client_id, 
                             ip_address, 
                             port);
        
        // Check for buffer overflow to ensure we don't write past the buffer limit
        if (len + added >= sizeof(response)) {
            fprintf(stderr, "[WARNING] Search result buffer exceeded size for file '%s'. Truncating list.\n", filename);
            break; // Stop iterating if buffer is full
        }
        
        len += added; // Update the current length of the response buffer
        file_found = 1; // Mark the flag as true since at least one result was found
    }

    // Clean up the prepared statement resources
    sqlite3_finalize(stmt);
    // Release the database lock
    pthread_mutex_unlock(&db_mutex);

    // 5. Send results back to the client
    if (file_found) {
        // Add the list termination line: ".\r\n"
        len += snprintf(response + len, sizeof(response) - len, ".\r\n");
        
        // Send the complete response (210 + Peer List + termination '.')
        if (send(session->socket_fd, response, len, 0) < 0) {
            perror("[ERROR] Failed to send search results");
        }
        printf("[INFO] Sent search results for file '%s' (Total peers: %d)\n", filename, file_found);
    } else {
        // If no rows were found, send the 'Not Found' error code
        send_response(session->socket_fd, "404\r\n"); // 404: File not found
        printf("[INFO] File '%s' not found. Sent 404.\n", filename);
    }
}

// Headers for unfinished use cases
void handle_register(Session *session, const char *username, const char *password);
void handle_login(Session *session, const char *username, const char *password);
void handle_publish(Session *session, uint32_t client_id, const char *filename);
void handle_unpublish(Session *session, const char *filename);
void handle_logout(Session *session);

// Process a single client request line
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
    
    if (sscanf(request, "%s %[^\r\n]", command, argument) < 1)
    {
        send_response(session->socket_fd, "300\r\n");
        return;
    }
    
    if (strcmp(command, "REGISTER") == 0)
    {
        char username[64], password[64];
        if (sscanf(argument, "%s %s", username, password) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_register(session, username, password);
    }
    else if (strcmp(command, "LOGIN") == 0)
    {
        char username[64], password[64];
        if (sscanf(argument, "%s %s", username, password) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_login(session, username, password);
    }
    else if (strcmp(command, "SENDINFO") == 0)
    {
        uint32_t client_id;
        int port;
        if (sscanf(argument, "%u %d", &client_id, &port) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_sendinfo(session, client_id, port);
    }
    else if (strcmp(command, "PUBLISH") == 0)
    {
        uint32_t client_id;
        char filename[256];
        if (sscanf(argument, "%u %255s", &client_id, filename) != 2)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_publish(session, client_id, filename);
    }
    else if (strcmp(command, "UNPUBLISH") == 0)
    {
        char filename[256];
        if (sscanf(argument, "%255s", filename) != 1)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_unpublish(session, filename);
    }
    else if (strcmp(command, "SEARCH") == 0)
    {
        char filename[256];
        if (sscanf(argument, "%255s", filename) != 1)
        {
            send_response(session->socket_fd, "300\r\n");
            return;
        }
        handle_search(session, filename);
    }
    else if (strcmp(command, "LOGOUT") == 0)
    {
        handle_logout(session);
    }
    else
    {
        send_response(session->socket_fd, "300\r\n");
    }
}

/* =============================================================================
   SESSION MANAGEMENT
   ============================================================================= */

// Clean up a session when client disconnects or session ends
// Parameters:
//   session: Session to clean up
void cleanup_session(Session *session)
{
    pthread_mutex_lock(&session_mutex);
    session->is_active = 0;
    session->is_logged_in = 0;
    session->account_id = -1;
    memset(session->username, 0, sizeof(session->username));
    pthread_mutex_unlock(&session_mutex);
}

// Main loop for handling a single client session (runs in separate thread)
// Parameters:
//   arg: Pointer to Session structure
// Returns: NULL (thread exit value)
void *session_loop(void *arg)
{
    Session *session = (Session *)arg;
    int sockfd = session->socket_fd;
    
    // Initialize session state
    session->buffer_len = 0;
    session->is_active = 1;
    session->is_logged_in = 0;
    session->account_id = -1;
    session->last_active = time(NULL);
    
    // Log connection information
    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &(session->client_addr.sin_addr), client_ip, sizeof(client_ip));
    printf("[INFO] New connection: socket=%d ip=%s port=%d\n", 
           sockfd, client_ip, ntohs(session->client_addr.sin_port));
    
    // Send welcome message to client
    send_response(sockfd, "100\r\n");
    
    // Main session loop - handle client requests
    while (session->is_active)
    {
        size_t cap = sizeof(session->recv_buffer);
        if (session->buffer_len >= cap - 1)
            break;
        
        size_t max_read = cap - session->buffer_len - 1;
        
        // Read data from client socket
        ssize_t avail = recv(sockfd, session->recv_buffer + session->buffer_len, max_read, 0);
        
        if (avail == 0)
        {
            // Client disconnected gracefully
            printf("[INFO] Client disconnected gracefully: %s\n", client_ip);
            break;
        }
        else if (avail < 0)
        {
            // Handle socket errors
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // No data available, sleep briefly and continue
                usleep(10 * 1000);
                continue;
            }
            if (errno == EINTR)
                continue; // Interrupted system call, retry
            
            perror("[ERROR] recv failed");
            break;
        }
        else
        {
            // Data received successfully
            session->buffer_len += (size_t)avail;
            session->recv_buffer[session->buffer_len] = '\0';
            session->last_active = time(NULL);
            
            // Process complete lines in buffer
            while (1)
            {
                ssize_t idx = find_crlf(session->recv_buffer, session->buffer_len);
                if (idx < 0)
                    break; // No complete line yet
                
                // Extract complete line
                size_t line_len = (size_t)idx;
                char *line = (char *)malloc(line_len + 1);
                if (!line)
                {
                    session->is_active = 0;
                    break;
                }
                
                memcpy(line, session->recv_buffer, line_len);
                line[line_len] = '\0';
                
                // Remove processed line from buffer
                size_t remain = session->buffer_len - (line_len + 2);
                if (remain > 0)
                    memmove(session->recv_buffer, session->recv_buffer + line_len + 2, remain);
                
                session->buffer_len = remain;
                session->recv_buffer[session->buffer_len] = '\0';
                
                // Process the request line
                process_request(session, line);
                free(line);
                
                if (!session->is_active)
                    break;
            }
        }
    }
    
    // Clean up session and close socket
    cleanup_session(session);
    close(sockfd);
    printf("[INFO] Session thread exiting for socket=%d\n", sockfd);
    return NULL;
}

/* =============================================================================
   SOCKET I/O (SERVER-SIDE INITIALIZATION)
   ============================================================================= */

// Initialize server socket and return file descriptor
// Returns: Socket file descriptor on success, -1 on failure
int init_server_socket()
{
    int listenfd;
    
    // Create TCP socket
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket creation failed");
        return -1;
    }
    
    // Set socket option to allow reuse of local address
    int opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(listenfd);
        return -1;
    }
    
    // Configure server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;           // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;   // Accept connections on all interfaces
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    
    // Bind socket to server address
    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind failed");
        close(listenfd);
        return -1;
    }
    
    // Start listening for incoming connections
    if (listen(listenfd, BACKLOG) == -1)
    {
        perror("listen failed");
        close(listenfd);
        return -1;
    }
    
    printf("[INFO] Server socket initialized on port %d\n", SERVER_PORT);
    return listenfd;
}

// Accept a new client connection
// Parameters:
//   listenfd: Listening socket file descriptor
//   client_addr: Output parameter for client address information
//   sin_size: Input/output parameter for address structure size
// Returns: New socket file descriptor for client communication, -1 on error
int accept_client_connection(int listenfd, struct sockaddr_in *client_addr, socklen_t *sin_size)
{
    int new_sock = accept(listenfd, (struct sockaddr *)client_addr, *sin_size);
    
    if (new_sock == -1)
    {
        perror("accept failed");
        return -1;
    }
    
    // Log successful connection
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr->sin_port);
    printf("[INFO] Accepted connection from %s:%d\n", client_ip, client_port);
    
    return new_sock;
}

/* =============================================================================
   MAIN SERVER LOOP
   ============================================================================= */

int main()
{
    // Initialize accounts database
    if (init_database() != 0)
    {
        fprintf(stderr, "[ERROR] Failed to initialize accounts database\n");
        return EXIT_FAILURE;
    }
    
    // Load file index from text file
    load_index_file();
    
    // Initialize server socket
    int listenfd = init_server_socket();
    if (listenfd == -1)
    {
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    
    printf("[INFO] Server starting\n");
    printf("[INFO] File index stored in: %s\n", INDEX_FILE);
    printf("[INFO] Accounts stored in: %s\n", DATABASE_FILE);
    
    // Initialize data structures
    memset(sessions, 0, sizeof(sessions));
    memset(client_infos, 0, sizeof(client_infos));
    
    // Variables for client connection handling
    struct sockaddr_in client_addr;
    socklen_t sin_size = sizeof(client_addr);
    pthread_t tid;
    
    // =========================================================================
    // MAIN SERVER LOOP - Accept and handle client connections
    // =========================================================================
    while (1)
    {
        // Accept new client connection (blocks until connection arrives)
        int new_sock = accept_client_connection(listenfd, &client_addr, &sin_size);
        if (new_sock == -1)
        {
            continue; // Try to accept next connection despite error
        }
        
        // Find available session slot
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
        
        // Check if server is at capacity
        if (slot_idx == -1)
        {
            printf("[WARNING] Server full, rejecting connection\n");
            close(new_sock);
            continue;
        }
        
        // Initialize session for new client
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
        
        // Create thread to handle this client
        if (pthread_create(&tid, NULL, session_loop, (void *)&sessions[slot_idx]) != 0)
        {
            perror("pthread_create failed");
            
            // Clean up session if thread creation fails
            pthread_mutex_lock(&session_mutex);
            sessions[slot_idx].is_active = 0;
            pthread_mutex_unlock(&session_mutex);
            
            close(new_sock);
            continue;
        }
        
        // Detach thread (cleanup handled by system when thread exits)
        pthread_detach(tid);
        printf("[INFO] Thread created for slot %d\n", slot_idx);
    }
    
    // Cleanup (unreachable in normal operation)
    close(listenfd);
    sqlite3_close(db);
    return 0;
}