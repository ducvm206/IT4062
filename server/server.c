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
#include <mysql/mysql.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include "../config.h"

/* =============================================================================
   CONSTANTS
   ============================================================================= */

#define SERVER_PORT 8000             // Server's listening port for client connections
#define P2P_PORT 6000                // Default P2P port for file transfers
#define BUFF_SIZE 8192               // Buffer size for socket I/O operations
#define MAX_CLIENTS 128              // Maximum number of concurrent client connections
#define MAX_TOTAL_FILES 4096         // Maximum number of files in the index
#define INDEX_FILE "index.txt"       // File name for storing the file index
#define PASSWORD_HASH_LENGTH 65      // Length of SHA256 hex string + null terminator
#define LOG_FILE "logs.txt"          // Log file name

// MySQL connection parameters
#define MYSQL_HOST "localhost"
#define MYSQL_USER "p2puser"
#define MYSQL_PASSWORD "p2ppass"
#define MYSQL_DATABASE "p2p_db"
#define MYSQL_PORT 3306
#define BACKLOG 10
//#define MYSQL_PORT 3306              // MySQL port

/* =============================================================================
   STRUCTS
   ============================================================================= */

// Structure for session information
typedef struct
{
    uint32_t client_id;
    struct sockaddr_in client_addr;
    int socket_fd;                  // Socket file descriptor of client
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

// Database connection for account authentication and management
MYSQL *db = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


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

int send_all(int sockfd, const char *buf, size_t len)
{
    size_t total_sent = 0;

    while (total_sent < len)
    {
        ssize_t n = send(sockfd,
                         buf + total_sent,
                         len - total_sent,
                         0);
        if (n <= 0)
        {
            return -1; // lỗi hoặc client đóng kết nối
        }
        total_sent += n;
    }

    return 0; // thành công
}

int read_line(int sockfd, char *buf, size_t maxlen)
{
    size_t i = 0;
    char c;

    while (i < maxlen - 1)
    {
        ssize_t n = recv(sockfd, &c, 1, 0);
        if (n == 1)
        {
            buf[i++] = c;
            if (c == '\n')
            {
                break;
            }
        }
        else if (n == 0)
        {
            // client đóng kết nối
            break;
        }
        else
        {
            // lỗi recv
            return -1;
        }
    }

    buf[i] = '\0';
    return (int)i;
}

// Logs client transaction activity to a file (server.log).
// Format: [Timestamp] STATUS COMMAND CID=ClientID USER=Username IP=IP:Port CODE=ResponseCode
void log_server(
    const char *status,
    const char *command,
    Session *s,
    const char *code
) {
    char timebuf[32];
    time_t now = time(NULL);
    strftime(timebuf, sizeof(timebuf),
             "%Y-%m-%d %H:%M:%S", localtime(&now));

    pthread_mutex_lock(&log_mutex);
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        fprintf(fp,
            "[%s] %s %s CID=%u USER=%s IP=%s:%d CODE=%s\n",
            timebuf,
            status,
            command,
            s->client_id,
            s->username[0] ? s->username : "-",
            inet_ntoa(s->client_addr.sin_addr),
            ntohs(s->client_addr.sin_port),
            code
        );
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

/* =============================================================================
   DATABASE OPERATIONS
   ============================================================================= */

// Initialize MySQL database connection and create tables if needed
// Returns: 0 on success, -1 on failure
int init_database()
{
    // Initialize MySQL connection
    db = mysql_init(NULL);
    if (db == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot initialize MySQL: %s\n", mysql_error(db));
        return -1;
    }
    
    // Connect to MySQL server
    if (mysql_real_connect(db, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, 
                          MYSQL_DATABASE, MYSQL_PORT, NULL, 0) == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot connect to MySQL: %s\n", mysql_error(db));
        mysql_close(db);
        db = NULL;
        return -1;
    }
    
    // Set character set to UTF-8
    if (mysql_set_character_set(db, "utf8mb4") != 0)
    {
        fprintf(stderr, "[WARNING] Cannot set character set: %s\n", mysql_error(db));
    }
    
    // Create accounts table with required schema
    const char *create_accounts_sql = 
        "CREATE TABLE IF NOT EXISTS accounts ("
        "account_id INT AUTO_INCREMENT PRIMARY KEY,"
        "username VARCHAR(64) NOT NULL UNIQUE,"
        "password_hash VARCHAR(65) NOT NULL,"
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    
    if (mysql_query(db, create_accounts_sql) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to create accounts table: %s\n", mysql_error(db));
        mysql_close(db);
        db = NULL;
        return -1;
    }
    
    // Create clients table
    const char *create_clients_sql = 
        "CREATE TABLE IF NOT EXISTS clients ("
        "client_id INT UNSIGNED PRIMARY KEY,"
        "account_id INT NOT NULL,"
        "ip_address VARCHAR(15) NOT NULL,"
        "port INT NOT NULL,"
        "last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
        "FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    
    if (mysql_query(db, create_clients_sql) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to create clients table: %s\n", mysql_error(db));
        // Continue anyway, table might already exist
    }
    
    // Create files table
    const char *create_files_sql = 
        "CREATE TABLE IF NOT EXISTS files ("
        "file_id INT AUTO_INCREMENT PRIMARY KEY,"
        "client_id INT UNSIGNED NOT NULL,"
        "filename VARCHAR(255) NOT NULL,"
        "filesize BIGINT NOT NULL,"
        "published_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,"
        "INDEX idx_files_filename (filename)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    
    if (mysql_query(db, create_files_sql) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to create files table: %s\n", mysql_error(db));
        // Continue anyway, table might already exist
    }
    
    printf("[INFO] MySQL database initialized successfully\n");
    printf("[INFO] Connected to database: %s@%s/%s\n", MYSQL_USER, MYSQL_HOST, MYSQL_DATABASE);
    return 0;
}

/* =============================================================================
   CLIENT INFO MANAGEMENT FUNCTIONS
   ============================================================================= */

// Update or add client connection information (from SENDINFO command)
int update_client_info(uint32_t client_id, int account_id, const char *ip, int port) {
    printf("[DEBUG-UPDATE_CLIENT_INFO] Starting database update...\n");
    printf("[DEBUG-UPDATE_CLIENT_INFO] ClientID: %u, AccountID: %d, IP: %s, Port: %d\n", 
           client_id, account_id, ip, port);
    
    // SQL query to insert or update client info if ID already exists
    const char *query = 
        "INSERT INTO clients (client_id, account_id, ip_address, port, last_seen) "
        "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
        "ON DUPLICATE KEY UPDATE "
        "account_id = VALUES(account_id), "
        "ip_address = VALUES(ip_address), "
        "port = VALUES(port), "
        "last_seen = CURRENT_TIMESTAMP;";

    MYSQL_STMT *stmt = NULL;
    int status = 0;

    pthread_mutex_lock(&db_mutex);

    stmt = mysql_stmt_init(db);
    if (!stmt) {
        printf("[DEBUG-UPDATE_CLIENT_INFO] ERROR: Failed to init MySQL statement\n");
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    printf("[DEBUG-UPDATE_CLIENT_INFO] MySQL statement initialized\n");

    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, "[ERROR] SQL error on update_client_info prepare: %s\n", mysql_stmt_error(stmt));
        printf("[DEBUG-UPDATE_CLIENT_INFO] ERROR: Failed to prepare SQL statement\n");
        status = -1;
        goto cleanup;
    }
    
    printf("[DEBUG-UPDATE_CLIENT_INFO] SQL statement prepared\n");

    // Bind parameters: client_id, account_id, ip_address, port
    MYSQL_BIND bind[4];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_LONG; // client_id (uint32)
    bind[0].buffer = (void*)&client_id;

    bind[1].buffer_type = MYSQL_TYPE_LONG; // account_id
    bind[1].buffer = (void*)&account_id;

    bind[2].buffer_type = MYSQL_TYPE_STRING; // ip_address
    bind[2].buffer = (void*)ip;
    bind[2].buffer_length = strlen(ip);

    bind[3].buffer_type = MYSQL_TYPE_LONG; // p2p_port
    bind[3].buffer = (void*)&port;
    
    printf("[DEBUG-UPDATE_CLIENT_INFO] Parameters bound\n");

    if (mysql_stmt_bind_param(stmt, bind)) {
        printf("[DEBUG-UPDATE_CLIENT_INFO] ERROR: Failed to bind parameters\n");
        status = -1;
        goto cleanup;
    }

    printf("[DEBUG-UPDATE_CLIENT_INFO] Executing SQL statement...\n");
    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "[ERROR] SQL error on update_client_info execute: %s\n", mysql_stmt_error(stmt));
        printf("[DEBUG-UPDATE_CLIENT_INFO] ERROR: Failed to execute statement\n");
        status = -1;
    } else {
        printf("[DEBUG-UPDATE_CLIENT_INFO] SUCCESS: SQL statement executed successfully\n");
        printf("[DEBUG-UPDATE_CLIENT_INFO] Client info inserted/updated in 'clients' table\n");
    }

cleanup:
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
    return status;
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
// Handle SENDINFO command from client
// Command format: SENDINFO <ClientID> <Port>
void handle_sendinfo(Session *session, uint32_t client_id, int p2p_port) {
    // Authorization check
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); // Forbidden
        log_server("ERR", "SENDINFO", session, "403");
        printf("[DEBUG-SENDINFO] Client NOT logged in, rejecting SENDINFO for ClientID: %u\n", client_id);
        return;
    }

    // Identify client IP from the connection socket
    char *client_ip = inet_ntoa(session->client_addr.sin_addr);
    session->client_id = client_id;

    printf("[DEBUG-SENDINFO] Attempting to update client info:\n");
    printf("[DEBUG-SENDINFO]   ClientID: %u\n", client_id);
    printf("[DEBUG-SENDINFO]   AccountID: %d\n", session->account_id);
    printf("[DEBUG-SENDINFO]   Username: %s\n", session->username);
    printf("[DEBUG-SENDINFO]   IP: %s\n", client_ip);
    printf("[DEBUG-SENDINFO]   P2P Port: %d\n", p2p_port);
    printf("[DEBUG-SENDINFO]   Socket FD: %d\n", session->socket_fd);

    // Update MySQL database
    if (update_client_info(client_id, session->account_id, client_ip, p2p_port) != 0) {
        send_response(session->socket_fd, "500\r\n"); // Internal Server Error
        printf("[DEBUG-SENDINFO] ERROR: Failed to update client info in database!\n");
        log_server("ERR", "SENDINFO", session, "500");
        return;
    }

    send_response(session->socket_fd, "103\r\n"); // 103: Information accepted
    
    printf("[DEBUG-SENDINFO] SUCCESS: Client info updated in database!\n");
    printf("[INFO] Client %u updated info: IP=%s, P2P_Port=%d\n", client_id, client_ip, p2p_port);
    log_server("OK", "SENDINFO", session, "103");
}

// Handle SEARCH command from client
// Command format: SEARCH <Filename>
void handle_search(Session *session, const char *filename) {
    // 1. Authorization check: Clients must be logged in to perform a search
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); // 403: Forbidden
        log_server("ERR", "SEARCH", session, "403");
        return;
    }

    // 2. Prepare SQL Query: Join files and clients to get initial peer info
    const char *query = 
        "SELECT DISTINCT c.client_id, c.ip_address, c.port "
        "FROM files f "
        "JOIN clients c ON f.client_id = c.client_id "
        "WHERE f.filename LIKE CONCAT('%', ?, '%');";

    pthread_mutex_lock(&db_mutex); // Lock database for thread safety
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (!stmt) {
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n"); // 500: Internal Server Error
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
        fprintf(stderr, "[ERROR] MySQL stmt prepare failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    // 3. Bind Parameters: Prevent SQL Injection by binding the filename
    MYSQL_BIND bind_param;
    memset(&bind_param, 0, sizeof(bind_param));
    unsigned long filename_len = strlen(filename);
    bind_param.buffer_type = MYSQL_TYPE_STRING;
    bind_param.buffer = (char *)filename;
    bind_param.buffer_length = filename_len;
    bind_param.length = &filename_len;

    mysql_stmt_bind_param(stmt, &bind_param);

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "[ERROR] MySQL stmt execute failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    // 4. Bind Results: Map DB columns to local variables
    uint32_t res_client_id;
    char res_ip[16];
    int res_port;
    unsigned long res_ip_len;
    
    MYSQL_BIND bind_result[3];
    memset(bind_result, 0, sizeof(bind_result));

    bind_result[0].buffer_type = MYSQL_TYPE_LONG; 
    bind_result[0].buffer = &res_client_id;

    bind_result[1].buffer_type = MYSQL_TYPE_STRING; 
    bind_result[1].buffer = res_ip;
    bind_result[1].buffer_length = sizeof(res_ip);
    bind_result[1].length = &res_ip_len;

    bind_result[2].buffer_type = MYSQL_TYPE_LONG; 
    bind_result[2].buffer = &res_port;

    mysql_stmt_bind_result(stmt, bind_result);
    mysql_stmt_store_result(stmt);

    int file_found_in_db = mysql_stmt_num_rows(stmt);

    // 5. Response Processing: Filter by active sessions and send to client
    if (file_found_in_db > 0) {
        // Send success code (210: File found, peer list follows)
        send_response(session->socket_fd, "210\r\n");
        log_server("OK", "SEARCH", session, "210");

        char peer_line[256];
        int online_peers = 0;
        
        // Fetch each potential peer from DB
        while (mysql_stmt_fetch(stmt) == 0) {
            res_ip[res_ip_len] = '\0'; 
            
            // CROSS-CHECK: Ensure this peer is currently ONLINE in active sessions
            pthread_mutex_lock(&session_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (sessions[i].is_active && sessions[i].client_id == res_client_id) {
                    
                    // Use the current real-time IP from the socket connection
                    char *current_ip = inet_ntoa(sessions[i].client_addr.sin_addr);
                    
                    // Format: "ClientID IP Port\r\n"
                    int p_len = snprintf(peer_line, sizeof(peer_line), "%u %s %d\r\n", 
                                         res_client_id, current_ip, res_port);
                    
                    send(session->socket_fd, peer_line, p_len, 0);
                    online_peers++;
                    break;
                }
            }
            pthread_mutex_unlock(&session_mutex);
        }

        // TERMINATION: Send a blank line to signify the end of the 210 list
        send(session->socket_fd, "\r\n", 2, 0); 

        printf("[INFO] SEARCH: Found '%s' at %d online peers.\n", filename, online_peers);
        log_server("OK", "SEARCH", session, "210");
    } else {
        // 404: No one in the database has this file
        send_response(session->socket_fd, "404\r\n");
        log_server("OK", "SEARCH", session, "404");
    }

    // 6. Resource Cleanup
    mysql_stmt_free_result(stmt);
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
}

// Handle REGISTER command from client
// Command format: REGISTER username password
// Response codes:
//   101: Đăng ký thành công
//   400: Username đã tồn tại hoặc password < 6 ký tự
//   300: Không xác định được kiểu thông điệp (đã được xử lý ở process_request)
void handle_register(Session *session, const char *username, const char *password)
{
    // 1. Kiểm tra độ dài password (tối thiểu 6 ký tự)
    if (strlen(password) < 6)
    {
        send_response(session->socket_fd, "400\r\n");
        log_server("ERR", "REGISTER", session, "400");
        return;
    }
    
    // 2. Kiểm tra username đã tồn tại chưa
    pthread_mutex_lock(&db_mutex);
    
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (stmt == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot initialize MySQL statement: %s\n", mysql_error(db));
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    const char *check_sql = "SELECT account_id FROM accounts WHERE username = ?;";
    
    if (mysql_stmt_prepare(stmt, check_sql, strlen(check_sql)) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER check prepare: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Bind username parameter
    MYSQL_BIND bind_param;
    memset(&bind_param, 0, sizeof(bind_param));
    bind_param.buffer_type = MYSQL_TYPE_STRING;
    bind_param.buffer = (char *)username;
    bind_param.buffer_length = strlen(username);
    bind_param.length = &bind_param.buffer_length;
    
    if (mysql_stmt_bind_param(stmt, &bind_param) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER check bind: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Execute query
    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER check execute: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Store result
    mysql_stmt_store_result(stmt);
    
    // Kiểm tra xem username đã tồn tại chưa
    if (mysql_stmt_num_rows(stmt) > 0)
    {
        // Username đã tồn tại
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "400\r\n");
        return;
    }
    
    mysql_stmt_close(stmt);
    
    // 3. Hash password
    char password_hash[PASSWORD_HASH_LENGTH];
    hash_password(password, password_hash);
    
    // 4. Insert tài khoản mới vào database
    stmt = mysql_stmt_init(db);
    if (stmt == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot initialize MySQL statement: %s\n", mysql_error(db));
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    const char *insert_sql = "INSERT INTO accounts (username, password_hash) VALUES (?, ?);";
    
    if (mysql_stmt_prepare(stmt, insert_sql, strlen(insert_sql)) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER insert prepare: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Bind parameters
    MYSQL_BIND bind_params[2];
    memset(bind_params, 0, sizeof(bind_params));
    
    unsigned long username_len = strlen(username);
    bind_params[0].buffer_type = MYSQL_TYPE_STRING;
    bind_params[0].buffer = (char *)username;
    bind_params[0].buffer_length = username_len;
    bind_params[0].length = &username_len;
    
    unsigned long hash_len = strlen(password_hash);
    bind_params[1].buffer_type = MYSQL_TYPE_STRING;
    bind_params[1].buffer = password_hash;
    bind_params[1].buffer_length = hash_len;
    bind_params[1].length = &hash_len;
    
    if (mysql_stmt_bind_param(stmt, bind_params) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER insert bind: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Thực thi insert
    if (mysql_stmt_execute(stmt) != 0)
    {
        // Có thể là lỗi UNIQUE constraint (username đã tồn tại - race condition)
        unsigned int err_no = mysql_stmt_errno(stmt);
        if (err_no == 1062) // ER_DUP_ENTRY
        {
            fprintf(stderr, "[ERROR] Username already exists: %s\n", username);
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            send_response(session->socket_fd, "400\r\n");
            log_server("ERR", "REGISTER", session, "400");
            return;
        }
        fprintf(stderr, "[ERROR] SQL error on REGISTER insert execute: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
    
    // 5. Gửi response thành công
    send_response(session->socket_fd, "101\r\n");
    log_server("OK", "REGISTER", session, "101");
    printf("[INFO] New account registered: username=%s\n", username);
}

// Handle LOGIN command from client
// Command format: LOGIN username password
// Response codes:
//   102: Đăng nhập thành công
//   401: Tài khoản không tồn tại hoặc sai mật khẩu
//   300: Không xác định được kiểu thông điệp (đã được xử lý ở process_request)
void handle_login(Session *session, const char *username, const char *password)
{
    // 1. Hash password để so sánh
    char password_hash[PASSWORD_HASH_LENGTH];
    hash_password(password, password_hash);
    
    // 2. Tìm tài khoản trong database
    pthread_mutex_lock(&db_mutex);
    
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (stmt == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot initialize MySQL statement: %s\n", mysql_error(db));
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        return;
    }
    
    const char *query_sql = "SELECT account_id, password_hash FROM accounts WHERE username = ?;";
    
    // If prepare fails (server error)
    if (mysql_stmt_prepare(stmt, query_sql, strlen(query_sql)) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on LOGIN prepare: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        return;
    }
    
    // Bind username parameter
    MYSQL_BIND bind_param;
    memset(&bind_param, 0, sizeof(bind_param));
    unsigned long username_len = strlen(username);
    bind_param.buffer_type = MYSQL_TYPE_STRING;
    bind_param.buffer = (char *)username;
    bind_param.buffer_length = username_len;
    bind_param.length = &username_len;
    
    // Execute the binding
    if (mysql_stmt_bind_param(stmt, &bind_param) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on LOGIN bind: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        return;
    }
    
    // Execute query
    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on LOGIN execute: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        return;
    }
    
    // Bind result columns
    int account_id;
    char stored_hash[PASSWORD_HASH_LENGTH];
    unsigned long hash_len;
    my_bool is_null[2];
    my_bool error[2];
    
    MYSQL_BIND bind_result[2];
    memset(bind_result, 0, sizeof(bind_result));
    
    bind_result[0].buffer_type = MYSQL_TYPE_LONG;
    bind_result[0].buffer = &account_id;
    bind_result[0].is_null = &is_null[0];
    bind_result[0].error = &error[0];
    
    bind_result[1].buffer_type = MYSQL_TYPE_STRING;
    bind_result[1].buffer = stored_hash;
    bind_result[1].buffer_length = sizeof(stored_hash) - 1;
    bind_result[1].length = &hash_len;
    bind_result[1].is_null = &is_null[1];
    bind_result[1].error = &error[1];
    
    // Execute the result binding
    if (mysql_stmt_bind_result(stmt, bind_result) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on LOGIN bind result: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "LOGIN", session, "500");
        return;
    }
    
    // Store result
    mysql_stmt_store_result(stmt);
    
    // Fetch result
    int rc = mysql_stmt_fetch(stmt);
    if (rc == 0)
    {
        // Tìm thấy username, so sánh password hash
        stored_hash[hash_len] = '\0';
        
        if (strcmp(password_hash, stored_hash) == 0)
        {
            // Mật khẩu đúng - đăng nhập thành công
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            
            // Cập nhật session
            pthread_mutex_lock(&session_mutex);
            session->account_id = account_id;
            strncpy(session->username, username, sizeof(session->username) - 1);
            session->username[sizeof(session->username) - 1] = '\0';
            session->is_logged_in = 1;
            pthread_mutex_unlock(&session_mutex);
            
            // Gửi response thành công
            send_response(session->socket_fd, "102\r\n");
            printf("[INFO] User logged in: username=%s, account_id=%d\n", username, account_id);
            log_server("OK", "LOGIN", session, "102");
            return;
        }
        else
        {
            // Mật khẩu sai
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            send_response(session->socket_fd, "401\r\n");
            log_server("ERR", "LOGIN", session, "401");
            return;
        }
    }
    else if (rc == MYSQL_NO_DATA)
    {
        // Không tìm thấy username
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "401\r\n");
        log_server("ERR", "LOGIN", session, "401");
        return;
    }
    else
    {
        // Lỗi SQL
        fprintf(stderr, "[ERROR] SQL error on LOGIN fetch: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "LOGIN", session, "500");
        return;
    }
}

void handle_publish(Session *session, const char *filename, long filesize)
{
    char query[BUFF_SIZE];

    if (!session->is_logged_in) {
        send_response(session->socket_fd, "401\r\n");
        return;
    }

    MYSQL *conn = mysql_init(NULL);
    if (!conn ||
        !mysql_real_connect(conn,
            MYSQL_HOST,
            MYSQL_USER,
            MYSQL_PASSWORD,
            MYSQL_DATABASE,
            0, NULL, 0))
    {
        send_response(session->socket_fd, "500\r\n");
        return;
    }

    snprintf(query, sizeof(query),
        "INSERT INTO files (client_id, filename, filesize) "
        "VALUES (%u, '%s', %ld)",
        session->client_id,
        filename,
        filesize
    );

    if (mysql_query(conn, query)) {
        fprintf(stderr, "[DB-ERR] Publish failed: %s\n", mysql_error(conn));
        send_response(session->socket_fd, "500\r\n");
    } else {
        send_response(session->socket_fd, "200\r\n");
        log_server("OK", "PUBLISH", session, "200");
    }

    mysql_close(conn);
}


void handle_unpublish(Session *session, const char *filename) {
    char query[BUFF_SIZE];

    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        send_response(session->socket_fd, "500\r\n");
        return;
    }

    if (!mysql_real_connect(conn,
            MYSQL_HOST,
            MYSQL_USER,
            MYSQL_PASSWORD,
            MYSQL_DATABASE,
            0,          // port = 0 → dùng mặc định
            NULL,
            0))
    {
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "UNPUBLISH", session, "500"); 
        mysql_close(conn);
        return;
    }

    if (!session->is_logged_in) {
        send_all(session->socket_fd, "401\r\n", 18);
        log_server("ERR", "UNPUBLISH", session, "401");
        return;
    }


    // Delete the file entry that matches both filename and this client's account_id
    snprintf(query, sizeof(query), 
             "DELETE FROM files WHERE client_id = %d AND filename = '%s'", 
             session->client_id, filename);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "[DB-ERR] Unpublish failed: %s\n", mysql_error(conn));
        send_all(session->socket_fd, "500 Internal Server Error\r\n", 27);
        log_server("ERR", "UNPUBLISH", session, "500");
    } else {
        // Check if any row was actually deleted
        if (mysql_affected_rows(conn) > 0) {
            printf("[SERVER] Client %d unpublished file: %s\n", session->account_id, filename);
            send_all(session->socket_fd, "200 File unpublished successfully\r\n", 35);
            log_server("OK", "UNPUBLISH", session, "200");
        } else {
            send_all(session->socket_fd, "404 File not found in your share list\r\n", 39);
            log_server("ERR", "UNPUBLISH", session, "404");
        }
    }
}

void handle_logout(Session *session)
{
    /* 1. Chưa login → reject */
    if (!session->is_logged_in) {
        const char *err = "403 Not logged in\r\n";
        log_server("ERR", "LOGOUT", session, "403");
        send(session->socket_fd, err, strlen(err), 0);
        return;
    }

    /* 2. Log */
    log_server("OK", "LOGOUT", session, "104");

    /* 3. Reset session state */
    session->is_logged_in = 0;
    session->account_id  = -1;
    session->client_id   = 0;
    memset(session->username, 0, sizeof(session->username));

    /* 4. Send response */
    const char *ok = "104 Logout successful\r\n";
    send(session->socket_fd, ok, strlen(ok), 0);

    printf("[INFO] Client logged out successfully\n");
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
// Main loop to handle communication with a specific client session
// Main loop to handle communication with a specific client session
void *session_loop(void *arg)
{
    Session *session = (Session *)arg;
    char buffer[BUFF_SIZE];
    char command[32];
    char payload[BUFF_SIZE];

    printf("[SERVER] Started session for client from %s:%d\n",
           inet_ntoa(session->client_addr.sin_addr),
           ntohs(session->client_addr.sin_port));

    // Send initial welcome message to client
    send_response(session->socket_fd, "100\r\n");

    while (1)
    {
        // Read a line of data from the client
        int n = read_line(session->socket_fd, buffer, sizeof(buffer));
        if (n <= 0)
        {
            printf("[SERVER] Client disconnected or error occurred (ID: %d)\n", session->account_id);
            break;
        }
        // Parse the incoming string into Command and Payload
        // Format expected: "COMMAND Payload\r\n"
        memset(command, 0, sizeof(command));
        memset(payload, 0, sizeof(payload));
        
        int fields = sscanf(buffer, "%s %[^\r\n]", command, payload);
        if (fields < 1) {
            continue;
        }

        // 1. Handle AUTHENTICATION commands
        if (strcmp(command, "REGISTER") == 0)
        {
            char username[64], password[64];
            if (sscanf(payload, "%63s %63s", username, password) != 2)
            {
                send_response(session->socket_fd, "300\r\n");
                continue;
            }
            printf("[DEBUG-SESSION] Processing REGISTER: username=%s\n", username);
            handle_register(session, username, password);
        }
        else if (strcmp(command, "LOGIN") == 0)
        {
            char username[64], password[64];
            if (sscanf(payload, "%63s %63s", username, password) != 2)
            {
                send_response(session->socket_fd, "300\r\n");
                printf("[DEBUG-SESSION] ERROR: Invalid LOGIN format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Processing LOGIN: username=%s\n", username);
            handle_login(session, username, password);
        }
        
        // 2. Handle SENDINFO command (Client info for P2P connections)
        else if (strcmp(command, "SENDINFO") == 0)
        {
            uint32_t client_id;
            int port;
            printf("[DEBUG-SESSION] Received SENDINFO command\n");
            printf("[DEBUG-SESSION] Raw payload: %s\n", payload);
            if (sscanf(payload, "%u %d", &client_id, &port) != 2) {
                send_response(session->socket_fd, "300\r\n");
                printf("[DEBUG-SESSION] ERROR: Invalid SENDINFO format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Parsed SENDINFO: ClientID=%u, Port=%d\n", client_id, port);
            printf("[DEBUG-SESSION] Current session state - Logged in: %d, AccountID: %d, Username: %s\n",
                   session->is_logged_in, session->account_id, session->username);
            handle_sendinfo(session, client_id, port);
        }
        
        // 3. Handle P2P FILE INDEXING commands (Requires Login)
        else if (strcmp(command, "PUBLISH") == 0) {
            char filename[256];
            long filesize;
            if (sscanf(payload, "%255s %ld", filename, &filesize) != 2) {
                send_response(session->socket_fd, "300\r\n");
                printf("[DEBUG-SESSION] ERROR: Invalid PUBLISH format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Processing PUBLISH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_publish(session, filename, filesize);
        }
        else if (strcmp(command, "UNPUBLISH") == 0) {
            printf("[DEBUG-SESSION] Processing UNPUBLISH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_unpublish(session, payload);
        }
        
        // 4. Handle SEARCH command
        else if (strcmp(command, "SEARCH") == 0) {
            printf("[DEBUG-SESSION] Processing SEARCH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_search(session, payload);
        }

        // 5. Handle DOWNLOAD STATUS updates (The 220/410 logic)
        else if (strcmp(command, "UPDATE_STATUS") == 0) {
            int status_code;
            char filename[256];
            if (sscanf(payload, "%d %s", &status_code, filename) == 2) {
                if (status_code == 220) {
                    printf("[STATUS] Client %d successfully downloaded: %s\n", session->account_id, filename);
                    send_all(session->socket_fd, "200 Status 220 Recorded\r\n", 25);
                } else if (status_code == 410) {
                    printf("[STATUS] Client %d failed to download: %s\n", session->account_id, filename);
                    send_all(session->socket_fd, "200 Status 410 Recorded\r\n", 25);
                }
            } else {
                send_all(session->socket_fd, "400 Invalid Status Format\r\n", 27);
            }
        }

        // 6. Handle LOGOUT command
        else if (strcmp(command, "LOGOUT") == 0) {
            printf("[DEBUG-SESSION] Processing LOGOUT command\n");
            pthread_mutex_lock(&session_mutex);
            session->is_logged_in = 0;
            session->account_id = -1;
            memset(session->username, 0, sizeof(session->username));
            pthread_mutex_unlock(&session_mutex);
            send_all(session->socket_fd, "104 Logged out successfully\r\n", 29);
            printf("[DEBUG-SESSION] User logged out\n");
        }

        // 7. Handle QUIT command
        else if (strcmp(command, "QUIT") == 0) {
            printf("[DEBUG-SESSION] Processing QUIT command\n");
            send_all(session->socket_fd, "221 Goodbye\r\n", 13);
            break;
        }

        // 8. Unknown command handling
        else {
            printf("[DEBUG-SESSION] Unknown command: %s\n", command);
            send_all(session->socket_fd, "300 Unknown Command\r\n", 21);
        }

        // Update the last active timestamp for timeout management
        session->last_active = time(NULL);
        
        // Print session state after command processing
        printf("[DEBUG-SESSION] Session state after command - Logged in: %d, AccountID: %d, Username: %s\n",
               session->is_logged_in, session->account_id, session->username);
        printf("[DEBUG-SESSION] -------------------------------------------------\n");
    }

    // Clean up session before thread exit
    close(session->socket_fd);
    pthread_mutex_lock(&session_mutex);
    session->is_active = 0;
    session->is_logged_in = 0;
    session->account_id = -1;
    memset(session->username, 0, sizeof(session->username));
    pthread_mutex_unlock(&session_mutex);

    printf("[SERVER] Session closed for client.\n");
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
    int new_sock = accept(listenfd, (struct sockaddr *)client_addr, sin_size);
    
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

// Connect to Client B via ClientID




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
    
    // Initialize server socket
    int listenfd = init_server_socket();
    if (listenfd == -1)
    {
        mysql_close(db);
        return EXIT_FAILURE;
    }
    
    printf("[INFO] Server starting\n");
    printf("[INFO] File index stored in: %s\n", INDEX_FILE);
    printf("[INFO] Database: MySQL (%s@%s/%s)\n", MYSQL_USER, MYSQL_HOST, MYSQL_DATABASE);
    
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
    mysql_close(db);
    return 0;
}