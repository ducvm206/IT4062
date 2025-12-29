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

#define SERVER_PORT 8000
#define BUFF_SIZE 8192
#define MAX_CLIENTS 1024
#define INDEX_FILE "index.txt"
#define PASSWORD_HASH_LENGTH 65
#define LOG_FILE "logs.txt"


#define MYSQL_HOST "localhost"
#define MYSQL_USER "p2puser"
#define MYSQL_PASSWORD "p2ppass"
#define MYSQL_DATABASE "p2p_db"
#define MYSQL_PORT 3306
#define BACKLOG 10

/* =============================================================================
   STRUCTS
   ============================================================================= */

// Session structure to track client connections
typedef struct
{
    uint32_t client_id;
    struct sockaddr_in client_addr;
    int socket_fd;
    int account_id;
    char username[64];
    int is_active;
    int is_logged_in;
    time_t last_active;
    char recv_buffer[BUFF_SIZE];
    size_t buffer_len;
} Session;

// Client information structure for P2P connections
typedef struct
{
    uint32_t client_id;
    char ip_address[16];
    int port;
    int account_id;
} ClientInfo;

// File index entry structure
typedef struct
{
    char filename[256];
    uint32_t client_id;
    char ip_address[16];
    int port;
    time_t published_time;
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
void hash_password(const char *password, char *hash_output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[64] = '\0';
}

// Send a response string to a client socket
void send_response(int socket_fd, const char *response)
{
    // Simple send - assumes complete transmission (no partial send handling)
    send(socket_fd, response, strlen(response), 0);
}

// Find the position of "\r\n" (CRLF) in a buffer
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

// Send all data in buffer, handling partial sends
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
            return -1; // Error or client closed connection
        }
        total_sent += n;
    }

    return 0; // Success
}

// Read a line ending with newline from socket
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
            // Client closed connection
            break;
        }
        else
        {
            // Error in recv
            return -1;
        }
    }

    buf[i] = '\0';
    return (int)i;
}

// Logs client transaction activity to a file (logs.txt).
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

    MYSQL_BIND bind[4];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_LONG; 
    bind[0].buffer = (void*)&client_id;

    bind[1].buffer_type = MYSQL_TYPE_LONG; 
    bind[1].buffer = (void*)&account_id;

    bind[2].buffer_type = MYSQL_TYPE_STRING; 
    bind[2].buffer = (void*)ip;
    bind[2].buffer_length = strlen(ip);

    bind[3].buffer_type = MYSQL_TYPE_LONG; 
    bind[3].buffer = (void*)&port;

    if (mysql_stmt_bind_param(stmt, bind)) {
        status = -1;
        goto cleanup;
    }

    if (mysql_stmt_execute(stmt)) {
        status = -1;
    }

cleanup:
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
    return status;
}

// Retrieve client connection information by client ID
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
void handle_sendinfo(Session *session, uint32_t client_id, int p2p_port) {
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); 
        log_server("ERR", "SENDINFO", session, "403");
        return;
    }

    if (p2p_port <= 0 || p2p_port > 65535) {
        send_response(session->socket_fd, "301\r\n"); 
        log_server("ERR", "SENDINFO", session, "301");
        return;
    }

    // Identify client IP from the connection socket
    char *client_ip = inet_ntoa(session->client_addr.sin_addr);
    session->client_id = client_id;

    // Update MySQL database
    if (update_client_info(client_id, session->account_id, client_ip, p2p_port) != 0) {
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SENDINFO", session, "500");
        return;
    }

    send_response(session->socket_fd, "103\r\n"); 
    log_server("OK", "SENDINFO", session, "103");
}

// Handle SEARCH command from client
void handle_search(Session *session, const char *filename) {
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); 
        log_server("ERR", "SEARCH", session, "403");
        return;
    }

    // Prepare SQL Query: Join files and clients to get initial peer info
    const char *query = 
        "SELECT DISTINCT c.client_id, c.ip_address, c.port "
        "FROM files f "
        "JOIN clients c ON f.client_id = c.client_id "
        "WHERE f.filename LIKE CONCAT('%', ?, '%');";

    pthread_mutex_lock(&db_mutex); 
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (!stmt) {
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    // Bind Parameters: Prevent SQL Injection by binding the filename
    MYSQL_BIND bind_param;
    memset(&bind_param, 0, sizeof(bind_param));
    unsigned long filename_len = strlen(filename);
    bind_param.buffer_type = MYSQL_TYPE_STRING;
    bind_param.buffer = (char *)filename;
    bind_param.buffer_length = filename_len;
    bind_param.length = &filename_len;

    mysql_stmt_bind_param(stmt, &bind_param);

    if (mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "SEARCH", session, "500");
        return;
    }

    // Bind Results: Map DB columns to local variables
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

    // Response Processing: Filter by active sessions and send to client
    if (file_found_in_db > 0) {
        send_response(session->socket_fd, "210\r\n");
        log_server("OK", "SEARCH", session, "210");

        char peer_line[256];
        int online_peers = 0;
        
        while (mysql_stmt_fetch(stmt) == 0) {
            res_ip[res_ip_len] = '\0'; 
            pthread_mutex_lock(&session_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (sessions[i].is_active && sessions[i].client_id == res_client_id) {
                    char *current_ip = inet_ntoa(sessions[i].client_addr.sin_addr);
                    int p_len = snprintf(peer_line, sizeof(peer_line), "%u %s %d\r\n", 
                                         res_client_id, current_ip, res_port);
                    send(session->socket_fd, peer_line, p_len, 0);
                    online_peers++;
                    break;
                }
            }
            pthread_mutex_unlock(&session_mutex);
        }
        send(session->socket_fd, "\r\n", 2, 0); 
        log_server("OK", "SEARCH", session, "210");
    } else {
        send_response(session->socket_fd, "404\r\n");
        log_server("OK", "SEARCH", session, "404");
    }
    mysql_stmt_free_result(stmt);
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
}

// Handle REGISTER command from client
void handle_register(Session *session, const char *username, const char *password)
{
    // Check password length (minimum 6 characters)
    if (strlen(password) < 6)
    {
        send_response(session->socket_fd, "400\r\n");
        log_server("ERR", "REGISTER", session, "400");
        return;
    }
    
    pthread_mutex_lock(&db_mutex);
    
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (stmt == NULL)
    {
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    const char *check_sql = "SELECT account_id FROM accounts WHERE username = ?;";
    
    if (mysql_stmt_prepare(stmt, check_sql, strlen(check_sql)) != 0)
    {
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
    
    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on REGISTER check execute: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    mysql_stmt_store_result(stmt);
    
    // Check if username already exists
    if (mysql_stmt_num_rows(stmt) > 0)
    {
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "400\r\n");
        log_server("ERR", "REGISTER", session, "400");
        return;
    }
    mysql_stmt_close(stmt);
    
    char password_hash[PASSWORD_HASH_LENGTH];
    hash_password(password, password_hash);
    
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
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    // Execute insert
    if (mysql_stmt_execute(stmt) != 0)
    {
        // Could be UNIQUE constraint error (username already exists - race condition)
        unsigned int err_no = mysql_stmt_errno(stmt);
        if (err_no == 1062) // ER_DUP_ENTRY
        {
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            send_response(session->socket_fd, "400\r\n");
            log_server("ERR", "REGISTER", session, "400");
            return;
        }
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "REGISTER", session, "500");
        return;
    }
    
    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&db_mutex);
    
    // Send success response
    send_response(session->socket_fd, "101\r\n");
    log_server("OK", "REGISTER", session, "101");
}

// Handle LOGIN command from client
void handle_login(Session *session, const char *username, const char *password)
{
    char password_hash[PASSWORD_HASH_LENGTH];
    hash_password(password, password_hash);
    
    pthread_mutex_lock(&db_mutex);
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (stmt == NULL)
    {
        fprintf(stderr, "[ERROR] Cannot initialize MySQL statement: %s\n", mysql_error(db));
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "LOGIN", session, "500");
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
        log_server("ERR", "LOGIN", session, "500");
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
        log_server("ERR", "LOGIN", session, "500");
        return;
    }
    
    // Execute query
    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "[ERROR] SQL error on LOGIN execute: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "LOGIN", session, "500");
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
        // Found username, compare password hash
        stored_hash[hash_len] = '\0';
        
        if (strcmp(password_hash, stored_hash) == 0)
        {
            // Password correct - login successful
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            
            // Update session
            pthread_mutex_lock(&session_mutex);
            session->account_id = account_id;
            strncpy(session->username, username, sizeof(session->username) - 1);
            session->username[sizeof(session->username) - 1] = '\0';
            session->is_logged_in = 1;
            pthread_mutex_unlock(&session_mutex);
            
            // Send success response
            send_response(session->socket_fd, "102\r\n");
            printf("[INFO] User logged in: username=%s, account_id=%d\n", username, account_id);
            log_server("OK", "LOGIN", session, "102");
            return;
        }
        else
        {
            // Wrong password
            mysql_stmt_close(stmt);
            pthread_mutex_unlock(&db_mutex);
            send_response(session->socket_fd, "401\r\n");
            log_server("ERR", "LOGIN", session, "401");
            return;
        }
    }
    else if (rc == MYSQL_NO_DATA)
    {
        // Username not found
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "401\r\n");
        log_server("ERR", "LOGIN", session, "401");
        return;
    }
    else
    {
        // SQL error
        fprintf(stderr, "[ERROR] SQL error on LOGIN fetch: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&db_mutex);
        send_response(session->socket_fd, "500\r\n");
        log_server("ERR", "LOGIN", session, "500");
        return;
    }
}

// Handle PUBLISH command from client
void handle_publish(Session *session, const char *filename)
{
    char query[BUFF_SIZE];

    // Authorization check
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n"); // Not logged in
        log_server("ERR", "PUBLISH", session, "403");
        return;
    }

    // Validate filename
    if (strlen(filename) == 0 || strlen(filename) > 255) {
        send_response(session->socket_fd, "402\r\n"); // Invalid filename
        log_server("ERR", "PUBLISH", session, "402");
        return;
    }

    // Create database connection
    MYSQL *conn = mysql_init(NULL);
    if (!conn ||
        !mysql_real_connect(conn,
            MYSQL_HOST,
            MYSQL_USER,
            MYSQL_PASSWORD,
            MYSQL_DATABASE,
            0, NULL, 0))
    {
        send_response(session->socket_fd, "500\r\n"); // Server error
        log_server("ERR", "PUBLISH", session, "500");
        return;
    }

    // Prepare and execute SQL query (NO filesize column)
    snprintf(query, sizeof(query),
        "INSERT INTO files (client_id, filename) "
        "VALUES (%u, '%s')",
        session->client_id,
        filename
    );

    if (mysql_query(conn, query)) {
        fprintf(stderr, "[DB-ERR] Publish failed: %s\n", mysql_error(conn));
        send_response(session->socket_fd, "500\r\n"); // Server error
        log_server("ERR", "PUBLISH", session, "500");
    } else {
        send_response(session->socket_fd, "201\r\n"); // Publish successful
        log_server("OK", "PUBLISH", session, "201");
        printf("[INFO] File published: %s by client %u\n", filename, session->client_id);
    }

    mysql_close(conn);
}

// Handle UNPUBLISH command from client
// Command format: UNPUBLISH <filename>
void handle_unpublish(Session *session, const char *filename) {
    char query[BUFF_SIZE];

    // Authorization check
    if (!session->is_logged_in) {
        send_all(session->socket_fd, "403\r\n", 5); // Not logged in
        log_server("ERR", "UNPUBLISH", session, "403");
        return;
    }

    // Validate filename
    if (strlen(filename) == 0 || strlen(filename) > 255) {
        send_all(session->socket_fd, "402\r\n", 5); // Invalid filename
        log_server("ERR", "UNPUBLISH", session, "402");
        return;
    }

    // Create database connection
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        send_response(session->socket_fd, "500\r\n"); // Server error
        log_server("ERR", "UNPUBLISH", session, "500");
        return;
    }

    if (!mysql_real_connect(conn,
            MYSQL_HOST,
            MYSQL_USER,
            MYSQL_PASSWORD,
            MYSQL_DATABASE,
            0,          // port = 0 → use default
            NULL,
            0))
    {
        send_response(session->socket_fd, "500\r\n"); // Server error
        log_server("ERR", "UNPUBLISH", session, "500"); 
        mysql_close(conn);
        return;
    }

    // Delete the file entry that matches both filename and this client's client_id
    snprintf(query, sizeof(query), 
             "DELETE FROM files WHERE client_id = %u AND filename = '%s'", 
             session->client_id, filename);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "[DB-ERR] Unpublish failed: %s\n", mysql_error(conn));
        send_all(session->socket_fd, "500\r\n", 5); // Server error
        log_server("ERR", "UNPUBLISH", session, "500");
    } else {
        // Check if any row was actually deleted
        if (mysql_affected_rows(conn) > 0) {
            printf("[SERVER] Client %u unpublished file: %s\n", session->client_id, filename);
            send_all(session->socket_fd, "202\r\n", 5); // Unpublish successful (changed from 200 to 202)
            log_server("OK", "UNPUBLISH", session, "202");
        } else {
            send_all(session->socket_fd, "404\r\n", 5); // File not found
            log_server("ERR", "UNPUBLISH", session, "404");
        }
    }
    
    mysql_close(conn);
}

void handle_update_status(Session *session, int status_code, const char *filename) {
    // Authorization check
    if (!session->is_logged_in) {
        send_response(session->socket_fd, "403\r\n");
        log_server("ERR", "UPDATE_STATUS", session, "403");
        return;
    }
    
    // Validate status code (only accept 220 or 410)
    if (status_code != 220 && status_code != 410) {
        send_response(session->socket_fd, "300\r\n");
        log_server("ERR", "UPDATE_STATUS", session, "300");
        return;
    }
    
    // Validate filename
    if (strlen(filename) == 0 || strlen(filename) > 255) {
        send_response(session->socket_fd, "300\r\n");
        log_server("ERR", "UPDATE_STATUS", session, "300");
        return;
    }
    
    // Log the status update to console and log file
    char status_str[16];
    if (status_code == 220) {
        strcpy(status_str, "DOWNLOAD_SUCCESS");
    } else {
        strcpy(status_str, "DOWNLOAD_FAILED");
    }
    
    printf("[STATUS] Client %u (%s) reported %s for file: %s\n", 
           session->client_id, session->username, status_str, filename);
    
    // Log to server log file
    char log_code[16];
    snprintf(log_code, sizeof(log_code), "%d", status_code);
    log_server("STATUS", "UPDATE_STATUS", session, log_code);
    
    // Send success response
    send_response(session->socket_fd, "220\r\n");
}

// Handle LOGOUT command from client
// Command format: LOGOUT
void handle_logout(Session *session)
{
    // Check if already logged out
    if (!session->is_logged_in) {
        const char *err = "403\r\n"; // Not logged in
        log_server("ERR", "LOGOUT", session, "403");
        send(session->socket_fd, err, strlen(err), 0);
        return;
    }

    // Log the logout action
    log_server("OK", "LOGOUT", session, "104");

    // Reset session state
    session->is_logged_in = 0;
    session->account_id  = -1;
    session->client_id   = 0;
    memset(session->username, 0, sizeof(session->username));

    // Send success response
    const char *ok = "104\r\n"; // Logout successful
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
    send_response(session->socket_fd, "100\r\n"); // Welcome/connection successful

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

        // Handle AUTHENTICATION commands
        if (strcmp(command, "REGISTER") == 0)
        {
            char username[64], password[64];
            if (sscanf(payload, "%63s %63s", username, password) != 2)
            {
                send_response(session->socket_fd, "300\r\n"); // Invalid format
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
                send_response(session->socket_fd, "300\r\n"); // Invalid format
                printf("[DEBUG-SESSION] ERROR: Invalid LOGIN format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Processing LOGIN: username=%s\n", username);
            handle_login(session, username, password);
        }
        
        // Handle SENDINFO command (Client info for P2P connections)
        else if (strcmp(command, "SENDINFO") == 0)
        {
            uint32_t client_id;
            int port;
            printf("[DEBUG-SESSION] Received SENDINFO command\n");
            printf("[DEBUG-SESSION] Raw payload: %s\n", payload);
            if (sscanf(payload, "%u %d", &client_id, &port) != 2) {
                send_response(session->socket_fd, "300\r\n"); // Invalid format
                printf("[DEBUG-SESSION] ERROR: Invalid SENDINFO format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Parsed SENDINFO: ClientID=%u, Port=%d\n", client_id, port);
            printf("[DEBUG-SESSION] Current session state - Logged in: %d, AccountID: %d, Username: %s\n",
                   session->is_logged_in, session->account_id, session->username);
            handle_sendinfo(session, client_id, port);
        }
        
        // Handle P2P FILE INDEXING commands (Requires Login)
        else if (strcmp(command, "PUBLISH") == 0) {
            char filename[256];
            // Parse without filesize
            if (sscanf(payload, "%255s", filename) != 1) {
                send_response(session->socket_fd, "300\r\n"); // Invalid format
                printf("[DEBUG-SESSION] ERROR: Invalid PUBLISH format\n");
                continue;
            }
            printf("[DEBUG-SESSION] Processing PUBLISH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_publish(session, filename);
        }
        
        else if (strcmp(command, "UNPUBLISH") == 0) {
            printf("[DEBUG-SESSION] Processing UNPUBLISH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_unpublish(session, payload);
        }
        
        // Handle SEARCH command
        else if (strcmp(command, "SEARCH") == 0) {
            printf("[DEBUG-SESSION] Processing SEARCH: %s\n", payload);
            printf("[DEBUG-SESSION] Session logged in: %d\n", session->is_logged_in);
            handle_search(session, payload);
        }

        // Handle UPDATE_STATUS command
        else if (strcmp(command, "UPDATE_STATUS") == 0) {
            int status_code;
            char filename[256];
            if (sscanf(payload, "%d %255s", &status_code, filename) == 2) {
                printf("[DEBUG-SESSION] Processing UPDATE_STATUS: status=%d, file=%s\n", 
                    status_code, filename);
                handle_update_status(session, status_code, filename);
            } else {
                send_response(session->socket_fd, "300\r\n");
                log_server("ERR", "UPDATE_STATUS", session, "300");
                printf("[DEBUG-SESSION] Invalid UPDATE_STATUS format: %s\n", payload);
            }
        }

        // Handle LOGOUT command
        else if (strcmp(command, "LOGOUT") == 0) {
            printf("[DEBUG-SESSION] Processing LOGOUT command\n");
            handle_logout(session);
        }

        // Handle QUIT command
        else if (strcmp(command, "QUIT") == 0) {
            printf("[DEBUG-SESSION] Processing QUIT command\n");
            send_all(session->socket_fd, "221 Goodbye\r\n", 13);
            break;
        }

        // Unknown command handling
        else {
            printf("[DEBUG-SESSION] Unknown command: %s\n", command);
            send_all(session->socket_fd, "300\r\n", 5); // Unknown command
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

/* =============================================================================
   MAIN SERVER LOOP
   ============================================================================= */

int main()
{
    if (init_database() != 0)
    {
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
    
    // MAIN SERVER LOOP - Accept and handle client connections
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
        sessions[slot_idx].client_id = 0;
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