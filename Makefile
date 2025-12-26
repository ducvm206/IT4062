# =========================
# Compiler & flags
# =========================
CC      = gcc
CFLAGS  = -Wall -Wextra -g
GTKFLAGS = $(shell pkg-config --cflags --libs gtk+-3.0)
LIBS    = -lpthread

# =========================
# Directories
# =========================
CLIENT_DIR = client
UI_DIR     = client/ui
SERVER_DIR = server

# =========================
# Targets
# =========================
CLIENT_BIN = client/client
SERVER_BIN = server/server

# =========================
# Source files
# =========================

CLIENT_SRCS = \
    client/client.c \
    client/ui/interface.c \
    client/ui/auth/auth.c \
    client/ui/dashboard/dashboard.c \
    client/ui/search/search.c

SERVER_SRCS = \
    server/server.c

# =========================
# Object files
# =========================
CLIENT_OBJS = $(CLIENT_SRCS:.c=.o)
SERVER_OBJS = $(SERVER_SRCS:.c=.o)

# =========================
# Default target
# =========================
all: $(CLIENT_BIN) $(SERVER_BIN)

# =========================
# Client build
# =========================
$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTKFLAGS) $(LIBS)

# =========================
# Server build
# =========================
$(SERVER_BIN): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lmysqlclient -lpthread -lcrypto

# =========================
# Compile .c → .o
# =========================
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(GTKFLAGS)

# =========================
# Clean
# =========================
clean:
	rm -f $(CLIENT_OBJS) $(SERVER_OBJS) $(CLIENT_BIN) $(SERVER_BIN)

# =========================
# Rebuild
# =========================
re: clean all
