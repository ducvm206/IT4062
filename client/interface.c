#include <gtk/gtk.h>
#include <string.h>
#include "interface.h"

/* Import từ client.c */
extern ClientState g_client;
int connect_to_server(const char *server_ip, int server_port);
int handle_login(int sock, const char *username, const char *password);
int handle_register(int sock, const char *username, const char *password);

/* GTK widgets */
static GtkWidget *entry_username;
static GtkWidget *entry_password;
static GtkWidget *window;

/* Utility dialog */
static void show_message(const char *msg, GtkMessageType type) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(window),
        GTK_DIALOG_MODAL,
        type,
        GTK_BUTTONS_OK,
        "%s",
        msg
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Login button callback */
static void on_login_clicked(GtkButton *button, gpointer user_data) {
    const char *username = gtk_entry_get_text(GTK_ENTRY(entry_username));
    const char *password = gtk_entry_get_text(GTK_ENTRY(entry_password));

    if (strlen(username) == 0 || strlen(password) == 0) {
        show_message("Username and password cannot be empty.", GTK_MESSAGE_WARNING);
        return;
    }

    if (handle_login(g_client.server_socket, username, password) == 0) {
        show_message("Login successful.", GTK_MESSAGE_INFO);

        /* TODO: Open Dashboard window */
        gtk_widget_destroy(window);
    } else {
        show_message("Login failed.", GTK_MESSAGE_ERROR);
    }
}

/* Register button callback */
static void on_register_clicked(GtkButton *button, gpointer user_data) {
    const char *username = gtk_entry_get_text(GTK_ENTRY(entry_username));
    const char *password = gtk_entry_get_text(GTK_ENTRY(entry_password));

    if (strlen(username) == 0 || strlen(password) == 0) {
        show_message("Username and password cannot be empty.", GTK_MESSAGE_WARNING);
        return;
    }

    if (handle_register(g_client.server_socket, username, password) == 0) {
        show_message("Register successful. You can now log in.", GTK_MESSAGE_INFO);
    } else {
        show_message("Register failed.", GTK_MESSAGE_ERROR);
    }
}
