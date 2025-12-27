#include "auth.h"
#include "../dashboard/dashboard.h"
#include "../../client.h"
#include "../interface.h"
#include <gtk/gtk.h>

static GtkWidget *entry_user;
static GtkWidget *entry_pass;
static GtkWidget *status_label;
static gboolean auth_exiting = TRUE;


/* Helper: set status text */
static void set_status(const char *msg, gboolean success)
{
    gtk_label_set_text(GTK_LABEL(status_label), msg);

    if (success) {
        gtk_widget_set_name(status_label, "status-success");
    } else {
        gtk_widget_set_name(status_label, "status-error");
    }
}

/* LOGIN */
static void on_login_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    GtkWidget *window = GTK_WIDGET(data);

    const char *user = gtk_entry_get_text(GTK_ENTRY(entry_user));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(entry_pass));

    if (strlen(user) == 0 || strlen(pass) == 0) {
        set_status("Username and password cannot be empty", FALSE);
        return;
    }

    if (handle_login(g_client.server_socket, user, pass) == 0) {
        g_client.is_logged_in = 1;

        /* 🚨 ĐÁNH DẤU: KHÔNG PHẢI THOÁT APP */
        auth_exiting = FALSE;

        gtk_widget_destroy(window);   // chỉ đóng auth
        show_dashboard_screen();      // mở dashboard
    } else {
        set_status("Login failed. Invalid username or password.", FALSE);
    }
}


/* REGISTER */
static void on_register_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;

    const char *user = gtk_entry_get_text(GTK_ENTRY(entry_user));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(entry_pass));

    if (strlen(user) == 0 || strlen(pass) == 0) {
        set_status("Username and password cannot be empty", FALSE);
        return;
    }

    if (handle_register(g_client.server_socket, user, pass) == 0) {
        set_status("Register successful. You can login now.", TRUE);
    } else {
        set_status("Register failed. Username may already exist.", FALSE);
    }
}

static void on_auth_window_destroy(GtkWidget *widget, gpointer data)
{
    (void)widget;
    (void)data;

    if (auth_exiting) {
        /* Người dùng bấm ❌ */
        if (g_client.server_socket >= 0) {
            disconnect_from_server(g_client.server_socket);
            g_client.server_socket = -1;
        }
        gtk_main_quit();
    }
}


/* BUILD AUTH VIEW */
GtkWidget* create_auth_view(GtkWidget *window)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(outer), 20);

    /* Title */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<span font_desc='20'><b>P2P File Sharing</b></span>");
    gtk_box_pack_start(GTK_BOX(outer), title, FALSE, FALSE, 10);

    /* Username */
    entry_user = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_user), "Username");

    /* Password */
    entry_pass = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_pass), "Password");
    gtk_entry_set_visibility(GTK_ENTRY(entry_pass), FALSE);

    /* Status label */
    status_label = gtk_label_new("");
    gtk_widget_set_halign(status_label, GTK_ALIGN_START);

    /* Buttons */
    GtkWidget *btn_login = gtk_button_new_with_label("Login");
    GtkWidget *btn_register = gtk_button_new_with_label("Register");

    g_signal_connect(btn_login, "clicked",
                     G_CALLBACK(on_login_clicked), window);
    g_signal_connect(btn_register, "clicked",
                     G_CALLBACK(on_register_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(outer), entry_user, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), entry_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), status_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), btn_login, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(outer), btn_register, FALSE, FALSE, 0);

    return outer;
}

/* SHOW AUTH WINDOW */
void auth_show(void)
{
    auth_exiting = TRUE;   // mỗi lần mở auth là trạng thái "thoát"

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Login / Register");
    gtk_window_set_default_size(GTK_WINDOW(window), 360, 280);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    g_signal_connect(window, "destroy",
                     G_CALLBACK(on_auth_window_destroy), NULL);

    GtkWidget *auth_view = create_auth_view(window);
    gtk_container_add(GTK_CONTAINER(window), auth_view);

    gtk_widget_show_all(window);
}