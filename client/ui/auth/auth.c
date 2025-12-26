#include "auth.h"
#include "../dashboard/dashboard.h"
#include "../../client.h"
#include "../interface.h"
#include <gtk/gtk.h>

static GtkWidget *entry_user;
static GtkWidget *entry_pass;

static void on_login_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    GtkWidget *window = GTK_WIDGET(data);

    const char *user = gtk_entry_get_text(GTK_ENTRY(entry_user));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(entry_pass));

    if (handle_login(g_client.server_socket, user, pass) == 0) {
        g_client.is_logged_in = 1;

        gtk_widget_destroy(window);      // đóng auth window
        show_dashboard_screen();         // 👉 MỞ DASHBOARD
    }
}

static void on_register_clicked(GtkButton *btn, gpointer data)
{
    const char *user = gtk_entry_get_text(GTK_ENTRY(entry_user));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(entry_pass));

    handle_register(g_client.server_socket, user, pass);
}

GtkWidget* create_auth_view(GtkWidget *window)  // Add parameter to match header
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    entry_user = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_user), "Username");

    entry_pass = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_pass), "Password");
    gtk_entry_set_visibility(GTK_ENTRY(entry_pass), FALSE);

    GtkWidget *btn_login = gtk_button_new_with_label("Login");
    GtkWidget *btn_register = gtk_button_new_with_label("Register");

    // Pass window as user data to the callback
    g_signal_connect(btn_login, "clicked", G_CALLBACK(on_login_clicked), window);
    g_signal_connect(btn_register, "clicked", G_CALLBACK(on_register_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(box), entry_user, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), entry_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_login, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_register, FALSE, FALSE, 0);

    return box;
}

void auth_show(void)
{
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Login / Register");
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 200);
    
    GtkWidget *auth_view = create_auth_view(window);  // Now correct - passes window
    gtk_container_add(GTK_CONTAINER(window), auth_view);
    
    gtk_widget_show_all(window);
}