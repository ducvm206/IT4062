#include "dashboard.h"
#include "../interface.h"
#include "../../client.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

/* =========================
 * Widgets
 * ========================= */
static GtkWidget *window;
static GtkWidget *file_list;

/* =========================
 * Helpers
 * ========================= */

/* Refresh list from index.txt */
static void refresh_shared_file_list(void)
{
    GList *rows, *iter;

    rows = gtk_container_get_children(GTK_CONTAINER(file_list));
    for (iter = rows; iter != NULL; iter = g_list_next(iter)) {
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    }
    g_list_free(rows);

    load_shared_files();

    for (int i = 0; i < g_shared_files.count; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *label = gtk_label_new(g_shared_files.files[i].filename);

        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_container_add(GTK_CONTAINER(row), label);
        gtk_list_box_insert(GTK_LIST_BOX(file_list), row, -1);
    }

    gtk_widget_show_all(file_list);
}


/* =========================
 * Callbacks
 * ========================= */

static void on_publish_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Select file to share",
        GTK_WINDOW(window),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Share", GTK_RESPONSE_ACCEPT,
        NULL
    );

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filepath = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

        const char *filename = strrchr(filepath, '/');
        filename = filename ? filename + 1 : filepath;

        if (handle_publish(g_client.server_socket, filename, filepath) == 0) {
            refresh_shared_file_list();
        }

        g_free(filepath);
    }

    gtk_widget_destroy(dialog);
}

static void on_unpublish_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;

    GtkListBoxRow *row =
        gtk_list_box_get_selected_row(GTK_LIST_BOX(file_list));

    if (!row) {
        g_print("[WARN] No file selected\n");
        return;
    }

    GtkWidget *label = gtk_bin_get_child(GTK_BIN(row));
    const char *filename = gtk_label_get_text(GTK_LABEL(label));

    if (!filename || strlen(filename) == 0)
        return;

    if (handle_unpublish(g_client.server_socket, filename) == 0) {
        refresh_shared_file_list();
    }
}

static void on_refresh_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;
    refresh_shared_file_list();
}

static void on_search_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;
    gtk_widget_destroy(window);
    interface_show_search();
}

static void on_logout_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;

    client_logout();
    gtk_widget_destroy(window);
    show_auth_screen();
}

/* =========================
 * UI Builder
 * ========================= */

static GtkWidget* create_dashboard_view(void)
{
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(root), 10);

    /* Header */
    char title[128];
    snprintf(title, sizeof(title), "Welcome, %s", g_client.username);
    GtkWidget *label_title = gtk_label_new(title);
    gtk_widget_set_halign(label_title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(root), label_title, FALSE, FALSE, 0);

    /* Buttons */
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    GtkWidget *btn_publish   = gtk_button_new_with_label("Publish");
    GtkWidget *btn_unpublish = gtk_button_new_with_label("Unpublish");
    GtkWidget *btn_refresh   = gtk_button_new_with_label("Refresh");
    GtkWidget *btn_search    = gtk_button_new_with_label("Search");
    GtkWidget *btn_logout    = gtk_button_new_with_label("Logout");

    g_signal_connect(btn_publish, "clicked", G_CALLBACK(on_publish_clicked), NULL);
    g_signal_connect(btn_unpublish, "clicked", G_CALLBACK(on_unpublish_clicked), NULL);
    g_signal_connect(btn_refresh, "clicked", G_CALLBACK(on_refresh_clicked), NULL);
    g_signal_connect(btn_search,  "clicked", G_CALLBACK(on_search_clicked), NULL);
    g_signal_connect(btn_logout,  "clicked", G_CALLBACK(on_logout_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(btn_box), btn_publish,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_unpublish, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_refresh,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_search,    FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(btn_box), btn_logout,    FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), btn_box, FALSE, FALSE, 0);

    /* File list */
    GtkWidget *frame = gtk_frame_new("Shared Files");

    file_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(
        GTK_LIST_BOX(file_list),
        GTK_SELECTION_SINGLE
    );

    gtk_container_add(GTK_CONTAINER(frame), file_list);
    gtk_box_pack_start(GTK_BOX(root), frame, TRUE, TRUE, 0);

    refresh_shared_file_list();
    return root;
}

/* =========================
 * Public API
 * ========================= */

void dashboard_show(void)
{
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Dashboard");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);

    GtkWidget *view = create_dashboard_view();
    gtk_container_add(GTK_CONTAINER(window), view);

    gtk_widget_show_all(window);
}
