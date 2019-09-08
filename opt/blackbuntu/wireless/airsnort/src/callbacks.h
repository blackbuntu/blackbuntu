#include <gtk/gtk.h>

void
on_AirSnortWindow_realize              (GtkWidget       *widget,
                                        gpointer         user_data);

gboolean
on_AirSnortWindow_delete_event         (GtkWidget       *widget,
                                        GdkEvent        *event,
                                        gpointer         user_data);

void
on_load_pcap                           (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_load_crack                          (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_save_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_exit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_clear_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Start_clicked                       (GtkButton       *button,
                                        gpointer         user_data);

void
on_Stop_clicked                        (GtkButton       *button,
                                        gpointer         user_data);

void
on_freq_changed                        (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_scan_toggled                        (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_Clear_clicked                       (GtkButton       *button,
                                        gpointer         user_data);

void
loadPacketFile                         (GtkButton       *button,
                                        gpointer         user_data);

void
savePacketData                         (GtkButton       *button,
                                        gpointer         user_data);

void
on_savefile_cancel                     (GtkButton       *button,
                                        gpointer         user_data);

void quick_message(char *title, char *message);

void myPositionFunc(GtkMenu *menu, int *x, int *y, gpointer data);

void
on_stats_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_stop_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_gps_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_GpsOk_clicked                       (GtkButton       *button,
                                        gpointer         user_data);

void
on_log_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_log_ok_clicked                      (GtkButton       *button,
                                        gpointer         user_data);

void
on_log_cancel_button_clicked           (GtkButton       *button,
                                        gpointer         user_data);

void
on_pcap_ok_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_DeviceName_changed                  (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_breadth40_changed                   (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_breadth128_changed                  (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_freq_realize                        (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_CardType_realize                    (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_breadth40_realize                   (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_breadth128_realize                  (GtkWidget       *widget,
                                        gpointer         user_data);


void
on_refresh_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_deviceCombo_realize                 (GtkWidget       *widget,
                                        gpointer         user_data);


void
on_DataList_realize                    (GtkWidget       *widget,
                                        gpointer         user_data);



void
on_CardList_realize                    (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_versionLabel_realize                (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_DeviceName_realize                  (GtkWidget       *widget,
                                        gpointer         user_data);
