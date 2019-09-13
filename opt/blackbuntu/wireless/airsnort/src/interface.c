/*
 * DO NOT EDIT THIS FILE - it is generated by Glade.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

#define GLADE_HOOKUP_OBJECT(component,widget,name) \
  g_object_set_data_full (G_OBJECT (component), name, \
    gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)

#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) \
  g_object_set_data (G_OBJECT (component), name, widget)

GtkWidget*
create_AirSnortWindow (void)
{
  GtkWidget *AirSnortWindow;
  GtkWidget *vbox1;
  GtkWidget *menu;
  GtkWidget *file;
  GtkWidget *file_menu;
  GtkWidget *load;
  GtkWidget *save;
  GtkWidget *log;
  GtkWidget *load_pcap_file;
  GtkWidget *separator1;
  GtkWidget *exit;
  GtkWidget *edit;
  GtkWidget *edit_menu;
  GtkWidget *clear;
  GtkWidget *settings;
  GtkWidget *settings_menu;
  GtkWidget *gps;
  GtkWidget *help;
  GtkWidget *help_menu;
  GtkWidget *about;
  GtkWidget *vbox4;
  GtkWidget *hbox1;
  GtkWidget *table2;
  GtkWidget *scan;
  GSList *scan_group = NULL;
  GtkWidget *channel;
  GtkObject *freq_adj;
  GtkWidget *freq;
  GtkWidget *vseparator1;
  GtkWidget *table4;
  GtkWidget *label25;
  GtkWidget *label26;
  GtkWidget *CardList;
  GtkWidget *CardType;
  GtkWidget *refresh;
  GtkWidget *deviceCombo;
  GtkWidget *DeviceName;
  GtkWidget *vseparator2;
  GtkWidget *table5;
  GtkWidget *label27;
  GtkObject *breadth40_adj;
  GtkWidget *breadth40;
  GtkWidget *label28;
  GtkObject *breadth128_adj;
  GtkWidget *breadth128;
  GtkWidget *scrolledwindow1;
  GtkWidget *DataList;
  GtkWidget *hbuttonbox1;
  GtkWidget *Start;
  GtkWidget *Stop;
  GtkWidget *Clear;
  GtkTooltips *tooltips;

  tooltips = gtk_tooltips_new ();

  AirSnortWindow = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title (GTK_WINDOW (AirSnortWindow), "AirSnort");

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (AirSnortWindow), vbox1);

  menu = gtk_menu_bar_new ();
  gtk_widget_show (menu);
  gtk_box_pack_start (GTK_BOX (vbox1), menu, FALSE, FALSE, 0);

  file = gtk_menu_item_new_with_mnemonic ("_File");
  gtk_widget_show (file);
  gtk_container_add (GTK_CONTAINER (menu), file);

  file_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (file), file_menu);

  load = gtk_menu_item_new_with_mnemonic ("_Load crack file");
  gtk_widget_show (load);
  gtk_container_add (GTK_CONTAINER (file_menu), load);

  save = gtk_menu_item_new_with_mnemonic ("_Save crack file");
  gtk_widget_show (save);
  gtk_container_add (GTK_CONTAINER (file_menu), save);

  log = gtk_check_menu_item_new_with_mnemonic ("Log to file");
  gtk_widget_show (log);
  gtk_container_add (GTK_CONTAINER (file_menu), log);

  load_pcap_file = gtk_menu_item_new_with_mnemonic ("Load pcap file");
  gtk_widget_show (load_pcap_file);
  gtk_container_add (GTK_CONTAINER (file_menu), load_pcap_file);

  separator1 = gtk_menu_item_new ();
  gtk_widget_show (separator1);
  gtk_container_add (GTK_CONTAINER (file_menu), separator1);
  gtk_widget_set_sensitive (separator1, FALSE);

  exit = gtk_menu_item_new_with_mnemonic ("E_xit");
  gtk_widget_show (exit);
  gtk_container_add (GTK_CONTAINER (file_menu), exit);

  edit = gtk_menu_item_new_with_mnemonic ("_Edit");
  gtk_widget_show (edit);
  gtk_container_add (GTK_CONTAINER (menu), edit);

  edit_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (edit), edit_menu);

  clear = gtk_menu_item_new_with_mnemonic ("Clear");
  gtk_widget_show (clear);
  gtk_container_add (GTK_CONTAINER (edit_menu), clear);

  settings = gtk_menu_item_new_with_mnemonic ("Settings");
  gtk_widget_show (settings);
  gtk_container_add (GTK_CONTAINER (menu), settings);

  settings_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (settings), settings_menu);

  gps = gtk_menu_item_new_with_mnemonic ("_Gps");
  gtk_widget_show (gps);
  gtk_container_add (GTK_CONTAINER (settings_menu), gps);
  gtk_tooltips_set_tip (tooltips, gps, "GPS Settings", NULL);

  help = gtk_menu_item_new_with_mnemonic ("_Help");
  gtk_widget_show (help);
  gtk_container_add (GTK_CONTAINER (menu), help);

  help_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (help), help_menu);

  about = gtk_menu_item_new_with_mnemonic ("About");
  gtk_widget_show (about);
  gtk_container_add (GTK_CONTAINER (help_menu), about);

  vbox4 = gtk_vbox_new (FALSE, 3);
  gtk_widget_show (vbox4);
  gtk_box_pack_start (GTK_BOX (vbox1), vbox4, TRUE, TRUE, 3);

  hbox1 = gtk_hbox_new (FALSE, 11);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox4), hbox1, FALSE, TRUE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (hbox1), 2);

  table2 = gtk_table_new (2, 2, FALSE);
  gtk_widget_show (table2);
  gtk_box_pack_start (GTK_BOX (hbox1), table2, TRUE, FALSE, 0);
  gtk_table_set_row_spacings (GTK_TABLE (table2), 2);
  gtk_table_set_col_spacings (GTK_TABLE (table2), 1);

  scan = gtk_radio_button_new_with_mnemonic (NULL, "scan");
  gtk_widget_show (scan);
  gtk_table_attach (GTK_TABLE (table2), scan, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_radio_button_set_group (GTK_RADIO_BUTTON (scan), scan_group);
  scan_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (scan));
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (scan), TRUE);

  channel = gtk_radio_button_new_with_mnemonic (NULL, "channel");
  gtk_widget_show (channel);
  gtk_table_attach (GTK_TABLE (table2), channel, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_radio_button_set_group (GTK_RADIO_BUTTON (channel), scan_group);
  scan_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (channel));

  freq_adj = gtk_adjustment_new (6, 1, 11, 1, 10, 10);
  freq = gtk_spin_button_new (GTK_ADJUSTMENT (freq_adj), 1, 0);
  gtk_widget_show (freq);
  gtk_table_attach (GTK_TABLE (table2), freq, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (freq), TRUE);
  gtk_spin_button_set_update_policy (GTK_SPIN_BUTTON (freq), GTK_UPDATE_IF_VALID);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (freq), TRUE);

  vseparator1 = gtk_vseparator_new ();
  gtk_widget_show (vseparator1);
  gtk_box_pack_start (GTK_BOX (hbox1), vseparator1, FALSE, FALSE, 0);

  table4 = gtk_table_new (2, 3, FALSE);
  gtk_widget_show (table4);
  gtk_box_pack_start (GTK_BOX (hbox1), table4, TRUE, FALSE, 0);
  gtk_table_set_row_spacings (GTK_TABLE (table4), 2);
  gtk_table_set_col_spacings (GTK_TABLE (table4), 3);

  label25 = gtk_label_new ("Network device");
  gtk_widget_show (label25);
  gtk_table_attach (GTK_TABLE (table4), label25, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (label25), GTK_JUSTIFY_CENTER);

  label26 = gtk_label_new ("Driver type");
  gtk_widget_show (label26);
  gtk_table_attach (GTK_TABLE (table4), label26, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (label26), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (label26), 0, 0.5);

  CardList = gtk_combo_new ();
  g_object_set_data (G_OBJECT (GTK_COMBO (CardList)->popwin),
                     "GladeParentKey", CardList);
  gtk_widget_show (CardList);
  gtk_table_attach (GTK_TABLE (table4), CardList, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_combo_set_value_in_list (GTK_COMBO (CardList), TRUE, FALSE);

  CardType = GTK_COMBO (CardList)->entry;
  gtk_widget_show (CardType);
  gtk_editable_set_editable (GTK_EDITABLE (CardType), FALSE);

  refresh = gtk_button_new_with_mnemonic ("Refresh");
  gtk_widget_show (refresh);
  gtk_table_attach (GTK_TABLE (table4), refresh, 2, 3, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  deviceCombo = gtk_combo_new ();
  g_object_set_data (G_OBJECT (GTK_COMBO (deviceCombo)->popwin),
                     "GladeParentKey", deviceCombo);
  gtk_widget_show (deviceCombo);
  gtk_table_attach (GTK_TABLE (table4), deviceCombo, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  DeviceName = GTK_COMBO (deviceCombo)->entry;
  gtk_widget_show (DeviceName);

  vseparator2 = gtk_vseparator_new ();
  gtk_widget_show (vseparator2);
  gtk_box_pack_start (GTK_BOX (hbox1), vseparator2, FALSE, FALSE, 0);

  table5 = gtk_table_new (2, 2, FALSE);
  gtk_widget_show (table5);
  gtk_box_pack_start (GTK_BOX (hbox1), table5, TRUE, FALSE, 0);
  gtk_table_set_row_spacings (GTK_TABLE (table5), 1);

  label27 = gtk_label_new ("40 bit crack breadth:");
  gtk_widget_show (label27);
  gtk_table_attach (GTK_TABLE (table5), label27, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (label27), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (label27), 0, 0.5);

  breadth40_adj = gtk_adjustment_new (3, 1, 20, 1, 10, 10);
  breadth40 = gtk_spin_button_new (GTK_ADJUSTMENT (breadth40_adj), 1, 0);
  gtk_widget_show (breadth40);
  gtk_table_attach (GTK_TABLE (table5), breadth40, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (breadth40), TRUE);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (breadth40), TRUE);

  label28 = gtk_label_new ("128 bit crack breadth: ");
  gtk_widget_show (label28);
  gtk_table_attach (GTK_TABLE (table5), label28, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (label28), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (label28), 0, 0.5);

  breadth128_adj = gtk_adjustment_new (2, 1, 20, 1, 10, 10);
  breadth128 = gtk_spin_button_new (GTK_ADJUSTMENT (breadth128_adj), 1, 0);
  gtk_widget_show (breadth128);
  gtk_table_attach (GTK_TABLE (table5), breadth128, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (breadth128), TRUE);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (breadth128), TRUE);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (vbox4), scrolledwindow1, TRUE, TRUE, 0);
  GTK_WIDGET_UNSET_FLAGS (scrolledwindow1, GTK_CAN_FOCUS);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow1), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scrolledwindow1), GTK_SHADOW_IN);

  DataList = gtk_tree_view_new ();
  gtk_widget_show (DataList);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), DataList);
  gtk_container_set_border_width (GTK_CONTAINER (DataList), 1);

  hbuttonbox1 = gtk_hbutton_box_new ();
  gtk_widget_show (hbuttonbox1);
  gtk_box_pack_start (GTK_BOX (vbox4), hbuttonbox1, FALSE, TRUE, 0);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox1), GTK_BUTTONBOX_SPREAD);
  gtk_box_set_spacing (GTK_BOX (hbuttonbox1), 30);

  Start = gtk_button_new_with_mnemonic ("Start");
  gtk_widget_show (Start);
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), Start);

  Stop = gtk_button_new_with_mnemonic ("Stop");
  gtk_widget_show (Stop);
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), Stop);

  Clear = gtk_button_new_with_mnemonic ("Clear");
  gtk_widget_show (Clear);
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), Clear);

  g_signal_connect_swapped ((gpointer) AirSnortWindow, "realize",
                            G_CALLBACK (on_AirSnortWindow_realize),
                            GTK_OBJECT (DataList));
  g_signal_connect ((gpointer) AirSnortWindow, "delete_event",
                    G_CALLBACK (on_AirSnortWindow_delete_event),
                    NULL);
  g_signal_connect ((gpointer) load, "activate",
                    G_CALLBACK (on_load_crack),
                    NULL);
  g_signal_connect ((gpointer) save, "activate",
                    G_CALLBACK (on_save_activate),
                    NULL);
  g_signal_connect ((gpointer) log, "activate",
                    G_CALLBACK (on_log_activate),
                    NULL);
  g_signal_connect ((gpointer) load_pcap_file, "activate",
                    G_CALLBACK (on_load_pcap),
                    NULL);
  g_signal_connect ((gpointer) exit, "activate",
                    G_CALLBACK (on_exit_activate),
                    NULL);
  g_signal_connect ((gpointer) clear, "activate",
                    G_CALLBACK (on_clear_activate),
                    NULL);
  g_signal_connect ((gpointer) gps, "activate",
                    G_CALLBACK (on_gps_activate),
                    NULL);
  g_signal_connect ((gpointer) about, "activate",
                    G_CALLBACK (on_about_activate),
                    NULL);
  g_signal_connect ((gpointer) scan, "toggled",
                    G_CALLBACK (on_scan_toggled),
                    NULL);
  g_signal_connect ((gpointer) freq, "changed",
                    G_CALLBACK (on_freq_changed),
                    NULL);
  g_signal_connect ((gpointer) freq, "realize",
                    G_CALLBACK (on_freq_realize),
                    NULL);
  g_signal_connect ((gpointer) CardList, "realize",
                    G_CALLBACK (on_CardList_realize),
                    NULL);
  g_signal_connect ((gpointer) CardType, "realize",
                    G_CALLBACK (on_CardType_realize),
                    NULL);
  g_signal_connect ((gpointer) refresh, "clicked",
                    G_CALLBACK (on_refresh_clicked),
                    NULL);
  g_signal_connect ((gpointer) deviceCombo, "realize",
                    G_CALLBACK (on_deviceCombo_realize),
                    NULL);
  g_signal_connect ((gpointer) DeviceName, "changed",
                    G_CALLBACK (on_DeviceName_changed),
                    NULL);
  g_signal_connect ((gpointer) DeviceName, "realize",
                    G_CALLBACK (on_DeviceName_realize),
                    NULL);
  g_signal_connect ((gpointer) breadth40, "changed",
                    G_CALLBACK (on_breadth40_changed),
                    NULL);
  g_signal_connect ((gpointer) breadth40, "realize",
                    G_CALLBACK (on_breadth40_realize),
                    NULL);
  g_signal_connect ((gpointer) breadth128, "changed",
                    G_CALLBACK (on_breadth128_changed),
                    NULL);
  g_signal_connect ((gpointer) breadth128, "realize",
                    G_CALLBACK (on_breadth128_realize),
                    NULL);
  g_signal_connect ((gpointer) DataList, "realize",
                    G_CALLBACK (on_DataList_realize),
                    NULL);
  g_signal_connect ((gpointer) Start, "clicked",
                    G_CALLBACK (on_Start_clicked),
                    NULL);
  g_signal_connect ((gpointer) Stop, "clicked",
                    G_CALLBACK (on_Stop_clicked),
                    NULL);
  g_signal_connect ((gpointer) Clear, "clicked",
                    G_CALLBACK (on_Clear_clicked),
                    NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
  GLADE_HOOKUP_OBJECT_NO_REF (AirSnortWindow, AirSnortWindow, "AirSnortWindow");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, vbox1, "vbox1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, menu, "menu");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, file, "file");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, file_menu, "file_menu");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, load, "load");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, save, "save");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, log, "log");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, load_pcap_file, "load_pcap_file");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, separator1, "separator1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, exit, "exit");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, edit, "edit");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, edit_menu, "edit_menu");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, clear, "clear");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, settings, "settings");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, settings_menu, "settings_menu");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, gps, "gps");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, help, "help");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, help_menu, "help_menu");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, about, "about");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, vbox4, "vbox4");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, hbox1, "hbox1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, table2, "table2");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, scan, "scan");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, channel, "channel");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, freq, "freq");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, vseparator1, "vseparator1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, table4, "table4");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, label25, "label25");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, label26, "label26");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, CardList, "CardList");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, CardType, "CardType");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, refresh, "refresh");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, deviceCombo, "deviceCombo");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, DeviceName, "DeviceName");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, vseparator2, "vseparator2");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, table5, "table5");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, label27, "label27");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, breadth40, "breadth40");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, label28, "label28");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, breadth128, "breadth128");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, scrolledwindow1, "scrolledwindow1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, DataList, "DataList");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, hbuttonbox1, "hbuttonbox1");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, Start, "Start");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, Stop, "Stop");
  GLADE_HOOKUP_OBJECT (AirSnortWindow, Clear, "Clear");
  GLADE_HOOKUP_OBJECT_NO_REF (AirSnortWindow, tooltips, "tooltips");

  return AirSnortWindow;
}

GtkWidget*
create_AboutDlg (void)
{
  GtkWidget *AboutDlg;
  GtkWidget *dialog_vbox1;
  GtkWidget *vbox2;
  GtkWidget *versionLabel;
  GtkWidget *label29;
  GtkWidget *label16;
  GtkWidget *dialog_action_area1;
  GtkWidget *button1;

  AboutDlg = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (AboutDlg), "About Airsnort");
  gtk_window_set_modal (GTK_WINDOW (AboutDlg), TRUE);
  gtk_window_set_type_hint (GTK_WINDOW (AboutDlg), GDK_WINDOW_TYPE_HINT_DIALOG);

  dialog_vbox1 = GTK_DIALOG (AboutDlg)->vbox;
  gtk_widget_show (dialog_vbox1);

  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), vbox2, TRUE, FALSE, 0);

  versionLabel = gtk_label_new ("AirSnort");
  gtk_widget_show (versionLabel);
  gtk_box_pack_start (GTK_BOX (vbox2), versionLabel, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (versionLabel), GTK_JUSTIFY_CENTER);

  label29 = gtk_label_new ("Copyright (c) 2002, Snax");
  gtk_widget_show (label29);
  gtk_box_pack_start (GTK_BOX (vbox2), label29, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label29), GTK_JUSTIFY_CENTER);

  label16 = gtk_label_new ("Copyright (c) 2001, Jeremy Bruestle and Blake Hegerle");
  gtk_widget_show (label16);
  gtk_box_pack_start (GTK_BOX (vbox2), label16, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label16), GTK_JUSTIFY_CENTER);

  dialog_action_area1 = GTK_DIALOG (AboutDlg)->action_area;
  gtk_widget_show (dialog_action_area1);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

  button1 = gtk_button_new_with_mnemonic ("Okay");
  gtk_widget_show (button1);
  gtk_dialog_add_action_widget (GTK_DIALOG (AboutDlg), button1, 0);

  g_signal_connect ((gpointer) versionLabel, "realize",
                    G_CALLBACK (on_versionLabel_realize),
                    NULL);
  g_signal_connect_swapped ((gpointer) button1, "clicked",
                            G_CALLBACK (gtk_widget_destroy),
                            GTK_OBJECT (AboutDlg));

  /* Store pointers to all widgets, for use by lookup_widget(). */
  GLADE_HOOKUP_OBJECT_NO_REF (AboutDlg, AboutDlg, "AboutDlg");
  GLADE_HOOKUP_OBJECT_NO_REF (AboutDlg, dialog_vbox1, "dialog_vbox1");
  GLADE_HOOKUP_OBJECT (AboutDlg, vbox2, "vbox2");
  GLADE_HOOKUP_OBJECT (AboutDlg, versionLabel, "versionLabel");
  GLADE_HOOKUP_OBJECT (AboutDlg, label29, "label29");
  GLADE_HOOKUP_OBJECT (AboutDlg, label16, "label16");
  GLADE_HOOKUP_OBJECT_NO_REF (AboutDlg, dialog_action_area1, "dialog_action_area1");
  GLADE_HOOKUP_OBJECT (AboutDlg, button1, "button1");

  return AboutDlg;
}

GtkWidget*
create_ListPopup (void)
{
  GtkWidget *ListPopup;
  GtkWidget *stats;
  GtkWidget *delete;
  GtkWidget *stop;

  ListPopup = gtk_menu_new ();

  stats = gtk_menu_item_new_with_mnemonic ("Display Statistics");
  gtk_widget_show (stats);
  gtk_container_add (GTK_CONTAINER (ListPopup), stats);

  delete = gtk_menu_item_new_with_mnemonic ("Delete");
  gtk_widget_show (delete);
  gtk_container_add (GTK_CONTAINER (ListPopup), delete);

  stop = gtk_menu_item_new_with_mnemonic ("Stop");
  gtk_widget_show (stop);
  gtk_container_add (GTK_CONTAINER (ListPopup), stop);

  g_signal_connect ((gpointer) stats, "activate",
                    G_CALLBACK (on_stats_activate),
                    NULL);
  g_signal_connect ((gpointer) stop, "activate",
                    G_CALLBACK (on_stop_activate),
                    NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
  GLADE_HOOKUP_OBJECT_NO_REF (ListPopup, ListPopup, "ListPopup");
  GLADE_HOOKUP_OBJECT (ListPopup, stats, "stats");
  GLADE_HOOKUP_OBJECT (ListPopup, delete, "delete");
  GLADE_HOOKUP_OBJECT (ListPopup, stop, "stop");

  return ListPopup;
}

GtkWidget*
create_GpsDialog (void)
{
  GtkWidget *GpsDialog;
  GtkWidget *dialog_vbox4;
  GtkWidget *vbox5;
  GtkWidget *vbox6;
  GtkWidget *hbox2;
  GtkWidget *GpsEnable;
  GSList *GpsEnable_group = NULL;
  GtkWidget *hbox3;
  GtkWidget *GpsDisable;
  GtkWidget *table3;
  GtkWidget *GpsDevice;
  GtkWidget *GpsSpeed;
  GtkWidget *GpsFormat;
  GtkWidget *DevCombo;
  GList *DevCombo_items = NULL;
  GtkWidget *combo_entry1;
  GtkWidget *SpeedCombo;
  GList *SpeedCombo_items = NULL;
  GtkWidget *combo_entry2;
  GtkWidget *FormatCombo;
  GList *FormatCombo_items = NULL;
  GtkWidget *combo_entry3;
  GtkWidget *dialog_action_area4;
  GtkWidget *GpsOk;
  GtkWidget *GpsCancel;

  GpsDialog = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (GpsDialog), "Gps Settings");
  gtk_window_set_modal (GTK_WINDOW (GpsDialog), TRUE);
  gtk_window_set_type_hint (GTK_WINDOW (GpsDialog), GDK_WINDOW_TYPE_HINT_DIALOG);

  dialog_vbox4 = GTK_DIALOG (GpsDialog)->vbox;
  gtk_widget_show (dialog_vbox4);

  vbox5 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox5);
  gtk_box_pack_start (GTK_BOX (dialog_vbox4), vbox5, TRUE, TRUE, 0);

  vbox6 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox6);
  gtk_box_pack_start (GTK_BOX (vbox5), vbox6, FALSE, TRUE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (vbox6), 10);

  hbox2 = gtk_hbox_new (TRUE, 0);
  gtk_widget_show (hbox2);
  gtk_box_pack_start (GTK_BOX (vbox6), hbox2, FALSE, FALSE, 0);

  GpsEnable = gtk_radio_button_new_with_mnemonic (NULL, "enable");
  gtk_widget_show (GpsEnable);
  gtk_box_pack_start (GTK_BOX (hbox2), GpsEnable, FALSE, FALSE, 0);
  gtk_radio_button_set_group (GTK_RADIO_BUTTON (GpsEnable), GpsEnable_group);
  GpsEnable_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (GpsEnable));

  hbox3 = gtk_hbox_new (TRUE, 0);
  gtk_widget_show (hbox3);
  gtk_box_pack_start (GTK_BOX (vbox6), hbox3, FALSE, FALSE, 0);

  GpsDisable = gtk_radio_button_new_with_mnemonic (NULL, "disable");
  gtk_widget_show (GpsDisable);
  gtk_box_pack_start (GTK_BOX (hbox3), GpsDisable, FALSE, FALSE, 0);
  gtk_radio_button_set_group (GTK_RADIO_BUTTON (GpsDisable), GpsEnable_group);
  GpsEnable_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (GpsDisable));
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (GpsDisable), TRUE);

  table3 = gtk_table_new (3, 2, TRUE);
  gtk_widget_show (table3);
  gtk_box_pack_start (GTK_BOX (vbox5), table3, TRUE, FALSE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (table3), 5);
  gtk_table_set_row_spacings (GTK_TABLE (table3), 10);

  GpsDevice = gtk_label_new ("Device");
  gtk_widget_show (GpsDevice);
  gtk_table_attach (GTK_TABLE (table3), GpsDevice, 0, 1, 0, 1,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (GpsDevice), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (GpsDevice), 0, 0.5);

  GpsSpeed = gtk_label_new ("Speed");
  gtk_widget_show (GpsSpeed);
  gtk_table_attach (GTK_TABLE (table3), GpsSpeed, 0, 1, 1, 2,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (GpsSpeed), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (GpsSpeed), 0, 0.5);

  GpsFormat = gtk_label_new ("Format");
  gtk_widget_show (GpsFormat);
  gtk_table_attach (GTK_TABLE (table3), GpsFormat, 0, 1, 2, 3,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (GpsFormat), GTK_JUSTIFY_CENTER);
  gtk_misc_set_alignment (GTK_MISC (GpsFormat), 0, 0.5);

  DevCombo = gtk_combo_new ();
  g_object_set_data (G_OBJECT (GTK_COMBO (DevCombo)->popwin),
                     "GladeParentKey", DevCombo);
  gtk_widget_show (DevCombo);
  gtk_table_attach (GTK_TABLE (table3), DevCombo, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  DevCombo_items = g_list_append (DevCombo_items, (gpointer) "");
  gtk_combo_set_popdown_strings (GTK_COMBO (DevCombo), DevCombo_items);
  g_list_free (DevCombo_items);

  combo_entry1 = GTK_COMBO (DevCombo)->entry;
  gtk_widget_show (combo_entry1);

  SpeedCombo = gtk_combo_new ();
  g_object_set_data (G_OBJECT (GTK_COMBO (SpeedCombo)->popwin),
                     "GladeParentKey", SpeedCombo);
  gtk_widget_show (SpeedCombo);
  gtk_table_attach (GTK_TABLE (table3), SpeedCombo, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND),
                    (GtkAttachOptions) (0), 0, 0);
  SpeedCombo_items = g_list_append (SpeedCombo_items, (gpointer) "");
  gtk_combo_set_popdown_strings (GTK_COMBO (SpeedCombo), SpeedCombo_items);
  g_list_free (SpeedCombo_items);

  combo_entry2 = GTK_COMBO (SpeedCombo)->entry;
  gtk_widget_show (combo_entry2);

  FormatCombo = gtk_combo_new ();
  g_object_set_data (G_OBJECT (GTK_COMBO (FormatCombo)->popwin),
                     "GladeParentKey", FormatCombo);
  gtk_widget_show (FormatCombo);
  gtk_table_attach (GTK_TABLE (table3), FormatCombo, 1, 2, 2, 3,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  FormatCombo_items = g_list_append (FormatCombo_items, (gpointer) "");
  gtk_combo_set_popdown_strings (GTK_COMBO (FormatCombo), FormatCombo_items);
  g_list_free (FormatCombo_items);

  combo_entry3 = GTK_COMBO (FormatCombo)->entry;
  gtk_widget_show (combo_entry3);

  dialog_action_area4 = GTK_DIALOG (GpsDialog)->action_area;
  gtk_widget_show (dialog_action_area4);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area4), GTK_BUTTONBOX_END);

  GpsOk = gtk_button_new_with_mnemonic ("Okay");
  gtk_widget_show (GpsOk);
  gtk_dialog_add_action_widget (GTK_DIALOG (GpsDialog), GpsOk, 0);

  GpsCancel = gtk_button_new_with_mnemonic ("Cancel");
  gtk_widget_show (GpsCancel);
  gtk_dialog_add_action_widget (GTK_DIALOG (GpsDialog), GpsCancel, 0);

  g_signal_connect ((gpointer) GpsOk, "clicked",
                    G_CALLBACK (on_GpsOk_clicked),
                    NULL);
  g_signal_connect_swapped ((gpointer) GpsOk, "clicked",
                            G_CALLBACK (gtk_widget_destroy),
                            GTK_OBJECT (GpsDialog));
  g_signal_connect_swapped ((gpointer) GpsCancel, "clicked",
                            G_CALLBACK (gtk_widget_destroy),
                            GTK_OBJECT (GpsDialog));

  /* Store pointers to all widgets, for use by lookup_widget(). */
  GLADE_HOOKUP_OBJECT_NO_REF (GpsDialog, GpsDialog, "GpsDialog");
  GLADE_HOOKUP_OBJECT_NO_REF (GpsDialog, dialog_vbox4, "dialog_vbox4");
  GLADE_HOOKUP_OBJECT (GpsDialog, vbox5, "vbox5");
  GLADE_HOOKUP_OBJECT (GpsDialog, vbox6, "vbox6");
  GLADE_HOOKUP_OBJECT (GpsDialog, hbox2, "hbox2");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsEnable, "GpsEnable");
  GLADE_HOOKUP_OBJECT (GpsDialog, hbox3, "hbox3");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsDisable, "GpsDisable");
  GLADE_HOOKUP_OBJECT (GpsDialog, table3, "table3");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsDevice, "GpsDevice");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsSpeed, "GpsSpeed");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsFormat, "GpsFormat");
  GLADE_HOOKUP_OBJECT (GpsDialog, DevCombo, "DevCombo");
  GLADE_HOOKUP_OBJECT (GpsDialog, combo_entry1, "combo_entry1");
  GLADE_HOOKUP_OBJECT (GpsDialog, SpeedCombo, "SpeedCombo");
  GLADE_HOOKUP_OBJECT (GpsDialog, combo_entry2, "combo_entry2");
  GLADE_HOOKUP_OBJECT (GpsDialog, FormatCombo, "FormatCombo");
  GLADE_HOOKUP_OBJECT (GpsDialog, combo_entry3, "combo_entry3");
  GLADE_HOOKUP_OBJECT_NO_REF (GpsDialog, dialog_action_area4, "dialog_action_area4");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsOk, "GpsOk");
  GLADE_HOOKUP_OBJECT (GpsDialog, GpsCancel, "GpsCancel");

  return GpsDialog;
}

