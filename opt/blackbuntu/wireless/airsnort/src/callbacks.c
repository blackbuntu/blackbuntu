#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <semaphore.h>
#else
#include <windows.h>
#include <io.h>
#include "iphlp.h"
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <gtk/gtk.h>

#include "PacketSource.h"
#include "callbacks.h"
#include "interface.h"
#include "support.h"

#include "display.h"
#include "capture.h"
#include "crack.h"
#include "bssidlist.h"
#include "utils.h"

void reallyQuit(void);

#define MAX_INTERFACES 64

int scan = 1;
int oldscan;
unsigned int chan = 6;
unsigned int spinchan = 6;
int funcId = 0;
int doCapture = 0;
#ifndef WIN32
pthread_t capThread;
extern sem_t capture_sem; 
#else
HANDLE capThread;
extern HANDLE capture_sem; 
#endif
int breadth40 = 3;
int breadth128 = 2;
int maxBreadth = 3;
int quitting = 0;
int logfile = 0;
char dumpfile[256] = {0};
int cardType = 0;

static int devNameRealized = 0;

int readPcapFile = 0;

#ifndef WIN32
char *cards[] = { "wlan-ng", "Host AP/Orinoco", "Other", NULL };
#else
char *cards[] = { "Orinoco", "DWL-650", NULL };
#endif

GtkListStore *listStore;
GtkTreeModel *listModel;
GtkTreeView *listWidget;

GtkEntry *cardTypeWidget;

GdkEventButton *popupEvent;
GtkCheckMenuItem *logFileMenu;
GtkCombo *deviceCombo;
char errbuf[PCAP_ERRBUF_SIZE];

void reallyQuit() {
//close packetsource
   doCapture = 0;
#ifndef WIN32
   sem_wait(&capture_sem);
#else
   WaitForSingleObject(capture_sem, INFINITE);
#endif
   if (logfile != -1) {
#ifndef WIN32
      close(logfile);
#else
      _close(logfile);
#endif
   }
   saveOpts();
   gtk_main_quit();
}

/* Function to open a dialog box displaying the message provided. */
void quick_message (gchar *title, gchar *message) {
   GtkWidget *dialog, *label;
   
   /* Create the widgets */
   dialog = gtk_dialog_new_with_buttons (title, NULL,
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_STOCK_OK, GTK_RESPONSE_NONE, NULL);
   label = gtk_label_new (message);
   
   /* Ensure that the dialog box is destroyed when the user responds. */
   g_signal_connect_swapped (GTK_OBJECT (dialog), "response", 
                             G_CALLBACK (gtk_widget_destroy), GTK_OBJECT (dialog));

   /* Add the label, and show everything we've added to the dialog. */
   gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox), label);
   gtk_widget_show_all (dialog);
}

#ifndef WIN32
void fillDeviceList(GtkCombo *combo) {
   struct ifreq ir;
   int count = 0, i = 0;
   int fd = socket(AF_INET, SOCK_STREAM, 0);
   GList *list = NULL;
   for (; count < 32; count++) {
      ir.ifr_ifindex = count;
      if (!ioctl(fd, SIOCGIFNAME, &ir)) {
         ioctl(fd, SIOCGIFFLAGS, &ir);
         if (ir.ifr_flags & IFF_LOOPBACK) {
            continue;
         }
         list = g_list_append(list, strdup(ir.ifr_name));
      }
   }
   close(fd);
   if (list) {
      gtk_combo_set_popdown_strings(combo, list);
      count = g_list_length(list);
      for (i = 0; i < count; i++) {
         free_r(g_list_nth_data(list, i));
      }
      g_list_free (list);
   }
}
#else
typedef DWORD (__stdcall *MYFUNC)(PIP_ADAPTER_INFO, ULONG*);

void fillDeviceList(GtkCombo *combo) {
   static MYFUNC getInfo = NULL;
   PIP_ADAPTER_INFO i, pAdapterInfo = NULL;
   ULONG len = 0, count, j;
   GList *list = NULL;

   if (getInfo == NULL) {
      HINSTANCE iphlpapi = LoadLibrary("iphlpapi");
      if (iphlpapi == NULL) {
         fprintf(stderr, "couldn't load iphlpapi.dll\n");
         return;
      }
      getInfo = (MYFUNC) GetProcAddress(iphlpapi, "GetAdaptersInfo");
      if (getInfo == NULL) {
         fprintf(stderr, "couldn't GetProcAddress for GetAdaptersInfo\n");
         return;
      }
   }

   if (((getInfo)(pAdapterInfo, &len)) == ERROR_BUFFER_OVERFLOW) {
      pAdapterInfo = (PIP_ADAPTER_INFO) malloc_r(len);
      if (pAdapterInfo == NULL) {
         fprintf(stderr, "malloc for pAdapterInfo failed, len = %d\n", len);
         return;
      }
   }
   else {  //failed, since we expected ERROR_BUFFER_OVERFLOW
      fprintf(stderr, "Failed GetAdaptersInfo for size\n");
      return;
   }

   if ((getInfo)(pAdapterInfo, &len) != NO_ERROR) {
      fprintf(stderr, "Failed GetAdaptersInfo\n");
      return;
   }
   fprintf(stderr, "Enumerating network interfaces:\n");
   for (j = 1, i = pAdapterInfo; i; i = i->Next, j++) {
      char *devName = (char*) malloc_r(strlen(i->AdapterName) + 9);
      strcpy(devName, "\\Device\\");
      strcat(devName, i->AdapterName);
      list = g_list_append(list, devName);
      fprintf(stderr, "   %d) %s \"%s\"\n", j, devName, i->Description);
   }
   free_r(pAdapterInfo);
   if (list) {
      gtk_combo_set_popdown_strings(combo, list);
      count = g_list_length(list);
      for (j = 0; j < count; j++) {
         free_r(g_list_nth_data(list, j));
      }
      g_list_free (list);
   }
}
#endif


void
on_AirSnortWindow_realize              (GtkWidget       *widget,
                                        gpointer         user_data)
{
   if (!funcId) {
      funcId = gtk_timeout_add( 500, (GtkFunction) update, user_data); 
   }
}


gboolean
on_AirSnortWindow_delete_event         (GtkWidget       *widget,
                                        GdkEvent        *event,
                                        gpointer         user_data)
{
   on_exit_activate(NULL, user_data);
   return TRUE;
}

void
loadFile(int isPcap) {
   GtkFileSelection *fs;
   if (doCapture) {
      quick_message("Error", "Can't load while capture in progress");
      return;
   }
   fs = GTK_FILE_SELECTION(gtk_file_selection_new(isPcap ? 
                           "Open Capture File" : "Open Crack File"));
   // Connect the ok_button to file_ok_sel function
   g_signal_connect (G_OBJECT (fs->ok_button),
	      "clicked", G_CALLBACK (isPcap ? on_pcap_ok_clicked : loadPacketFile), (gpointer) fs);
   // Connect the ok_button to destroy the widget
   g_signal_connect_swapped (G_OBJECT (fs->ok_button),
              "clicked", G_CALLBACK (gtk_widget_destroy),
	      G_OBJECT (fs));
    
   // Connect the cancel_button to destroy the widget
   g_signal_connect_swapped (G_OBJECT (fs->cancel_button),
                      "clicked", G_CALLBACK (gtk_widget_destroy),
		      G_OBJECT (fs));
    
   gtk_widget_show (GTK_WIDGET(fs));
}

void
on_load_pcap                           (GtkMenuItem     *menuitem,
                                        gpointer         user_data) {
   loadFile(1);
}

void
on_load_crack                          (GtkMenuItem     *menuitem,
                                        gpointer         user_data) {
   loadFile(0);
}

void
saveFile(int isPcap) {
   GtkFileSelection *fs = GTK_FILE_SELECTION(gtk_file_selection_new(isPcap ? 
                                             "Pcap Log File" : "Save Crack File"));
   // Connect the ok_button to file_ok_sel function
   g_signal_connect (G_OBJECT (fs->ok_button),
	      "clicked", G_CALLBACK (isPcap ? on_log_ok_clicked : savePacketData), (gpointer) fs);
   // Connect the ok_button to destroy the widget
   g_signal_connect_swapped (G_OBJECT (fs->ok_button),
              "clicked", G_CALLBACK (gtk_widget_destroy),
	      G_OBJECT (fs));
   // Connect the cancel_button
   g_signal_connect (G_OBJECT (fs->cancel_button),
	      "clicked", G_CALLBACK (isPcap ? on_log_cancel_button_clicked : on_savefile_cancel), (gpointer) fs);
   // Connect the cancel_button to destroy the widget
   g_signal_connect_swapped (G_OBJECT (fs->cancel_button),
              "clicked", G_CALLBACK (gtk_widget_destroy),
	      G_OBJECT (fs));
    
   gtk_widget_show (GTK_WIDGET(fs));
}



void
on_save_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   saveFile(0);
//   gtk_widget_show_all (create_SaveFile());
}


void
on_exit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   if (!head) {
      reallyQuit();
   }
   else {
      GtkDialog *dialog;
      GtkLabel *label;
      gint result;
   
      /* Create the widgets */
      dialog = (GtkDialog*) gtk_dialog_new_with_buttons ("Save Data?", NULL,
                                            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_STOCK_YES, GTK_RESPONSE_YES, 
                                            GTK_STOCK_NO, GTK_RESPONSE_NO, 
                                            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, 
                                            NULL);
      label = (GtkLabel*) gtk_label_new ("Save captured data before exit?");
      /* Add the label, and show everything we've added to the dialog. */
      gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox), GTK_WIDGET(label));
      gtk_widget_show_all(GTK_WIDGET(dialog));

      result = gtk_dialog_run(dialog);
      gtk_widget_destroy(GTK_WIDGET(dialog));
      switch (result) {
         case GTK_RESPONSE_YES:
            quitting = 1;
            saveFile(0);
            break;
         case GTK_RESPONSE_NO:
            reallyQuit();
            break;
         case GTK_RESPONSE_CANCEL:
         case GTK_RESPONSE_NONE:
            break;
      }
   }
}


void
on_clear_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   on_Clear_clicked(NULL, (gpointer)listStore);
}

void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   gtk_widget_show_all (create_AboutDlg());
}

int getCardType() {
   const char *ct = gtk_entry_get_text (cardTypeWidget);
   int i;
   for (i = 0; cards[i]; i++) {
      if (!strcmp(cards[i], ct)) break;
   }
   if (i == OTHER) {
      //tell user that they must set monitor mode manually
      quick_message("Notice", "You must place your card into monitor mode\nmanually.  Channel scan may not be available");
   }
   return i;
}

//Start capturing packets.  Opens a packet source, which places the nic into
//monitor mode, then creates a thread to process captured packets.
void
on_Start_clicked                       (GtkButton       *button,
                                        gpointer         user_data)
{
   CaptureArg *ca;
#ifdef WIN32
   if (WaitForSingleObject(capture_sem, 0) != WAIT_OBJECT_0) return;
#else
   if (sem_trywait(&capture_sem)) return;
#endif
   if (!scan) {
      chan = spinchan;
   }
   cardType = getCardType();
   ca = (CaptureArg*) malloc_r(sizeof(CaptureArg));
   ca->src = openPacketSource(dev, 3000, 1, 0, errbuf, cardType, chan);
   if (ca->src) {
      switch (ca->src->dlType) {
         case DLT_PRISM_HEADER:
            ca->offset = 144;
            break;
         case DLT_EN10MB:      //WTF?  When did Orinoco start reporting this type?
         case DLT_IEEE802_11:
            ca->offset = 0;
            break;
         case DLT_AIRONET_HEADER:
            ca->offset = 0;
            break;
         default: //COOKED
            ca->offset = 160;
      }
      if (*dumpfile) {
         openPacketDumpFile(ca->src, dumpfile);
         dumpfile[0] = 0;
      }
      else {
         ca->src->dump = 0; //NULL;
      }
      doCapture = 1;
#ifndef WIN32
      pthread_create(&capThread, NULL, capture, ca);
#else
      capThread = CreateThread(NULL, 0, capture, ca, 0, NULL);
#endif
   }
}


void
on_Stop_clicked                        (GtkButton       *button,
                                        gpointer         user_data)
{
   doCapture = 0;
}


void
on_freq_changed                        (GtkEditable     *editable,
                                        gpointer         user_data)
{
   spinchan = (unsigned int) gtk_spin_button_get_value_as_int((GtkSpinButton*) editable);
   if (!scan) {
      chan = spinchan; 
      setChannel(cardType, chan);
   }
}


void
on_scan_toggled                        (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
   scan = gtk_toggle_button_get_active(togglebutton); 
   if (!scan) {
      chan = spinchan; 
      setChannel(cardType, chan);
   }
}

void
on_Clear_clicked                       (GtkButton       *button,
                                        gpointer         user_data)
{
   gtk_list_store_clear(listStore);
   clearList();
}

//test for big endian architecture and convert x if required
unsigned int le_to_h(unsigned int x) {
   unsigned int e = 0xFF000000;
   if (*((char*)&e)) {
      unsigned short l = x >> 16;
      unsigned int h = x & 0xFFFF;
      l = (l >> 8) | (l << 8);
      h = (h >> 8) | ((h << 8) & 0xFF00);
      x = l | (h << 16);
   }
   return x;
}

void
loadPacketFile                         (GtkButton       *button,
                                        gpointer         user_data)
{
   PacketInfo pi;
   unsigned char bssid[6], sta[] = {0,0,0,0,0,0};
   unsigned char dummyPacket[200];
   int len;
   unsigned char slen, chan;
   BssidList *b;
   const char *fname = gtk_file_selection_get_filename(GTK_FILE_SELECTION(user_data));
   FILE *fd = fopen(fname, "rb");
   
   pi.bssid = bssid;
   pi.sta = sta;
   pi.raw = dummyPacket;
   pi.wep = 1;
   if (fd) {
      while (fread(&len, 1, sizeof(int), fd) == sizeof(int)) {
         if (fread(bssid, 1, 6, fd) != 6) break;
         if (len == 0) {   //this is name info
            if (fread(&chan, 1, 1, fd) != 1) break;
            pi.channel = chan & 0x0F;
            dummyPacket[178] = chan & 0x10 ? 0 : 0x10;
            if (fread(&slen, 1, 1, fd) != 1) break;
            if (slen > 32) break; //name should not be this long!!!
            if (fread(pi.name, 1, slen, fd) != slen) break;
            pi.name[slen] = 0;
            b = addBssid(&pi);
            b->hasName = 1;
         }
         else {
            len = le_to_h(len);
            pi.channel = 0;
            pi.pack = (Packet *) malloc_r(sizeof(Packet));
            pi.pack->len = len - 6;
            pi.iv = pi.pack->buf = (unsigned char *) malloc_r(pi.pack->len);
            pi.pack->next = NULL;
            len = fread(pi.pack->buf, 1, pi.pack->len, fd);
            if (len != pi.pack->len) {
               free_r(pi.pack->buf);
               free_r(pi.pack);
               break;
            }
            addPacket(NULL, &pi, 1);
         }
      }
      fclose(fd);
   }
}

/***********************************************************

  format of saved data:

  For ksample packets:

  4 byte integer length of 802.11b data = n+6 (includes bssid)
  6 byte bssid
  n bytes of packet data
     3 byte IV
     n-3 bytes of data w/ 802.11b checksum at the end

  For sample packets

  4 byte integer length = 11
  6 byte bssid
  5 bytes of packet data
     3 byte IV
     1 dummy byte = 0
     1 byte = first byte of 802.11b data (the 0xAA byte)

  For AP name information

  4 byte integer length = 0
  6 byte bssid
  1 byte channel number
  1 byte length of name = n
  n byte AP name

************************************************************/

void
savePacketData                         (GtkButton       *button,
                                        gpointer         user_data)
{
   unsigned char first, dummy = 0;
   Packet *pkt;
   Sample *samp;
   BssidList *temp = head;
   int len, i;
   unsigned char uch;
   const char *fname = gtk_file_selection_get_filename(GTK_FILE_SELECTION(user_data));
   FILE *fd = fopen(fname, "wb");
   if (fd) {
      for (; temp; temp = temp->next) {
         if (temp->hasName) {
            len = 0;
            fwrite(&len, 1, sizeof(int), fd);
            fwrite(temp->bssid, 1, 6, fd);
            uch = temp->channel;
//            uch |= temp->usingWep ? 0 : 0x10;
            fwrite(&uch, 1, 1, fd);
            uch = strlen(temp->name);
            fwrite(&uch, 1, 1, fd);
            fwrite(temp->name, 1, uch, fd);
         }
         if (temp->ap) {
            for (pkt = temp->ap->pkts; pkt; pkt = pkt->next) {
               len = le_to_h(pkt->len + 6);
               fwrite(&len, 1, sizeof(int), fd);
               fwrite(temp->bssid, 1, 6, fd);
               fwrite(pkt->buf, 1, pkt->len, fd);
            }
            len = le_to_h(11);
            for (i = 0; i < 13; i++) {
               for (samp = temp->ap->samples[i]; samp; samp = samp->next) {
                  fwrite(&len, 1, sizeof(int), fd);
                  fwrite(temp->bssid, 1, 6, fd);
                  fwrite(samp->iv, 1, 3, fd);
                  fwrite(&dummy, 1, 1, fd);
                  first = samp->firstByte ^ 0xAA;
                  fwrite(&first, 1, 1, fd);
               }
            }
         }
      }
   }
   fclose(fd);
   if (quitting) {
      reallyQuit();
   }
}

void
on_savefile_cancel                     (GtkButton       *button,
                                        gpointer         user_data)
{
   if (quitting) {
      reallyQuit();
   }
}

void
on_stats_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
}

void
on_stop_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
}


void
on_gps_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   gtk_widget_show_all (create_GpsDialog());
}


void
on_GpsOk_clicked                       (GtkButton       *button,
                                        gpointer         user_data)
{

}

void
on_log_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
   logFileMenu = GTK_CHECK_MENU_ITEM(menuitem);
   if (logFileMenu->active) {
      saveFile(1);
//      gtk_widget_show_all (create_LogFile());
   }
   else if (logfile) {  //file is open, time to close
//      close(logfile);
//      logfile = -1;
   }
}

void
on_log_ok_clicked                      (GtkButton       *button,
                                        gpointer         user_data)
{
   //this will only take effect when user clicks start to begin a capture
   strncpy(dumpfile, gtk_file_selection_get_filename(GTK_FILE_SELECTION(user_data)), sizeof(dumpfile));
   dumpfile[sizeof(dumpfile) - 1] = 0;
}

void
on_log_cancel_button_clicked           (GtkButton       *button,
                                        gpointer         user_data)
{
   gtk_check_menu_item_set_active(logFileMenu, 0);
}

void
on_pcap_ok_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
   CaptureArg *ca = (CaptureArg*) malloc_r(sizeof(CaptureArg));
   const char *fname = gtk_file_selection_get_filename(GTK_FILE_SELECTION(user_data));
   ca->src = openOfflinePacketSource(fname, errbuf);
   if (ca->src) {
      switch (ca->src->dlType) {
         case DLT_PRISM_HEADER:
            ca->offset = 144;
            break;
         default: //DLT_IEEE802_11
            ca->offset = 0;
      }
      ca->src->dump = 0; //NULL;
      oldscan = scan;
      scan = 0;
      doCapture = 1;
      readPcapFile = 1;
#ifndef WIN32
      pthread_create(&capThread, NULL, capture, ca);
#else
      capThread = CreateThread(NULL, 0, capture, ca, 0, NULL);
#endif
   }

}

void
on_DeviceName_changed                  (GtkEditable     *editable,
                                        gpointer         user_data)
{
   if (devNameRealized) {
      strncpy(dev, gtk_entry_get_text(GTK_ENTRY(editable)), WLAN_DEVNAMELEN_MAX);
      dev[WLAN_DEVNAMELEN_MAX - 1] = 0;
   }
}

void breadthChanged(void) {
   BssidList *node;
   for (node = head; node; node = node->next) {
      if (node->usingWep && !node->ap->cracked) {
         node->newBreadth = 1;
         checkThread(node);
//         sem_post(&(node->crackSem));
      }
   }
}

void
on_breadth40_changed                   (GtkEditable     *editable,
                                        gpointer         user_data)
{
   breadth40 = gtk_spin_button_get_value_as_int((GtkSpinButton*) editable);
   maxBreadth = breadth40 < breadth128 ? breadth128 : breadth40;
   breadthChanged();
}


void
on_breadth128_changed                  (GtkEditable     *editable,
                                        gpointer         user_data)
{
   breadth128 = gtk_spin_button_get_value_as_int((GtkSpinButton*) editable);
   maxBreadth = breadth40 < breadth128 ? breadth128 : breadth40;
   breadthChanged();
}


void
on_freq_realize                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
   gtk_spin_button_set_value((GtkSpinButton*) widget, chan);
}


void
on_CardType_realize                    (GtkWidget       *widget,
                                        gpointer         user_data)
{
   int i;
   cardTypeWidget = GTK_ENTRY(widget);
   for (i = 0; cards[i]; i++);
   if (cardType < 0 || cardType >= i) cardType = 0;
   gtk_entry_set_text (cardTypeWidget, cards[cardType]);
}

void
on_CardList_realize                    (GtkWidget       *widget,
                                        gpointer         user_data)
{
   GtkCombo *c = GTK_COMBO(widget);
   GList *list = NULL;
   int i;
   for (i = 0; cards[i]; i++) {
      list = g_list_append(list, cards[i]);
   }
   if (list) {
      gtk_combo_set_popdown_strings(c, list);
      g_list_free (list);
   }
}

void
on_breadth40_realize                   (GtkWidget       *widget,
                                        gpointer         user_data)
{
   gtk_spin_button_set_value((GtkSpinButton*) widget, (float)breadth40);
}


void
on_breadth128_realize                  (GtkWidget       *widget,
                                        gpointer         user_data)
{
   gtk_spin_button_set_value((GtkSpinButton*) widget, (float)breadth128);
}


void
on_refresh_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
   fillDeviceList(deviceCombo);
}


void
on_deviceCombo_realize                 (GtkWidget       *widget,
                                        gpointer         user_data)
{
   fillDeviceList(GTK_COMBO(widget));
   deviceCombo = GTK_COMBO(widget);
}

void
on_DataList_realize                    (GtkWidget       *widget,
                                        gpointer         user_data)
{
   GtkCellRenderer *renderer;
   GtkTreeViewColumn *column;

   listStore = gtk_list_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, 
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_STRING);
   listModel = GTK_TREE_MODEL(listStore);
   listWidget = GTK_TREE_VIEW(widget);

   gtk_tree_view_set_model(listWidget, listModel);
   renderer = gtk_cell_renderer_text_new();

   column = gtk_tree_view_column_new_with_attributes ("C", renderer,
                                                      "text", CRACK_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("BSSID", renderer,
                                                      "text", SSID_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Name", renderer,
                                                      "text", NAME_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("WEP", renderer,
                                                      "text", WEP_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Last Seen", renderer,
                                                      "text", TIME_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Last IV", renderer,
                                                      "text", IV_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Chan", renderer,
                                                      "text", CHAN_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Packets", renderer,
                                                      "text", TOTAL_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Encrypted", renderer,
                                                      "text", ENCRYPTED_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Interesting", renderer,
                                                      "text", INTERESTING_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("Unique", renderer,
                                                      "text", UNIQUE_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("PW: Hex", renderer,
                                                      "text", PWHEX_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

   column = gtk_tree_view_column_new_with_attributes ("PW: ASCII", renderer,
                                                      "text", PWASC_COL,
                                                      NULL);
   gtk_tree_view_column_set_resizable(column, TRUE);
   gtk_tree_view_append_column (GTK_TREE_VIEW (listWidget), column);

}

void
on_versionLabel_realize                     (GtkWidget       *widget,
                                        gpointer         user_data)
{
   GtkLabel *progname = GTK_LABEL(widget);
   char version[80];
#ifdef HAVE_CONFIG_H
   snprintf(version, sizeof(version), "AirSnort v%s", VERSION);
#else
   strcpy(version, "AirSnort Windows");
#endif
   gtk_label_set_text(progname, version);
}


void
on_DeviceName_realize                  (GtkWidget       *widget,
                                        gpointer         user_data)
{
   gtk_entry_set_text (GTK_ENTRY(widget), dev);
   devNameRealized = 1;
}

