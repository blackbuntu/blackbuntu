#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (!TRUE)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

#ifdef WIN32
#define getkey() getch();
#else
#define getkey() getchar();
#endif

#ifdef WIN32
#define snprintf _snprintf
#else
#define stricmp strcasecmp
#endif

const int PACKET_TYPE_OFFSET = 0x04;

const int TNS_CONNECT = 0x01;
const int TNS_REFUSE  = 0x04;
const int TNS_REDIRECT= 0x05;
const int TNS_RESEND  = 0x0b;

const char* VERSION = "v1.0.5";
const char* AUTHOR = "patrik@cqure.net";

const int MODE_FIND_FIRST = 0x01;
const int MODE_FIND_ALL   = 0x02;

double m_nTries=0, m_nDicItems, m_nStartTM;
int m_bVerbose = 0, m_bQuit = FALSE, m_nMode;
char m_sCurrSID[512];
