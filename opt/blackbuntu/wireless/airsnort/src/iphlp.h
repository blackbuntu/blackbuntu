
#ifndef __IPHLPAPI_H
#define __IPHLPAPI_H

#include <time.h>

#define MAX_ADAPTER_ADDRESS_LENGTH 8
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_NAME_LENGTH 256

typedef struct {
  char String[16];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;

typedef struct _IP_ADDR_STRING {
  struct _IP_ADDR_STRING* Next;
  IP_ADDRESS_STRING IpAddress;
  IP_MASK_STRING IpMask;
  DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO {
  struct _IP_ADAPTER_INFO* Next;
  DWORD ComboIndex;
  char AdapterName[MAX_ADAPTER_NAME_LENGTH+4];
  char Description[MAX_ADAPTER_DESCRIPTION_LENGTH+4];
  UINT AddressLength;
  BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
  DWORD Index;
  UINT Type;
  UINT DhcpEnabled;
  PIP_ADDR_STRING CurrentIpAddress;
  IP_ADDR_STRING IpAddressList;
  IP_ADDR_STRING GatewayList;
  IP_ADDR_STRING DhcpServer;
  BOOL HaveWins;
  IP_ADDR_STRING PrimaryWinsServer;
  IP_ADDR_STRING SecondaryWinsServer;
  time_t LeaseObtained;
  time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;

#endif