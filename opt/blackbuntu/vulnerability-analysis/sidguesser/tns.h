
#ifdef WIN32
#pragma pack( push, 1 )
#endif

#ifndef byte
typedef unsigned char byte;
#endif

struct tTNS_Header {

	short nPacketLen;
	short nPacketCSum;
	byte nPacketType; /* CONNECT */
	byte nReserved;
	short nHeaderCSum;
	short nVersion;
	short nVCompat;
	short nSOptions;
	short nUnitSize;
	short nMaxUSize;
	short nProtoC;
	short nLineTV;
	short nValOf1;
	short nLenOfCD;/* Length of connect data */
	short nOffCD;/* offset of connect data */
	int nMaxRecvData;
	byte bFlags0;
	byte bFlags1;
#ifdef WIN32
};
#else
} __attribute__ ((packed)) ;
#endif
