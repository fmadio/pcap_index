//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// Generate structured index for the specified pcap 
// 
// Index format is
//
// Packet (n  ) [ 64bit LE nanoseccond EPOCH time | 64bit byte offset into the PCAP ]
// Packet (n+1) [ 64bit LE nanoseccond EPOCH time | 64bit byte offset into the PCAP ]
// Packet (n+2) [ 64bit LE nanoseccond EPOCH time | 64bit byte offset into the PCAP ]
//
// this enables a simple bisection search function to find a specific packet`s timestamp 
// without having to parse the entire pcap
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"

// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1
#define PCAPHEADER_LINK_ERF			197	

typedef struct
{
	u32				Sec;				// time stamp sec since epoch 
	u32				NSec;				// nsec fraction since epoch

	u32				LengthCapture;		// captured length, inc trailing / aligned data
	u32				Length;				// length on the wire

} __attribute__((packed)) PCAPPacket_t;

// per file header

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;

double TSC2Nano = 0;

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	fprintf(stderr, "pcap_index -o <output base>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --verify <path to fmadio index file>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "NOTE: Input PCAP`s are always read from STDIN\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Example: cat test8k.pcap  | ./pcap_split  > test8k.index\n"); 
	fprintf(stderr, "\n");
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* VerifyFileName = NULL;

	u64 TargetByte = 0;
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		else if (strcmp(argv[i], "--verify") == 0)
		{
			VerifyFileName = argv[i+1];
			i++;
		}
	}
	u64 StartTS					= clock_ns();
	u64 PCAPOffset				= 0;
	u64 TotalPkt				= 0;

	FILE* FIn = stdin; 
	assert(FIn != NULL);

	FILE* Verify = NULL;
	if (VerifyFileName)
	{
		Verify = fopen(VerifyFileName, "r");

		// skip PCAP header
		fseek(Verify, sizeof(PCAPHeader_t), SEEK_SET);
	}

	// read header
	PCAPHeader_t HeaderMaster;
	int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FIn);
	if (rlen != sizeof(HeaderMaster))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return 0;
	}
	PCAPOffset		= sizeof(PCAPHeader_t);

	u64 TScale = 0;
	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: fprintf(stderr, "PCAP Nano\n"); TScale = 1;    break;
	case PCAPHEADER_MAGIC_USEC: fprintf(stderr, "PCAP Micro\n"); TScale = 1000; break;
	}

	FILE* OutFile 				= stdout;
	u64 LastTS					= 0;

	u8* 			Pkt			= malloc(1024*1024);	
	PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)Pkt;

	while (!feof(FIn))
	{

		// header 
		int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FIn);
		if (rlen != sizeof(PCAPPacket_t)) break;

		// validate size
		if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
		{
			fprintf(stderr, "Invalid packet length: %i\n", PktHeader->LengthCapture);
			break;
		}

		// payload
		rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FIn);
		if (rlen != PktHeader->LengthCapture)
		{
			fprintf(stderr, "payload read fail %i expect %i\n", rlen, PktHeader->LengthCapture);
			break;
		}
		LastTS = (u64)PktHeader->Sec * 1000000000ULL + (u64)PktHeader->NSec * TScale;

		u64 Header[2];
		Header[0] = LastTS;
		Header[1] = PCAPOffset;
		fwrite(Header, 1, sizeof(u64)*2, OutFile);

		// verify against fmadio index generator
		if (Verify)
		{
			u64 VHeader[2];
			int rlen = fread(VHeader, 1, sizeof(u64)*2, Verify);
			if ((Header[0] != VHeader[0]) || (Header[1] != VHeader[1]))
			{
				fprintf(stderr, "[%lli]ERROR: TimeStamp %llx %llx : Offset %016llx %016llx\n", TotalPkt, Header[0], VHeader[0], Header[1], VHeader[1]);
			}
		}

		PCAPOffset 	+= sizeof(PCAPPacket_t);
		PCAPOffset 	+= PktHeader->LengthCapture; 
		TotalPkt	+= 1;

		if ((TotalPkt % (u64)100e3) == 0)
		{
			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (PCAPOffset * 8.0) / dT; 
			fprintf(stderr, "[%.3f H][%s] : Total Bytes %.3f GB Speed: %.3fGbps\n", dT / (60*60), TimeStr, PCAPOffset / 1e9, Bps / 1e9);
		}
	}
	fclose(OutFile);

	return 0;
}

