#pragma once
#include <stdint.h>
#include <Windows.h>
#include <Tlhelp32.h>

typedef struct _LIST_ENTRY32 {
	uint32_t Flink;
	uint32_t Blink;
} UCLIST_ENTRY32, *PUCLIST_ENTRY32;

typedef struct _PEB_LDR_DATA32 {
	BYTE       Reserved1[8];
	uint32_t      Reserved2[3];
	UCLIST_ENTRY32 InMemoryOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32 {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	uint32_t                         Reserved3[2];
	uint32_t                 Ldr;
	uint32_t  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	uint32_t PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	uint32_t                         Reserved7[1];
	uint32_t                         SessionId;
} PEB32, *PPEB32;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct _LDR_DATA_TABLE_ENTRY {                             //  x86  /  x64
	struct _LIST_ENTRY32          InLoadOrderLinks;            // 0x000 / 0x000
	struct _LIST_ENTRY32          InMemoryOrderLinks;          // 0x008 / 0x010
	union {                                                  // 0x010 / 0x020
		struct _LIST_ENTRY32        InInitializationOrderLinks;
		struct _LIST_ENTRY32        InProgressLinks;
	};
	void                       *DllBase;                     // 0x018 / 0x030
	void                       *EntryPoint;                  // 0x01c / 0x038
	union {                                                  // 0x020 / 0x040
		uint32_t                  SizeOfImage;
		void                     *AlignDummy1;                 // <-- This is just here to clearify implicit alignment before next member
	};
	struct _UNICODE_STRING      FullDllName;                 // 0x024 / 0x048
	struct _UNICODE_STRING      BaseDllName;                 // 0x02c / 0x058
	union {                                                  // 0x034 / 0x068
		uint8_t                   FlagGroup[4];
		uint32_t                  Flags;
		struct {
			uint32_t                PackagedBinary : 1;
			uint32_t                MarkedForRemoval : 1;
			uint32_t                ImageDll : 1;
			uint32_t                LoadNotificationsSent : 1;
			uint32_t                TelemetryEntryProcessed : 1;
			uint32_t                ProcessStaticImport : 1;
			uint32_t                InLegacyLists : 1;
			uint32_t                InIndexes : 1;
			uint32_t                ShimDll : 1;
			uint32_t                InExceptionTable : 1;
			uint32_t                ReservedFlags1 : 2;
			uint32_t                LoadInProgress : 1;
			uint32_t                ReservedFlags2 : 1;
			uint32_t                EntryProcessed : 1;
			uint32_t                ReservedFlags3 : 3;
			uint32_t                DontCallForThreads : 1;
			uint32_t                ProcessAttachCalled : 1;
			uint32_t                ProcessAttachFailed : 1;
			uint32_t                CorDeferredValidate : 1;
			uint32_t                CorImage : 1;
			uint32_t                DontRelocate : 1;
			uint32_t                CorILOnly : 1;
			uint32_t                ReservedFlags5 : 3;
			uint32_t                Redirected : 1;
			uint32_t                ReservedFlags6 : 2;
			uint32_t                CompatDatabaseProcessed : 1;
		};
	};
	uint16_t                    ObsoleteLoadCount;           // 0x038 / 0x06c
	uint16_t                    TlsIndex;                    // 0x03a / 0x06e
	union {                                                  // 0x03c / 0x070
		struct _LIST_ENTRY        HashLinks;
		struct {                                               // Obsolete in Windows 8
			void                   *SectionPointer;
			uint32_t                CheckSum;
		};
	};
	union {                                                  // 0x044 / 0x080
		uint32_t                  TimeDateStamp;
		void                     *LoadedImports;               // Obsolete in win8
	};
	struct _ACTIVATION_CONTEXT *EntryPointActivationContext; // 0x048 / 0x088
	void                       *PatchInformation;            // 0x04c / 0x090
};


#pragma pack(push, 1)
struct SegmentDescriptor {
	union {
		struct {
			unsigned short limit0;
			unsigned short base0;
			unsigned char base1;
			unsigned char type : 4;
			unsigned char system : 1;      /* S flag */
			unsigned char dpl : 2;
			unsigned char present : 1;     /* P flag */
			unsigned char limit1 : 4;
			unsigned char avail : 1;
			unsigned char is_64_code : 1;  /* L flag */
			unsigned char db : 1;          /* DB flag */
			unsigned char granularity : 1; /* G flag */
			unsigned char base2;
		};
		uint64_t desc;
	};
};
#pragma pack(pop)

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

/************************************************************************/
/* Kills all open Processes                                             */
/************************************************************************/
DWORD GetModuleSize(HMODULE HDLL)
{
	HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hModSnap == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 me;
	me.dwSize = sizeof(me);

	if (!Module32First(hModSnap, &me)) {
		return 0;
	}

	do
	{
		if (me.hModule == HDLL)
		{
			CloseHandle(hModSnap);
			return me.modBaseSize;
		}
	} while (Module32Next(hModSnap, &me));


	CloseHandle(hModSnap);

	return 0;
}


/************************************************************************/
/* This function enabled the debug privilege                            */
/************************************************************************/
void EnableDebugPrivilege()
{
	TOKEN_PRIVILEGES	priv;
	HANDLE				hThis, hToken;
	LUID				luid;

	hThis = GetCurrentProcess();
	OpenProcessToken(hThis, TOKEN_ADJUST_PRIVILEGES, &hToken);
	LookupPrivilegeValue(0, "seDebugPrivilege", &luid);
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0);
	CloseHandle(hToken);
	CloseHandle(hThis);
}