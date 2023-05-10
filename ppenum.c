#include <windows.h>
#include "beacon.h"

#define stringify( name ) #name

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

const char* convert_type[] =
{
    stringify(PsProtectedTypeNone),
    stringify(PsProtectedTypeProtectedLight),
    stringify(PsProtectedTypeProtected),
};

const char* convert_signer[] =
{
    stringify(PsProtectedSignerNone),
    stringify(PsProtectedSignerAuthenticode),
    stringify(PsProtectedSignerCodeGen),
    stringify(PsProtectedSignerAntimalware),
    stringify(PsProtectedSignerLsa),
    stringify(PsProtectedSignerWindows),
    stringify(PsProtectedSignerWinTcb),
    stringify(PsProtectedSignerWinSystem),
    stringify(PsProtectedSignerApp),
    stringify(PsProtectedSignerMax)
};

typedef	DWORD(WINAPI* _GetLastError)();
typedef HANDLE(WINAPI* _OpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
typedef BOOL(WINAPI* _CloseHandle)(HANDLE hObject);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(IN HANDLE ProcessHandle, ULONG ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

void go(char* args, int length) {

	datap			parser;
	formatp			buffer;

	int				pid;
	HANDLE			hProcess;
	NTSTATUS		status;
	PS_PROTECTION	protect;

	_GetLastError				getLastError;
	_OpenProcess				openProcess;
	_CloseHandle				closeHandle;
	_NtQueryInformationProcess	ntQueryInformationProcess;
	
	BeaconDataParse(&parser, args, length);
	pid = BeaconDataInt(&parser);

	getLastError = (_GetLastError)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLastError");
	openProcess = (_OpenProcess)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess");
	closeHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
	ntQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	hProcess = openProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (!hProcess)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess failed: %d", getLastError());
		return;
	}

	status = ntQueryInformationProcess(hProcess, 61UL, &protect, sizeof(PS_PROTECTION), NULL);

	if (status != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] NtQueryInformationProcess failed: %x", status);
		closeHandle(hProcess);
		return;
	}

	BeaconFormatAlloc(&buffer, 1024);

	BeaconFormatPrintf(&buffer, "Type   : %s\n", convert_type[(PS_PROTECTED_TYPE)protect.Type]);
	BeaconFormatPrintf(&buffer, "Signer : %s", convert_signer[(PS_PROTECTED_SIGNER)protect.Signer]);

	BeaconPrintf(CALLBACK_OUTPUT,"%s\n", BeaconFormatToString(&buffer, NULL));
	BeaconFormatFree(&buffer);  
	 
	closeHandle(hProcess);
}