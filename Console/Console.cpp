
// Default
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>

// STL
#include <cctype>

// Custom
#include "ConsoleUtils.h"

// Namespaces
using namespace ConsoleUtils;

// General definitions
typedef LONG(NTAPI* fnNtResumeProcess)(HANDLE hProcess);
typedef LONG(NTAPI* fnNtSuspendProcess)(HANDLE hProcess);

fnNtSuspendProcess NtResumeProcess = nullptr;
fnNtResumeProcess NtSuspendProcess = nullptr;

SC_HANDLE g_hServiceManager = nullptr;
SC_HANDLE g_hService = nullptr;

bool g_bIsValidLaunch = false;
bool g_bStop = false;

typedef LONG(NTAPI* fnNtFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

typedef struct _LOADER_DATA {
	// Addresses
	fnNtFlushInstructionCache m_pNtFlushInstructionCache;
	fnVirtualAlloc m_pVirtualAlloc;
	fnGetProcAddress m_pGetProcAddress;
	fnLoadLibraryA m_pLoadLibraryA;
	// Memory
	void* m_pMemoryAddress;
	DWORD m_unMemorySize;
	char m_pLoaderPath[1024];
} LOADER_DATA, *PLOADER_DATA;

typedef struct _CONSOLE_MESSAGE {
	char m_pMessage[1024];
	COLOR_PAIR m_ColorPair;
} CONSOLE_MESSAGE, *PCONSOLE_MESSAGE;

bool StartSteamService(const SC_HANDLE hServiceManager, const SC_HANDLE hService) {
	if (!hServiceManager) {
		return false;
	}

	if (!hService) {
		return false;
	}

	SERVICE_STATUS_PROCESS ssp;
	memset(&ssp, 0, sizeof(ssp));

	DWORD unBytesNeeded = 0;
	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
		return false;
	}

	if (ssp.dwCurrentState == SERVICE_RUNNING) {
		return true;
	}

	DWORD64 unStartTime = GetTickCount64();
	while (ssp.dwCurrentState == SERVICE_START_PENDING) {

		DWORD unWaitTime = ssp.dwWaitHint / 10;

		if (unWaitTime < 1000) {
			unWaitTime = 1000;
		}
		else if (unWaitTime > 10000) {
			unWaitTime = 10000;
		}

		Sleep(unWaitTime);

		unBytesNeeded = 0;
		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
			return false;
		}

		if (ssp.dwCurrentState == SERVICE_RUNNING) {
			return true;
		}

		if (GetTickCount64() - unStartTime > 30000) {
			return false;
		}
	}


	if (!StartService(hService, 0, nullptr)) {
		return false;
	}

	unStartTime = GetTickCount64();
	while (true) {
		Sleep(ssp.dwWaitHint);

		unBytesNeeded = 0;
		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
			return false;
		}

		if (ssp.dwCurrentState == SERVICE_RUNNING) {
			return true;
		}

		if (GetTickCount64() - unStartTime > 30000) {
			return false;
		}
	}

	return false;
}

bool StopSteamService(const SC_HANDLE hServiceManager, const SC_HANDLE hService) {
	if (!hServiceManager) {
		return false;
	}

	if (!hService) {
		return false;
	}

	SERVICE_STATUS_PROCESS ssp;
	memset(&ssp, 0, sizeof(ssp));

	DWORD unBytesNeeded = 0;
	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
		return false;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED) {
		return true;
	}

	DWORD64 unStartTime = GetTickCount64();
	while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {

		DWORD unWaitTime = ssp.dwWaitHint / 10;

		if (unWaitTime < 1000) {
			unWaitTime = 1000;
		}
		else if (unWaitTime > 10000) {
			unWaitTime = 10000;
		}

		Sleep(unWaitTime);

		unBytesNeeded = 0;
		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
			return false;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED) {
			return true;
		}

		if (GetTickCount64() - unStartTime > 30000) {
			return false;
		}
	}


	if (!ControlService(hService, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&ssp))) {
		return false;
	}

	unStartTime = GetTickCount64();
	while (true) {
		Sleep(ssp.dwWaitHint);

		unBytesNeeded = 0;
		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(SERVICE_STATUS_PROCESS), &unBytesNeeded)) {
			return false;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED) {
			return true;
		}

		if (GetTickCount64() - unStartTime > 30000) {
			return false;
		}
	}

	return false;
}

typedef struct _RESTART_SERVICE_DATA {
	SC_HANDLE m_hServiceManager;
	SC_HANDLE m_hService;
} RESTART_SERVICE_DATA, *PRESTART_SERVICE_DATA;

DWORD WINAPI StartServiceRoutine(LPVOID lpThreadParameter) {
	PRESTART_SERVICE_DATA pData = reinterpret_cast<PRESTART_SERVICE_DATA>(lpThreadParameter);
	if (!pData) {
		return -1;
	}

	if (!StartSteamService(pData->m_hServiceManager, pData->m_hService)) {
		return -1;
	}

	delete pData;
	return 0;
}

bool Lower(const TCHAR* szInput, const size_t unLength, TCHAR* szOutput) {
	if (!szInput) {
		return false;
	}

	if (!unLength) {
		return false;
	}

	if (!szOutput) {
		return false;
	}

	for (size_t i = 0; i < unLength; ++i) {
		szOutput[i] = std::tolower(szInput[i]);
	}

	return true;
}

DWORD GetPID(const TCHAR* szProcessName) {
	if (!szProcessName) {
		return 0;
	}

	PROCESSENTRY32 pe;
	memset(&pe, 0, sizeof(pe));

	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!hSnap || (hSnap == INVALID_HANDLE_VALUE)) {
		return 0;
	}

	if (Process32First(hSnap, &pe)) {
		while (Process32Next(hSnap, &pe)) {
			PTCHAR szName = new TCHAR[MAX_PATH + 1];
			if (!szName) {
				CloseHandle(hSnap);
				return 0;
			}
			memset(szName, 0, sizeof(TCHAR[MAX_PATH + 1]));
			if (!Lower(pe.szExeFile, MAX_PATH, szName)) {
				delete[] szName;
				continue;
			}
			if (_tcsncmp(szName, szProcessName, MAX_PATH) == 0) {
				delete[] szName;
				CloseHandle(hSnap);
				return pe.th32ProcessID;
			}
			delete[] szName;
		}
	}

	CloseHandle(hSnap);
	return 0;
}

size_t GetExportOffset(void* pMemory, const size_t unSize, const char* szExportName) {
	if (!pMemory) {
		return 0;
	}

	if (!unSize) {
		return 0;
	}

	if (unSize < sizeof(IMAGE_DOS_HEADER)) {
		return 0;
	}

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMemory);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	if (unSize < pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		return 0;
	}

	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pMemory) + pDH->e_lfanew);
	if (pNTHs->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
#ifdef _WIN64
	if (pFH->Machine != IMAGE_FILE_MACHINE_AMD64) {
		return 0;
	}

	const PIMAGE_OPTIONAL_HEADER64 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 0;
	}
#elif _WIN32
	if (pFH->Machine != IMAGE_FILE_MACHINE_I386) {
		return 0;
	}

	const PIMAGE_OPTIONAL_HEADER32 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 0;
	}
#else
#error Unknown platform
#endif

	const PIMAGE_DATA_DIRECTORY pExportDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	const PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(&(pNTHs->OptionalHeader)) + pFH->SizeOfOptionalHeader);
	for (DWORD i = 0; i < pFH->NumberOfSections; ++i) {
		if ((pExportDD->VirtualAddress >= pFirstSection[i].VirtualAddress) && (pExportDD->VirtualAddress < (pFirstSection[i].VirtualAddress + pFirstSection[i].Misc.VirtualSize))) {

			const DWORD unDelta = pFirstSection[i].VirtualAddress - pFirstSection[i].PointerToRawData;

			const PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pMemory) + pExportDD->VirtualAddress - unDelta);

			const PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfFunctions - unDelta);
			const PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfNameOrdinals - unDelta);
			const PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMemory) + pExportDirectory->AddressOfNames - unDelta);

			const DWORD unNumberOfFunctions = pExportDirectory->NumberOfFunctions;
			const DWORD unNumberOfNames = pExportDirectory->NumberOfNames;
			for (DWORD j = 0; j < unNumberOfFunctions; ++j) {
				for (DWORD l = 0; l < unNumberOfNames; ++l) {
					if (pOrdinals[l] == j) {
						if (strcmp(szExportName, reinterpret_cast<char*>(pMemory) + pNames[l] - unDelta) == 0) {
							const DWORD unRVA = *reinterpret_cast<PDWORD>(&pFunctions[pOrdinals[l]]);
							for (DWORD k = 0; k < pFH->NumberOfSections; ++k) {
								if ((unRVA >= pFirstSection[k].VirtualAddress) && (unRVA < (pFirstSection[k].VirtualAddress + pFirstSection[k].SizeOfRawData))) {
									return unRVA - pFirstSection[k].VirtualAddress + pFirstSection[k].PointerToRawData;
								}
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

bool InjectLibrary(const HANDLE hProcess, void* pMemory, const size_t unSize, PLOADER_DATA pLoaderData) {
	if (!hProcess) {
		return false;
	}

	if (!pMemory) {
		return false;
	}

	if (!unSize) {
		return false;
	}

	if (unSize < sizeof(IMAGE_DOS_HEADER)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMemory);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid DOS signature)\n"));
		return false;
	}

	if (unSize < pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (File is too small)\n"));
		return false;
	}

	const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pMemory) + pDH->e_lfanew);
	if (pNTHs->Signature != IMAGE_NT_SIGNATURE) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid PE signature)\n"));
		return false;
	}

	const PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
#ifdef _WIN64
	if (pFH->Machine != IMAGE_FILE_MACHINE_AMD64) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER64 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#elif _WIN32
	if (pFH->Machine != IMAGE_FILE_MACHINE_I386) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid platform)\n"));
		return false;
	}

	const PIMAGE_OPTIONAL_HEADER32 pOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pNTHs->OptionalHeader));
	if (pOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid optional PE signature)\n"));
		return false;
	}
#else
#error Unknown platform
#endif

	const size_t unLoaderOffset = GetExportOffset(pMemory, unSize, "?DumpVAC@@YGKPAX@Z");
	if (!unLoaderOffset) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Loader not found)\n"));
		return false;
	}

	void* pBuffer = VirtualAllocEx(hProcess, nullptr, unSize + sizeof(LOADER_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to allocate memory)\n"));
		return false;
	}

	if (!WriteProcessMemory(hProcess, pBuffer, pMemory, unSize, nullptr)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	pLoaderData->m_pMemoryAddress = pBuffer;
	pLoaderData->m_unMemorySize = unSize;

	char szBuffer[sizeof(LOADER_DATA::m_pLoaderPath)];
	memset(szBuffer, 0, sizeof(szBuffer));
	if (!GetModuleFileNameA(nullptr, szBuffer, sizeof(szBuffer))) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	char szDriveFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDriveFile, 0, sizeof(szDriveFile));
	char szDirFile[sizeof(LOADER_DATA::m_pLoaderPath) / 2];
	memset(szDirFile, 0, sizeof(szDirFile));
	if (_splitpath_s(szBuffer, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, nullptr, 0, nullptr, 0)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unknown path)\n"));
		return false;
	}

	memset(szBuffer, 0, sizeof(szBuffer));
	sprintf_s(szBuffer, "%s%s", szDriveFile, szDirFile);

	memcpy(pLoaderData->m_pLoaderPath, szBuffer, sizeof(LOADER_DATA::m_pLoaderPath));

	if (!WriteProcessMemory(hProcess, reinterpret_cast<char*>(pBuffer) + unSize, pLoaderData, sizeof(LOADER_DATA), nullptr)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Unable to write memory)\n"));
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0x100000 /* 1 MiB */, reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<size_t>(pBuffer) + unLoaderOffset), reinterpret_cast<char*>(pBuffer) + unSize, CREATE_SUSPENDED, nullptr);
	if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to inject library (Invalid thread handle)\n"));
		return false;
	}

	ResumeThread(hThread);

	if (!NT_SUCCESS(NtResumeProcess(hProcess))) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `NtResumeProcess` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return true;
}

bool FileRead(const TCHAR* szPath, PHANDLE phHeap, LPVOID* ppMemory, PDWORD punFileSize) {
	const HANDLE hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateFile` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const DWORD unFileSize = GetFileSize(hFile, nullptr);
	if (!unFileSize || (unFileSize == INVALID_FILE_SIZE)) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `GetFileSize` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	const HANDLE hHeap = GetProcessHeap();
	if (!hHeap || (hHeap == INVALID_HANDLE_VALUE)) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `GetProcessHeap` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	void* pMemory = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, unFileSize);
	if (!pMemory) {
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unNumberOfBytesRead = 0;
	if (!ReadFile(hFile, pMemory, unFileSize, &unNumberOfBytesRead, nullptr) && (unFileSize != unNumberOfBytesRead)) {
		if (!HeapFree(hHeap, NULL, pMemory)) {
			CloseHandle(hFile);
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
		CloseHandle(hFile);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapAlloc` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	CloseHandle(hFile);

	if (phHeap) {
		*phHeap = hHeap;
	}

	if (ppMemory) {
		*ppMemory = pMemory;
	} else {
		if (!HeapFree(hHeap, NULL, pMemory)) {
			tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
			return false;
		}
	}

	if (punFileSize) {
		*punFileSize = unFileSize;
	}

	return true;
}

bool HackSteamService(const HANDLE hProcess) {
	if (!hProcess) {
		return false;
	}

	HMODULE hRemoteNTDLL = nullptr;
	HMODULE hRemoteKernel32 = nullptr;

	HMODULE hModules[1024];
	memset(hModules, 0, sizeof(hModules));

	DWORD unNeeded = 0;
	if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &unNeeded)) {
		const DWORD unEnd = unNeeded / sizeof(HMODULE);
		for (unsigned int i = 0; i < unEnd; ++i) {
			TCHAR szModuleName[MAX_PATH];
			memset(szModuleName, 0, sizeof(szModuleName));
			if (GetModuleBaseName(hProcess, hModules[i], szModuleName, MAX_PATH - 1)) {
				if ((_tccmp(szModuleName, _T("ntdll.dll")) == 0) && !hRemoteNTDLL) {
					hRemoteNTDLL = hModules[i];
					continue;
				}

				if ((_tccmp(szModuleName, _T("KERNEL32.DLL")) == 0) && !hRemoteKernel32) {
					hRemoteKernel32 = hModules[i];
					continue;
				}
			}
		}
	}

	if (!hRemoteNTDLL) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `EnumProcessModules` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	if (!hRemoteKernel32) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `EnumProcessModules` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	LOADER_DATA LoaderData;
	memset(&LoaderData, 0, sizeof(LoaderData));

	LoaderData.m_pNtFlushInstructionCache = reinterpret_cast<fnNtFlushInstructionCache>(GetProcAddress(hRemoteNTDLL, "NtFlushInstructionCache"));
	LoaderData.m_pVirtualAlloc = reinterpret_cast<fnVirtualAlloc>(GetProcAddress(hRemoteKernel32, "VirtualAlloc"));
	LoaderData.m_pGetProcAddress = reinterpret_cast<fnGetProcAddress>(GetProcAddress(hRemoteKernel32, "GetProcAddress"));
	LoaderData.m_pLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(hRemoteKernel32, "LoadLibraryA"));

	HANDLE hHeap = nullptr;
	LPVOID pMemory = nullptr;
	DWORD unFileSize = 0;

	if (!FileRead(_T("DumpVAC.dll"), &hHeap, &pMemory, &unFileSize)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `FileRead` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	if (!InjectLibrary(hProcess, pMemory, unFileSize, &LoaderData)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `InjectLibrary` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	tclrprintf(COLOR::COLOR_GREEN, _T("[+] Library injected!\n"));
	tclrprintf(COLOR::COLOR_GREEN, _T("[+]  > Base = 0x%08X\n"), reinterpret_cast<unsigned int>(LoaderData.m_pMemoryAddress));
	tclrprintf(COLOR::COLOR_GREEN, _T("[+]  > Size = 0x%08X\n"), LoaderData.m_unMemorySize);

	if (!HeapFree(hHeap, NULL, pMemory)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HeapFree` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
	if (dwCtrlType == CTRL_C_EVENT) {
		g_bStop = true;

		if (g_bIsValidLaunch) {
			StopSteamService(g_hServiceManager, g_hService);
		} else {
			const DWORD unPID = GetPID(_T("steamservice.exe"));
			if (!unPID) {
				return TRUE;
			}

			const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, unPID);
			if (!hProcess || (hProcess == INVALID_HANDLE_VALUE)) {
				return TRUE;
			}

			TerminateProcess(hProcess, EXIT_FAILURE);

			CloseHandle(hProcess);

			tclrprintf(COLOR::COLOR_YELLOW, _T("[i] Service terminated.\n"));
		}

		return TRUE;
	}
	return FALSE;
}

bool ConnectToSteamService() {

	tclrprintf(COLOR::COLOR_CYAN, _T("[i] Connecting to SteamService... "));

	unsigned char unCount = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	while (!hPipe || (hPipe == INVALID_HANDLE_VALUE)) {
		if (unCount >= 30) {
			tclrprintf(COLOR::COLOR_RED, _T("[ FAIL ]\n"));
			return false;
		}
		++unCount;
		hPipe = CreateFile(_T("\\\\.\\pipe\\DumpVAC"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		Sleep(1000);
	}

	tclrprintf(COLOR::COLOR_GREEN, _T("[  OK  ]\n\n"));

	HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!hEvent || (hEvent == INVALID_HANDLE_VALUE)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateEvent` (LastError = 0x%08X)\n"), GetLastError());
		return false;
	}

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));

	ol.hEvent = hEvent;

	CONSOLE_MESSAGE Message;

	bool bContinue = true;
	while (bContinue && !g_bStop) {
		bContinue = false;
		memset(&Message, 0, sizeof(Message));
		DWORD unNumberOfBytesRead = 0;
		if (!ReadFile(hPipe, &Message, sizeof(Message), &unNumberOfBytesRead, &ol)) {
			switch (GetLastError()) {
				case ERROR_HANDLE_EOF: {
					break;
				}
				case ERROR_IO_PENDING: {
					bool bPending = true;
					while (bPending && !g_bStop) {
						bPending = false;
						if (!GetOverlappedResult(hPipe, &ol, &unNumberOfBytesRead, FALSE)) {
							switch (GetLastError()) {
								case ERROR_HANDLE_EOF: {
									break;
								}
								case ERROR_IO_INCOMPLETE: {
									bPending = true;
									bContinue = true;
									break;
								}
							}
						} else {
							if (unNumberOfBytesRead == sizeof(CONSOLE_MESSAGE)) {
								Message.m_pMessage[sizeof(Message.m_pMessage) - 1] = '\0';
								if (strnlen_s(Message.m_pMessage, sizeof(Message.m_pMessage)) > 0) {
									clrprintf(Message.m_ColorPair, "%s", Message.m_pMessage);
								}
								ResetEvent(ol.hEvent);
							}
						}
						Sleep(5);
					}
					break;
				}
				default: {
					break;
				}
			}
		} else {
			Message.m_pMessage[sizeof(Message.m_pMessage) - 1] = '\0';
			if (strnlen_s(Message.m_pMessage, sizeof(Message.m_pMessage)) > 0) {
				clrprintf(Message.m_ColorPair, "%s", Message.m_pMessage);
			}
			bContinue = true;
		}
		Sleep(5);
	}

	tclrprintf(COLOR::COLOR_WHITE, _T("\n"));

	CloseHandle(hEvent);
	CloseHandle(hPipe);

	return true;
}

int _tmain() {
	Terminal SCU(true, true);

	if (SCU.Open()) {
		SCU.ChangeColorPalette(COLOR::COLOR_BLACK, 0x1B1B1B);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_BLUE, 0x2962FF);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_GREEN, 0x00C853);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_CYAN, 0x00B8D4);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_RED, 0xD50000);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_MAGENTA, 0xAA00FF);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_YELLOW, 0xFFD600);
		SCU.ChangeColorPalette(COLOR::COLOR_DARK_GRAY, 0x616161);
		SCU.ChangeColorPalette(COLOR::COLOR_GRAY, 0xEEEEEE);
		SCU.ChangeColorPalette(COLOR::COLOR_BLUE, 0x448AFF);
		SCU.ChangeColorPalette(COLOR::COLOR_GREEN, 0x69F0AE);
		SCU.ChangeColorPalette(COLOR::COLOR_CYAN, 0x18FFFF);
		SCU.ChangeColorPalette(COLOR::COLOR_RED, 0xFF5252);
		SCU.ChangeColorPalette(COLOR::COLOR_MAGENTA, 0xE040FB);
		SCU.ChangeColorPalette(COLOR::COLOR_YELLOW, 0xFFFF00);
		SCU.ChangeColorPalette(COLOR::COLOR_WHITE, 0xFAFAFA);

		tclrprintf(COLOR::COLOR_WHITE, _T("Console [Version 1.0.0] (zeze839@gmail.com)\n\n"));
	} else {
		return -1;
	}

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `OpenProcessToken` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	LUID luid;
	memset(&luid, 0, sizeof(luid));

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `LookupPrivilegeValue` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	TOKEN_PRIVILEGES tp;
	memset(&tp, 0, sizeof(tp));

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))	{
		CloseHandle(hToken);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `AdjustTokenPrivileges` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	CloseHandle(hToken);

	const HMODULE hNTDLL = GetModuleHandle(_T("ntdll.dll"));
	if (!hNTDLL) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Not found NTDLL module.\n"));
		return -1;
	}

	NtResumeProcess = reinterpret_cast<fnNtResumeProcess>(GetProcAddress(hNTDLL, "NtResumeProcess"));
	if (!NtResumeProcess) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Not found NtResumeProcess API.\n"));
		return -1;
	}

	NtSuspendProcess = reinterpret_cast<fnNtSuspendProcess>(GetProcAddress(hNTDLL, "NtSuspendProcess"));
	if (!NtSuspendProcess) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Not found NtSuspendProcess API.\n"));
		return -1;
	}

	g_hServiceManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!g_hServiceManager) {
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `OpenSCManager` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	g_hService = OpenService(g_hServiceManager, _T("Steam Client Service"), SERVICE_ALL_ACCESS);
	if (!g_hService) {
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `OpenService` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	SetConsoleCtrlHandler(HandlerRoutine, TRUE);

	if (!StopSteamService(g_hServiceManager, g_hService)) {
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `StopSteamService` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	PRESTART_SERVICE_DATA pData = new RESTART_SERVICE_DATA;
	memset(pData, 0, sizeof(RESTART_SERVICE_DATA));

	pData->m_hServiceManager = g_hServiceManager;
	pData->m_hService = g_hService;

	const HANDLE hStartThread = CreateThread(nullptr, 0, StartServiceRoutine, reinterpret_cast<LPVOID>(pData), CREATE_SUSPENDED, nullptr);
	if (!hStartThread || (hStartThread == INVALID_HANDLE_VALUE)) {
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `CreateThread` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	ResumeThread(hStartThread);

	const DWORD64 unStartTime = GetTickCount64();
	DWORD unPID = GetPID(_T("steamservice.exe"));
	while (unPID == 0) {
		unPID = GetPID(_T("steamservice.exe"));

		if (GetTickCount64() - unStartTime > 5000) {
			break;
		}

		_mm_pause();
	}

	if (unPID == 0) {
		WaitForSingleObject(hStartThread, INFINITE);
		CloseHandle(hStartThread);
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed to find service."));
		return -1;
	}

	const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, unPID);
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE)) {
		WaitForSingleObject(hStartThread, INFINITE);
		CloseHandle(hStartThread);
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `OpenProcess` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	if (!NT_SUCCESS(NtSuspendProcess(hProcess))) {
		WaitForSingleObject(hStartThread, INFINITE);
		CloseHandle(hStartThread);
		CloseHandle(hProcess);
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `NtSuspendProcess` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	tclrprintf(COLOR::COLOR_GREEN, _T("[+] Found service!\n"));
	tclrprintf(COLOR::COLOR_GREEN, _T("[+]  > PID  = %lu\n"), unPID);

	if (!HackSteamService(hProcess)) {
		WaitForSingleObject(hStartThread, INFINITE);
		CloseHandle(hStartThread);
		CloseHandle(hProcess);
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `HackSteamService`.\n"));
		return -1;
	}

	g_bIsValidLaunch = true;

	if (!ConnectToSteamService()) {
		WaitForSingleObject(hStartThread, INFINITE);
		CloseHandle(hStartThread);
		CloseHandle(hProcess);
		CloseServiceHandle(g_hService);
		CloseServiceHandle(g_hServiceManager);
		tclrprintf(COLOR::COLOR_RED, _T("[!] Failed `ConnectToSteamService` (LastError = 0x%08X)\n"), GetLastError());
		return -1;
	}

	WaitForSingleObject(hStartThread, INFINITE);
	CloseHandle(hStartThread);
	CloseHandle(hProcess);
	CloseServiceHandle(g_hService);
	CloseServiceHandle(g_hServiceManager);

	tclrprintf(COLOR::COLOR_WHITE, _T("\nPress ")); tclrprintf(COLOR::COLOR_CYAN, _T("<Enter>")); tclrprintf(COLOR::COLOR_WHITE, _T(" to exit.")); tclrscanf(COLOR::COLOR_WHITE, _T(""));
	return 0;
}
