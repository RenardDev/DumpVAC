
// Framework
#include "framework.h"

// IceKey
#include "IceKey.h"

// ConsoleAPI
#include "Console.h"

// LibraryLoader
#include "LibraryLoader.h"

// Detours
#include "Detours.h"

// Distorm(X)
#include "distorm.h"
#include "distormx.h"

// STL
#include <unordered_map>
#include <memory>
#include <vector>
#include <array>

// Namespaces
using namespace Detours;

// General definitions

#define MAGIC_VALVE_SIGNATURE 0x00564C56 // VLV

typedef HMODULE(WINAPI* fnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

enum MODULE_RESULT : unsigned int {
	NOT_SET = 0x0,
	SUCCESS = 0x1,
	ALREADY_LOADED = 0x2,
	FAIL_INITIALIZE = 0x3,
	UKN1 = 0x4,
	UKN2 = 0x5,
	FAIL_TO_DECRYPT_MODULE = 0xB,
	FAIL_MODULE_SIZE_NULL = 0xC,
	UKN3 = 0xF,
	FAIL_GET_MODULE_TEMP_PATH = 0x13,
	FAIL_WRITE_MODULE = 0x15,
	FAIL_LOAD_MODULE = 0x16,
	FAIL_GET_EXPORT_RUNFUNC = 0x17,
	FAIL_GET_EXPORT_RUNFUNC_2 = 0x19
};

typedef void(__fastcall* fnEncrypt)(void* pBase, void* pData, unsigned int unDataSize, unsigned char* pIceKey);
typedef MODULE_RESULT(__stdcall* fnRunFunc)(unsigned int unID, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize);

typedef struct _MODULE {
	unsigned short m_unRunFuncExportFunctionOrdinal;
	unsigned short m_unRunFuncExportModuleOrdinal;
	void* m_pModuleBase;
	PIMAGE_NT_HEADERS m_pNTHs;
	unsigned int m_unImportedLibraryCount;
	void* m_pIAT;
} MODULE, *PMODULE;

typedef struct _MODULE_HEADER {
	IMAGE_DOS_HEADER m_DH;
	unsigned int m_unMagic;
	unsigned int m_unCrypt;
	unsigned int m_unFileSize;
	unsigned int m_unTimeStamp;
	unsigned char m_pCryptRSASignature[0x80];
} MODULE_HEADER, *PMODULE_HEADER;

typedef struct _MODULE_INFO {
	unsigned int m_unHash; // CRC32
	HMODULE m_hModule;
	PMODULE m_pModule;
	fnRunFunc m_pRunFunc;
	MODULE_RESULT m_unLastResult;
	unsigned int m_unModuleSize;
	PMODULE_HEADER m_pRawModule;
} MODULE_INFO, *PMODULE_INFO;

typedef bool(__stdcall* fnLoadModuleStandard)(PMODULE_INFO pModuleInfo, unsigned char unFlags);
typedef MODULE_RESULT(__fastcall* fnCallFunctionAsyncInternal)(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unID, int nC, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize);

PLOADER_DATA g_pLoaderData = nullptr;

std::unordered_map<HMODULE, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>> g_ImportingModules;
std::unordered_map<unsigned int, std::array<unsigned char, 16>> g_IceKeys;
std::vector<unsigned int> g_DumpedHashes;

fnLoadLibraryExW LoadLibraryExW_Original = nullptr;
HMODULE WINAPI LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	HMODULE hModule = LoadLibraryExW_Original(lpLibFileName, hFile, dwFlags);
	if (!lpLibFileName) {
		return hModule;
	}

	const size_t unLength = wcsnlen_s(lpLibFileName, MAX_PATH);
	const size_t unSize = unLength * sizeof(wchar_t);

	auto Import = g_ImportingModules.find(hModule);
	if (Import == g_ImportingModules.end()) {
		std::unique_ptr<wchar_t[]> pMem(new wchar_t[unLength + 1]);
		wchar_t* pBuffer = pMem.get();
		memset(pBuffer, 0, unSize + sizeof(wchar_t));
		memcpy(pBuffer, lpLibFileName, unSize);
		pBuffer[unLength] = 0;

		g_ImportingModules.insert(std::pair<HMODULE, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>>(hModule, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>(hFile, std::move(pMem))));
	} else {
		std::unique_ptr<wchar_t[]> pMem(new wchar_t[unLength + 1]);
		wchar_t* pBuffer = pMem.get();
		memset(pBuffer, 0, unSize + sizeof(wchar_t));
		memcpy(pBuffer, lpLibFileName, unSize);
		pBuffer[unLength] = 0;

		Import->second = std::pair<HANDLE, std::unique_ptr<wchar_t[]>>(hFile, std::move(pMem));
	}

	return hModule;
}

void DumpOutData(void* pOutData, unsigned int* pOutDataSize) {

	char szBuffer[2048];
	memset(szBuffer, 0, sizeof(szBuffer));
	sprintf_s(szBuffer, "%sVAC_OUT_%08X.dat", g_pLoaderData->m_pLoaderPath, reinterpret_cast<unsigned int>(pOutData));
	FILE* pFile = nullptr;
	fopen_s(&pFile, szBuffer, "wb+");
	if (!pFile) {
		return;
	}

	if (fwrite(pOutData, 1, 4232, pFile) != 4232) {
		fclose(pFile);
		return;
	}

	fclose(pFile);

	clrprintf(COLOR::COLOR_RED, "[DumpVAC] RunFunc (OUT) dumped to `%s`.\n", szBuffer);
}

void EncryptICE(unsigned char* pAddress, void* pAllocation, int a3, unsigned char* pIceKey) {
	IceKey ICE(1);
	ICE.set(pIceKey);

	unsigned char* pData = reinterpret_cast<unsigned char*>(reinterpret_cast<unsigned int>(pAllocation) - reinterpret_cast<unsigned int>(pAddress));
	unsigned short unCount = 512;
	do {
		ICE.encrypt((unsigned __int8*)(pData + reinterpret_cast<unsigned int>(pAddress)), pAddress);
		pAddress += 8;
		--unCount;
	} while (unCount);
}

unsigned int* g_pOutDataSize = nullptr;

unsigned int unKey = 0;
unsigned char g_pIceKey[8];

unsigned int unECX = 0;
unsigned int unEDX = 0;

fnEncrypt Encrypt = nullptr;
__declspec(naked) void Encrypt_Hook() {
	__asm {
		mov [unECX], ecx
		mov [unEDX], edx

		push ebp
		mov ebp, esp

		push ecx
		mov ecx, [ebp + 0Ch]
		mov [unKey], ecx
		pop ecx

		mov esp, ebp
		pop ebp
	}
	//for (i = 0; i < 4096; i += 8) {
	//	clrprintf(COLOR::COLOR_RED, "[%08X] ", unESP + i);
	//	for (k = 0; (k < 8) && ((i + k) < 4096); ++k) {
	//		clrprintf(COLOR::COLOR_RED, "%08X ", reinterpret_cast<unsigned int*>(unESP)[i + k]);
	//	}
	//	clrprintf(COLOR::COLOR_RED, "\n");
	//}
	clrprintf(COLOR::COLOR_RED, "[DumpVAC] Encryption Key: %02X %02X %02X %02X %02X %02X %02X %02X\n", reinterpret_cast<unsigned char*>(unKey)[0], reinterpret_cast<unsigned char*>(unKey)[1], reinterpret_cast<unsigned char*>(unKey)[2], reinterpret_cast<unsigned char*>(unKey)[3], reinterpret_cast<unsigned char*>(unKey)[4], reinterpret_cast<unsigned char*>(unKey)[5], reinterpret_cast<unsigned char*>(unKey)[6], reinterpret_cast<unsigned char*>(unKey)[7], unKey);
	//__asm {
	//	ret
	//}
	g_pIceKey[0] = reinterpret_cast<unsigned char*>(unKey)[0];
	g_pIceKey[1] = reinterpret_cast<unsigned char*>(unKey)[1];
	g_pIceKey[2] = reinterpret_cast<unsigned char*>(unKey)[2];
	g_pIceKey[3] = reinterpret_cast<unsigned char*>(unKey)[3];
	g_pIceKey[4] = reinterpret_cast<unsigned char*>(unKey)[4];
	g_pIceKey[5] = reinterpret_cast<unsigned char*>(unKey)[5];
	g_pIceKey[6] = reinterpret_cast<unsigned char*>(unKey)[6];
	g_pIceKey[7] = reinterpret_cast<unsigned char*>(unKey)[7];

	//((unsigned int*)unEDX)[0] = 0x00000000; // ICE Key address
	//((unsigned int*)unEDX)[1] = 0x00000000; // Loader Status
	//((unsigned int*)unEDX)[2] = 0xFFFFFFFF; // ??

	/*
	((unsigned int*)unEDX)[1026] = 0x46221D9E;
	((unsigned int*)unEDX)[1027] = 0x67746882;
	((unsigned int*)unEDX)[1028] = 0xE3287DC7;
	((unsigned int*)unEDX)[1029] = 0xA4993577;
	((unsigned int*)unEDX)[1030] = 0x93523D76;
	((unsigned int*)unEDX)[1031] = 0xF2D2A55E;
	((unsigned int*)unEDX)[1032] = 0x429C7F5F;
	((unsigned int*)unEDX)[1033] = 0x2137159A;
	((unsigned int*)unEDX)[1034] = 0xB842B5E0;
	((unsigned int*)unEDX)[1035] = 0x535C9CE6;
	((unsigned int*)unEDX)[1036] = 0xA3BAC349;
	((unsigned int*)unEDX)[1037] = 0x2DAB997A;
	((unsigned int*)unEDX)[1038] = 0x56BAB25F;
	((unsigned int*)unEDX)[1039] = 0x925CB300;
	((unsigned int*)unEDX)[1040] = 0x68881140;
	((unsigned int*)unEDX)[1041] = 0xB3C7F37A;
	((unsigned int*)unEDX)[1042] = 0xE3287DC7;
	*/

	//((unsigned int*)unEDX)[1024] = 0x00000040;
	//((unsigned int*)unEDX)[1025] = 0x00000000;

	DumpOutData((void*)unEDX, g_pOutDataSize);
	//DumpOutData((void*)(unECX - 4 * unSize), unSize);
	EncryptICE((unsigned char*)unEDX, (unsigned char*)unECX, 0, g_pIceKey);
	//VirtualFree(reinterpret_cast<LPVOID>(unECX), 0, MEM_RELEASE);
	__asm {
		ret
	}
}

bool bCallOriginal = false;
bool bSessionCheck = false;

unsigned char pIceKey1[8];
unsigned char pIceKey2[8];

fnRunFunc RunFunc = nullptr;
MODULE_RESULT __stdcall RunFunc_Hook(unsigned int unID, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize) {
	if (!bCallOriginal) {
		bCallOriginal = true;
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] RunFunc ID=%08X\n", unID);

		char szBuffer[2048];
		memset(szBuffer, 0, sizeof(szBuffer));
		sprintf_s(szBuffer, "%sVAC_IN_%08X.dat", g_pLoaderData->m_pLoaderPath, reinterpret_cast<unsigned int>(pInData));
		FILE* pFile = nullptr;
		fopen_s(&pFile, szBuffer, "wb+");
		if (!pFile) {
			return RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);
		}

		unsigned char* pMemory = new unsigned char [unInDataSize];
		if (!pMemory) {
			fclose(pFile);
			return RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);
		}

		memcpy(pMemory, pInData, unInDataSize);

		IceKey ICE(1);
		ICE.set(pIceKey1);
		for (size_t i = 0; i < unInDataSize; i += 8) {
			ICE.decrypt(&pMemory[i], &pMemory[i]);
		}

		if (fwrite(pMemory, 1, unInDataSize, pFile) != unInDataSize) {
			fclose(pFile);
			return RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);
		}

		delete[] pMemory;

		fclose(pFile);

		clrprintf(COLOR::COLOR_RED, "[DumpVAC] RunFunc (IN) dumped to `%s`.\n", szBuffer);

		//clrprintf(COLOR::COLOR_RED, "OUT = %08X\n", reinterpret_cast<unsigned int>(pOutData));

		//DebugBreak();

		g_pOutDataSize = pOutDataSize;

		MODULE_RESULT unResult = RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);

		clrprintf(COLOR::COLOR_RED, "[DumpVAC] OK.\n");

		//unsigned int unLESP = 0;
		//__asm { mov unLESP, esp };

		//clrprintf(COLOR::COLOR_RED, "[DumpVAC] ESP = %08X\n", unLESP);

		//unsigned char* pIceKey = reinterpret_cast<unsigned char*>(unLESP + 0x29C);
		//clrprintf(COLOR::COLOR_RED, "[DumpVAC] Encrypt called with %02X %02X %02X %02X %02X %02X %02X %02X key.\n", pIceKey[0], pIceKey[1], pIceKey[2], pIceKey[3], pIceKey[4], pIceKey[5], pIceKey[6], pIceKey[7]);

		return unResult;
	}

	if (bSessionCheck) {
		bSessionCheck = false;
		clrprintf(COLOR::COLOR_GREEN, "[DumpVAC] RunFunc allowed. (Session check)\n");
		return RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);
	}

	clrprintf(COLOR::COLOR_RED, "[DumpVAC] RunFunc ID=%08X\n", unID);
	clrprintf(COLOR::COLOR_RED, "[DumpVAC] RunFunc blocked.\n");

	if (unID == 4) {
		return MODULE_RESULT::SUCCESS;
	}

	return MODULE_RESULT::FAIL_INITIALIZE;
}

unsigned int unSessionModuleHash = 0;

fnLoadModuleStandard LoadModuleStandard = nullptr;
bool __stdcall LoadModuleStandard_Hook(PMODULE_INFO pModuleInfo, unsigned char unFlags) {

	clrprintf(COLOR::COLOR_WHITE, "[DumpVAC] ");
	clrprintf(COLOR::COLOR_CYAN, "PreLoadModuleStandard\n");
	clrprintf(COLOR::COLOR_GREEN, " -> ModuleInfo = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo));
	if (pModuleInfo) {
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unHash       = 0x%08X\n", pModuleInfo->m_unHash);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_hModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_hModule));
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule));
		if (pModuleInfo->m_pModule) {
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unRunFuncExportFunctionOrdinal = 0x%04X\n", pModuleInfo->m_pModule->m_unRunFuncExportFunctionOrdinal);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unRunFuncExportModuleOrdinal   = 0x%04X\n", pModuleInfo->m_pModule->m_unRunFuncExportModuleOrdinal);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pModuleBase                    = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pModuleBase));
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pNTHs                          = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pNTHs));
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unImportedLibraryCount         = 0x%08X\n", pModuleInfo->m_pModule->m_unImportedLibraryCount);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pIAT                           = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pIAT));
		}
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pRunFunc     = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pRunFunc));
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unLastResult = 0x%08X\n", pModuleInfo->m_unLastResult);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unModuleSize = 0x%08X\n", pModuleInfo->m_unModuleSize);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pRawModule   = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pRawModule));
	}
	clrprintf(COLOR::COLOR_GREEN, " -> unFlags    = 0x%02X\n", unFlags);

	bool bResult = LoadModuleStandard(pModuleInfo, unFlags);
	if (!pModuleInfo) {
		return bResult;
	}

	clrprintf(COLOR::COLOR_WHITE, "[DumpVAC] ");
	clrprintf(COLOR::COLOR_CYAN, "PostLoadModuleStandard\n");
	clrprintf(COLOR::COLOR_GREEN, " -> ModuleInfo = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo));
	if (pModuleInfo) {
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unHash       = 0x%08X\n", pModuleInfo->m_unHash);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_hModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_hModule));
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule));
		if (pModuleInfo->m_pModule) {
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unRunFuncExportFunctionOrdinal = 0x%04X\n", pModuleInfo->m_pModule->m_unRunFuncExportFunctionOrdinal);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unRunFuncExportModuleOrdinal   = 0x%04X\n", pModuleInfo->m_pModule->m_unRunFuncExportModuleOrdinal);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pModuleBase                    = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pModuleBase));
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pNTHs                          = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pNTHs));
			clrprintf(COLOR::COLOR_GREEN, "       -> m_unImportedLibraryCount         = 0x%08X\n", pModuleInfo->m_pModule->m_unImportedLibraryCount);
			clrprintf(COLOR::COLOR_GREEN, "       -> m_pIAT                           = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pModule->m_pIAT));
		}
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pRunFunc     = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pRunFunc));
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unLastResult = 0x%08X\n", pModuleInfo->m_unLastResult);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_unModuleSize = 0x%08X\n", pModuleInfo->m_unModuleSize);
		clrprintf(COLOR::COLOR_GREEN, "    -> m_pRawModule   = 0x%08X\n", reinterpret_cast<unsigned int>(pModuleInfo->m_pRawModule));
	}
	clrprintf(COLOR::COLOR_GREEN, " -> unFlags    = 0x%02X\n", unFlags);
	clrprintf(COLOR::COLOR_GREEN, " -> Result     = 0x%02X\n", bResult);

	if (pModuleInfo->m_pRunFunc) {
		if (!bCallOriginal) {
			RunFunc = pModuleInfo->m_pRunFunc;
			unSessionModuleHash = pModuleInfo->m_unHash;
		}

		if (unSessionModuleHash == pModuleInfo->m_unHash) {
			bSessionCheck = true;
		}

		pModuleInfo->m_pRunFunc = RunFunc_Hook;
	}

	HMODULE hModule = pModuleInfo->m_hModule;
	if (!hModule) {
		return bResult;
	}

	const PMODULE_HEADER pMH = reinterpret_cast<PMODULE_HEADER>(hModule);
	if (pMH->m_unMagic != MAGIC_VALVE_SIGNATURE) {
		return bResult;
	}

	unsigned int unHash = pModuleInfo->m_unHash;

	for (auto it = g_DumpedHashes.begin(); it != g_DumpedHashes.end(); ++it) {
		if (*it == unHash) {
			return bResult;
		}
	}

	g_DumpedHashes.push_back(unHash);

	auto Import = g_ImportingModules.find(hModule);
	if (Import != g_ImportingModules.end()) {
		auto Keys = g_IceKeys.find(unHash);
		if (Keys != g_IceKeys.end()) {

			const size_t unModuleSize = pModuleInfo->m_unModuleSize;

			memcpy(pIceKey1, Keys->second.data(), 8);
			memcpy(pIceKey2, Keys->second.data() + 8, 8);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] Found VAC module\n");
			clrprintf(COLOR::COLOR_RED, "[DumpVAC]  -> Base = 0x%08X\n", hModule);
			clrprintf(COLOR::COLOR_RED, "[DumpVAC]  -> Size = 0x%08X\n", unModuleSize);
			clrprintf(COLOR::COLOR_RED, "[DumpVAC]  -> Path = `%ws`\n", Import->second.second.get());
			clrprintf(COLOR::COLOR_RED, "[DumpVAC]  -> FKey = %02X %02X %02X %02X %02X %02X %02X %02X\n", pIceKey1[0], pIceKey1[1], pIceKey1[2], pIceKey1[3], pIceKey1[4], pIceKey1[5], pIceKey1[6], pIceKey1[7]);
			clrprintf(COLOR::COLOR_RED, "[DumpVAC]  -> SKey = %02X %02X %02X %02X %02X %02X %02X %02X\n", pIceKey2[0], pIceKey2[1], pIceKey2[2], pIceKey2[3], pIceKey2[4], pIceKey2[5], pIceKey2[6], pIceKey2[7]);

			unsigned char* pMemory = new unsigned char [unModuleSize];
			if (!pMemory) {
				return bResult;
			}

			memcpy(pMemory, pModuleInfo->m_pRawModule, unModuleSize);

			Encrypt = reinterpret_cast<fnEncrypt>(Scan::FindSignature(hModule, "\x55\x8B\xEC\x83\xEC\x0C\x53\x56\x57\x8B\xF9"));
			if (Encrypt) {
				if (distormx_hook(reinterpret_cast<void**>(&Encrypt), Encrypt_Hook)) {
					clrprintf(COLOR::COLOR_RED, "[DumpVAC] Encrypt hooked.\n");
				}
			}

			// Removing loader
			unsigned char* pLoader = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x55\x8B\xEC\xB8\xF0\x43\x00\x00")));
			if (!pLoader) {
				delete[] pMemory;
				return bResult;
			}

			if (!Memory::ChangeProtection(pLoader, 1, PAGE_READWRITE)) {
				delete[] pMemory;
				return bResult;
			}

			pLoader[0] = 0xC3;

			Memory::RestoreProtection(pLoader);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] Loader patched.\n");

			// Removing all junks/trash.
			unsigned char* pMagic = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x51\x53\x56\x57\x8B")));
			if (!pMagic) {
				delete[] pMemory;
				return bResult;
			}

			if (!Memory::ChangeProtection(pMagic, 6, PAGE_READWRITE)) {
				delete[] pMemory;
				return bResult;
			}

			pMagic[0] = 0xB8;
			pMagic[1] = 0x00;
			pMagic[2] = 0x00;
			pMagic[3] = 0x00;
			pMagic[4] = 0x00;
			pMagic[5] = 0xC3;

			Memory::RestoreProtection(pMagic);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] Magic patched.\n");

			unsigned char* pRDTSC = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x0F\x31\x83\xA4\x24\xCC")));
			if (!pRDTSC) {
				delete[] pMemory;
				return bResult;
			}

			if (!Memory::ChangeProtection(pRDTSC, 21, PAGE_READWRITE)) {
				delete[] pMemory;
				return bResult;
			}

			//unsigned long long rdtsc = __rdtsc();
			//unsigned int edx = (rdtsc >> 32) & 0xFFFFFFFF;
			//unsigned int eax = rdtsc & 0xFFFFFFFF;

			unsigned int edx = 0x0009E9EC; // High
			unsigned int eax = 0xA8423856; // Low

			// and dword ptr ss:[esp+0xCC], 0x0
			pRDTSC[0 ] = 0x83;
			pRDTSC[1 ] = 0xA4;
			pRDTSC[2 ] = 0x24;
			pRDTSC[3 ] = 0xCC;
			pRDTSC[4 ] = 0x00;
			pRDTSC[5 ] = 0x00;
			pRDTSC[6 ] = 0x00;
			pRDTSC[7 ] = 0x00;

			// mov dword ptr ss:[esp+0x1C], 0x0009E9EC
			pRDTSC[8 ] = 0xC7;
			pRDTSC[9 ] = 0x44;
			pRDTSC[10] = 0x24;
			pRDTSC[11] = 0x1C;
			memcpy(&pRDTSC[12], &edx, 4);

			// mov eax, 0xA8423856
			pRDTSC[16] = 0xB8;
			memcpy(&pRDTSC[17], &eax, 4);

			Memory::RestoreProtection(pRDTSC);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] RDTSC fixed.\n");

			unsigned char* pEncryptedSize = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x68\x2A\x2A\x2A\x2A\x8B\xD1")));
			if (!pEncryptedSize) {
				delete[] pMemory;
				return bResult;
			}

			const unsigned int unEncryptedSize = *reinterpret_cast<unsigned int*>(pEncryptedSize + 1);
			if (!unEncryptedSize) {
				delete[] pMemory;
				return bResult;
			}

			unsigned char* pEncryptedPayload = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\xB9\x2A\x2A\x2A\x2A\x68")));
			if (!pEncryptedPayload) {
				delete[] pMemory;
				return bResult;
			}

			pEncryptedPayload = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned int*>(pEncryptedPayload + 1));
			if (!pEncryptedPayload) {
				delete[] pMemory;
				return bResult;
			}

			unsigned char* pFirstIceKey = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\xA3\x2A\x2A\x2A\x2A\xC7")));
			if (!pFirstIceKey) {
				delete[] pMemory;
				return bResult;
			}

			unsigned char* pSecondIceKey = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(pFirstIceKey + 6, reinterpret_cast<size_t>(pFirstIceKey) - reinterpret_cast<size_t>(hModule) - 6,  "\xA3\x2A\x2A\x2A\x2A\xC7")));
			if (!pSecondIceKey) {
				delete[] pMemory;
				return bResult;
			}

			pFirstIceKey = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned int*>(pFirstIceKey + 1) + 0x10);
			pSecondIceKey = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned int*>(pSecondIceKey + 1) + 0x10);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] VAC FKey: %02X %02X %02X %02X %02X %02X %02X %02X\n", pFirstIceKey[0], pFirstIceKey[1], pFirstIceKey[2], pFirstIceKey[3], pFirstIceKey[4], pFirstIceKey[5], pFirstIceKey[6], pFirstIceKey[7]);

			IceKey ICE(1);
			ICE.set(pFirstIceKey);
			ICE.decrypt(&pIceKey1[0], &pIceKey1[0]);
			ICE.set(pIceKey1);

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] VAC  DKey: %02X %02X %02X %02X %02X %02X %02X %02X\n", pIceKey1[0], pIceKey1[1], pIceKey1[2], pIceKey1[3], pIceKey1[4], pIceKey1[5], pIceKey1[6], pIceKey1[7]);

			unsigned char* pPayload = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindData(pMemory, unModuleSize, pEncryptedPayload, unEncryptedSize)));
			if (!pPayload) {
				delete[] pMemory;
				return bResult;
			}

			for (unsigned int i = 0; i < unEncryptedSize; i += 8) {
				ICE.decrypt(&pPayload[i], &pPayload[i]);
			}

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] VAC SKey: %02X %02X %02X %02X %02X %02X %02X %02X\n", pSecondIceKey[0], pSecondIceKey[1], pSecondIceKey[2], pSecondIceKey[3], pSecondIceKey[4], pSecondIceKey[5], pSecondIceKey[6], pSecondIceKey[7]);

			char szBuffer[2048];
			memset(szBuffer, 0, sizeof(szBuffer));
			sprintf_s(szBuffer, "%sVAC_%08X.dll", g_pLoaderData->m_pLoaderPath, unHash);
			FILE* pFile = nullptr;
			fopen_s(&pFile, szBuffer, "wb+");
			if (!pFile) {
				delete[] pMemory;
				return bResult;
			}

			reinterpret_cast<PMODULE_HEADER>(pMemory)->m_unCrypt = 0;

			if (fwrite(pMemory, 1, unModuleSize, pFile) != unModuleSize) {
				fclose(pFile);
				delete[] pMemory;
				return bResult;
			}

			fclose(pFile);
			delete[] pMemory;

			clrprintf(COLOR::COLOR_RED, "[DumpVAC] Dumped to `%s`.\n", szBuffer);
		}
	}

	return bResult;
}

fnCallFunctionAsyncInternal CallFunctionAsyncInternal = nullptr;
MODULE_RESULT __fastcall CallFunctionAsyncInternal_Hook(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unActionID, int nC, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize) {

	clrprintf(COLOR::COLOR_WHITE, "[DumpVAC] ");
	clrprintf(COLOR::COLOR_CYAN, "PreCallFunctionAsyncInternal\n");
	clrprintf(COLOR::COLOR_GREEN, " -> (this)      = 0x%08X\n", reinterpret_cast<unsigned int>(pThis));
	clrprintf(COLOR::COLOR_GREEN, " -> Hash        = 0x%08X\n", unHash);
	clrprintf(COLOR::COLOR_GREEN, " -> Flags       = 0x%02X\n", unFlags);
	clrprintf(COLOR::COLOR_GREEN, " -> ActionID     = 0x%08X\n", unActionID);
	clrprintf(COLOR::COLOR_GREEN, " -> InData      = 0x%08X\n", reinterpret_cast<unsigned int>(pInData));
	clrprintf(COLOR::COLOR_GREEN, " -> InDataSize  = 0x%08X\n", unInDataSize);
	clrprintf(COLOR::COLOR_GREEN, " -> OutData     = 0x%08X\n", reinterpret_cast<unsigned int>(pOutData));
	clrprintf(COLOR::COLOR_GREEN, " -> OutDataSize = 0x%08X\n", pOutDataSize ? *pOutDataSize : 0x00000000ui32);

	unsigned char* pIn = reinterpret_cast<unsigned char*>(pInData);
	if (pIn) {
		auto Keys = g_IceKeys.find(unHash);
		if (Keys == g_IceKeys.end()) {
			auto vKeys = std::array<unsigned char, 16>();
			memcpy(vKeys.data(), pIn + 0x10, 16);
			clrprintf(COLOR::COLOR_GREEN, " -> FKey        = %02X %02X %02X %02X %02X %02X %02X %02X\n", vKeys[0], vKeys[1], vKeys[2], vKeys[3], vKeys[4], vKeys[5], vKeys[6], vKeys[7]);
			clrprintf(COLOR::COLOR_GREEN, " -> SKey        = %02X %02X %02X %02X %02X %02X %02X %02X\n", vKeys[8], vKeys[9], vKeys[10], vKeys[11], vKeys[12], vKeys[13], vKeys[14], vKeys[15]);
			g_IceKeys.insert(std::pair<unsigned int, std::array<unsigned char, 16>>(unHash, std::move(vKeys)));
		} else {
			memcpy(Keys->second.data(), pIn + 0x10, 16);
		}
	}

	MODULE_RESULT unResult = CallFunctionAsyncInternal(pThis, pEDX, unHash, unFlags, nA, nB, unActionID, nC, pInData, unInDataSize, pOutData, pOutDataSize);

	clrprintf(COLOR::COLOR_WHITE, "[DumpVAC] ");
	clrprintf(COLOR::COLOR_CYAN, "PostCallFunctionAsyncInternal\n");
	clrprintf(COLOR::COLOR_GREEN, " -> (this)      = 0x%08X\n", reinterpret_cast<unsigned int>(pThis));
	clrprintf(COLOR::COLOR_GREEN, " -> Hash        = 0x%08X\n", unHash);
	clrprintf(COLOR::COLOR_GREEN, " -> Flags       = 0x%02X\n", unFlags);
	clrprintf(COLOR::COLOR_GREEN, " -> ActionID    = 0x%08X\n", unActionID);
	clrprintf(COLOR::COLOR_GREEN, " -> InData      = 0x%08X\n", reinterpret_cast<unsigned int>(pInData));
	clrprintf(COLOR::COLOR_GREEN, " -> InDataSize  = 0x%08X\n", unInDataSize);
	clrprintf(COLOR::COLOR_GREEN, " -> OutData     = 0x%08X\n", reinterpret_cast<unsigned int>(pOutData));
	clrprintf(COLOR::COLOR_GREEN, " -> OutDataSize = 0x%08X\n", pOutDataSize ? *pOutDataSize : 0x00000000ui32);
	clrprintf(COLOR::COLOR_GREEN, " -> Result      = 0x%08X\n", unResult);

	return unResult;
}

DWORD WINAPI MainRoutine(LPVOID lpThreadParameter) {
	if (!ConnectToConsole()) {
		return 0;
	}

	clrprintf(COLOR::COLOR_WHITE, "DumpVAC [Version 1.0.0] (zeze839@gmail.com)\n\n");
	clrprintf(COLOR::COLOR_WHITE, "[DumpVAC] Loading... ");

	if (!g_pLoaderData) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Loader data not available.\n");
		return 0;
	}

	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel32) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `kernel32.dll` module.\n");
		return 0;
	}

	LoadLibraryExW_Original = reinterpret_cast<fnLoadLibraryExW>(GetProcAddress(hKernel32, "LoadLibraryExW"));
	if (!LoadLibraryExW_Original) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `LoadLibraryExW` function.\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&LoadLibraryExW_Original), LoadLibraryExW_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to hook `LoadLibraryExW` function.\n");
		return 0;
	}

	HMODULE hSteamService = GetModuleHandle(_T("SteamService.dll"));
	if (!hSteamService) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `SteamService.dll` module.\n");
		return 0;
	}

	unsigned char* pJZ = const_cast<unsigned char*>(reinterpret_cast<const unsigned char* const>(Scan::FindData(hSteamService, reinterpret_cast<const unsigned char*>("\x74\x47\x6A\x01\x6A\x00"), 6)));
	if (!pJZ) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `74 47 6A 01 6A 00` signature.\n");
		return 0;
	}

	if (!Memory::ChangeProtection(pJZ, 1, PAGE_EXECUTE_READWRITE)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to change memory protection for `74 47 6A 01 6A 00` signature.\n");
		return 0;
	}

	// Forces to use LoadModuleStandard. (Potential File Spam)
	pJZ[0] = 0xEB; // jz -> jmp

	if (!Memory::RestoreProtection(pJZ)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to change memory protection for `74 47 6A 01 6A 00` signature.\n");
		return 0;
	}

	pJZ = const_cast<unsigned char*>(reinterpret_cast<const unsigned char* const>(Scan::FindSignature(hSteamService, "\x74\x18\xE8\x2A\x2A\x2A\x2A\x6A\x2A\xFF\x76\x18\x8B\xC8\x8B\x10\xFF\x52\x2A\xC7\x46\x18\x2A\x2A\x2A\x2A\x5E")));
	if (!pJZ) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");
		return 0;
	}

	if (!Memory::ChangeProtection(pJZ, 1, PAGE_EXECUTE_READWRITE)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to patch `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");

		return 0;
	}

	// Forces to save RAW module in `MODULE_INFO`. (Potential Memory Leak?)
	pJZ[0] = 0xEB; // jz -> jmp

	if (!Memory::RestoreProtection(pJZ)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to change memory protection for `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");
		return 0;
	}

	LoadModuleStandard = reinterpret_cast<fnLoadModuleStandard>(Scan::FindSignature(hSteamService, "\x55\x8B\xEC\x83\xEC\x28\x53\x56\x8B\x75"));
	if (!LoadModuleStandard) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `55 8B EC 83 EC 28 53 56 8B 75` signature.\n");
		return 0;
	}

	CallFunctionAsyncInternal = reinterpret_cast<fnCallFunctionAsyncInternal>(Scan::FindSignature(hSteamService, "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x68\x2A\x2A\x2A\x2A\x64\xA1\x2A\x2A\x2A\x2A\x50\x64\x89\x25\x2A\x2A\x2A\x2A\x83\xEC\x6C"));
	if (!CallFunctionAsyncInternal) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Unable to find `55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 6C` signature.\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&LoadModuleStandard), LoadModuleStandard_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to hook function with `55 8B EC 83 EC 28 53 56 8B 75` signature.\n");
		return 0;
	}

	if (!distormx_hook(reinterpret_cast<void**>(&CallFunctionAsyncInternal), CallFunctionAsyncInternal_Hook)) {
		clrprintf(COLOR::COLOR_RED, "[ FAIL ]\n");
		clrprintf(COLOR::COLOR_RED, "[DumpVAC] Error: ");
		clrprintf(COLOR::COLOR_WHITE, "Failed to hook function with `55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 6C` signature.\n");
		return 0;
	}

	clrprintf(COLOR::COLOR_GREEN, "[  OK  ]\n");
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	g_pLoaderData = reinterpret_cast<PLOADER_DATA>(lpReserved);
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			CreateThread(nullptr, 0x100000 /* 1 MiB */, MainRoutine, lpReserved, NULL, nullptr);
		}
		case DLL_THREAD_ATTACH: {
			break;
		}
		case DLL_THREAD_DETACH: {
			break;
		}
		case DLL_PROCESS_DETACH: {
			break;
		}
	}
	return TRUE;
}
