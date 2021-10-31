#include "user_common.h"
#include "user_sr.h"
//��õ�ǰ���̵�PEB��ַ
PVOID WINAPI GetPeb()
{

	PVOID ppeb = NULL;
	//���PEB
#ifdef _M_IX86 
	__asm
	{
		mov eax, dword ptr fs : [0x30];
		mov ppeb, eax;
	}
#elif defined(_M_AMD64)
	ppeb = (PVOID)__readgsqword(0x60);
#endif
	if (ppeb == NULL)
		return NULL;
	else
		return ppeb;
}


void DebugPrint(const char *format, ...)
{
	char buf[MAX_PATH * 2];
	va_list ap;
	va_start(ap, format);
	vsprintf(buf, format, ap);
	va_end(ap);
	OutputDebugStringA(buf);
}

LARGE_INTEGER GetTimeCount()
{
	LARGE_INTEGER t;
	QueryPerformanceCounter(&t);
	return t;
}

LARGE_INTEGER GetTimeFrequency()
{
	LARGE_INTEGER t;
	QueryPerformanceFrequency(&t);
	return t;
}


//��ansi�ַ�ת��ΪUnicode�ַ�
//lpChar		ansi�ַ�������ʼ��ַ
//lpTchar		ת���󱣴�unicode�ַ�����ʼ��ַ
//lengthTchar	����unicode�ַ�����󳤶�
bool Char8ToUnicode16(char *lpChar, wchar_t *lpTchar, DWORD lengthTchar)
{
	DWORD dLength = MultiByteToWideChar(CP_ACP, 0, lpChar, (int)strlen(lpChar) + 1, NULL, 0);
	if (dLength >= lengthTchar)return false;
	MultiByteToWideChar(CP_ACP, 0, lpChar, (int)strlen(lpChar) + 1, lpTchar, dLength);
	return true;
}

//��Unicode�ַ�ת��Ϊansi�ַ�
//lpTchar		unicode�ַ�������ʼ��ַ
//lpAnsi		ת���󱣴�ansi�ַ�����ʼ��ַ
//lengthChar	����ansi�ַ�����󳤶�
bool Unicode16ToChar8(wchar_t *lpTcharStr, char *lpAnsiStr, DWORD lengthChar)
{
	DWORD dLength = WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, NULL, 0, NULL, NULL);
	if (dLength >= lengthChar)return false;
	if (WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, lpAnsiStr, dLength, NULL, NULL) == dLength)return true;
	return false;
}

namespace path
{
	BOOLEAN NtPathToDosPathW(const wchar_t *FullNtPath, wchar_t *FullDosPath)
	{
		wchar_t DosDevice[4] = { 0 };			//dos�豸����󳤶�Ϊ4
		wchar_t NtPath[64] = { 0 };				//nt�豸����󳤶�Ϊ64
		wchar_t *RetStr = NULL;
		size_t NtPathLen = 0;
		if (!FullNtPath || !FullDosPath)
		{
			return FALSE;
		}
		for (short i = 65; i < 26 + 65; i++)
		{
			DosDevice[0] = i;
			DosDevice[1] = L':';
			if (QueryDosDeviceW(DosDevice, NtPath, 64))
			{
				if (NtPath)
				{
					NtPathLen = wcslen(NtPath);
					if (!wcsnicmp(NtPath, FullNtPath, NtPathLen))
					{
						wcscpy(FullDosPath, DosDevice);
						wcscat(FullDosPath, FullNtPath + NtPathLen);
						return TRUE;
					}
				}
			}
		}
		return FALSE;
	}

	BOOLEAN DosPathToNtPathW(const wchar_t *FullDosPath, wchar_t *FullNtPath)
	{
		wchar_t DosDevice[4] = { 0 };         //dos�豸����󳤶�Ϊ4
		wchar_t NtPath[64] = { 0 };         //nt�豸����󳤶�Ϊ64
		wchar_t *RetStr = NULL;
		size_t NtPathLen = 0;
		if (!FullNtPath || !FullDosPath)
		{
			return FALSE;
		}
		DosDevice[0] = FullDosPath[0];
		DosDevice[1] = L':';
		if (QueryDosDeviceW(DosDevice, NtPath, 64))
		{
			if (NtPath)
			{
				wcscpy(FullNtPath, NtPath);
				wcscat(FullNtPath, FullDosPath + 2);
				return TRUE;
			}
		}
		return FALSE;
	}

	BOOLEAN NtPathToDosPathA(const char *FullNtPath, char *FullDosPath)
	{
		char DosDevice[4] = { 0 };         //dos�豸����󳤶�Ϊ4
		char NtPath[64] = { 0 };         //nt�豸����󳤶�Ϊ64
		char *RetStr = NULL;
		size_t NtPathLen = 0;
		if (!FullNtPath || !FullDosPath)
		{
			return FALSE;
		}
		for (short i = 65; i < 26 + 65; i++)
		{
			DosDevice[0] = i;
			DosDevice[1] = L':';
			if (QueryDosDeviceA(DosDevice, NtPath, 64))
			{
				if (NtPath)
				{
					NtPathLen = strlen(NtPath);
					if (!strnicmp(NtPath, FullNtPath, NtPathLen))
					{
						strcpy(FullDosPath, DosDevice);
						strcat(FullDosPath, FullNtPath + NtPathLen);
						return TRUE;
					}
				}
			}
		}
		return FALSE;
	}

	BOOLEAN DosPathToNtPathA(const char *FullDosPath, char *FullNtPath)
	{
		char DosDevice[4] = { 0 };         //dos�豸����󳤶�Ϊ4
		char NtPath[64] = { 0 };         //nt�豸����󳤶�Ϊ64
		char *RetStr = NULL;
		size_t NtPathLen = 0;
		if (!FullNtPath || !FullDosPath)
		{
			return FALSE;
		}
		DosDevice[0] = FullDosPath[0];
		DosDevice[1] = L':';
		if (QueryDosDeviceA(DosDevice, NtPath, 64))
		{
			if (NtPath)
			{
				strcpy(FullNtPath, NtPath);
				strcat(FullNtPath, FullDosPath + 2);
				return TRUE;
			}
		}
		return FALSE;
	}

	//todo:������µ�·������ȷ
	BOOL DeviceNtPathToDosPath(const wchar_t* pszNtPath, wchar_t* pszDosPath)
	{
		static std::map<std::wstring, std::wstring> ntd;
		static WCHAR    szDriveStr[MAX_PATH];
		static WCHAR	szDevName[MAX_PATH];
		WCHAR			szDrive[3];
		bool			chanceUsed = false;

		if (IsBadReadPtr(pszNtPath, 1) != 0)return FALSE;
		if (IsBadWritePtr(pszDosPath, 1) != 0)return FALSE;

	START:
		if (ntd.size() == 0)
		{
			memset(szDriveStr, 0, ARRAYSIZE(szDriveStr));
			memset(szDevName, 0, ARRAYSIZE(szDevName));
			if (GetLogicalDriveStringsW(sizeof(szDriveStr), szDriveStr))
			{
				for (int i = 0; szDriveStr[i]; i += 4)
				{
					if (!lstrcmpiW(&(szDriveStr[i]), L"A:\\") || !lstrcmpiW(&(szDriveStr[i]), L"B:\\"))//���Դ�Сд�ıȽ��ַ���
						continue;
					szDrive[0] = szDriveStr[i];
					szDrive[1] = szDriveStr[i + 1];
					szDrive[2] = '\0';
					if (!QueryDosDeviceW(szDrive, szDevName, MAX_PATH))//��ѯ Dos �豸���������̷����ƣ��硰c:��������dos����
						return FALSE;
					ntd.emplace(szDrive, szDevName);
				}
			}
			chanceUsed = true;
		}

		for (auto &f : ntd)
		{
			if (_wcsnicmp(pszNtPath, f.second.c_str(), f.second.length()) == 0)//�Ƚϵ�ǰ�̷�
			{
				wcscpy(pszDosPath, f.first.c_str());//����������  
				wcscat(pszDosPath, pszNtPath + f.second.length());//����·��  
				return TRUE;
			}

		}

		if (!chanceUsed)
		{
			//ʧ�ܣ����������һ����Ϊ��������������Ϣ����ˢ�µ��µĲ�ѯʧ�ܣ���˴�ͷ����
			ntd.clear();
			goto START;
		}

		return FALSE;

	}

	bool Exists(std::string path)
	{
		return PathFileExistsA(path.c_str());
	}

	bool RemoveFile(std::string path)
	{
		int ret = -1;
		if (Exists(path))ret = remove(path.c_str());//TODO:��������ļ���ҲӦ��ʧ�ܣ�
		if (ret < 0)return false;
		else return true;
	}

	std::string Join(std::initializer_list<std::string> li)
	{
		std::string ret = "";
		for (auto sp : li)
		{
			while (sp.back() == '\\' || sp.back() == '/')sp.pop_back();
			while (sp.front() == '\\' || sp.front() == '/')sp = sp.substr(1);
			ret += "\\" + sp;
		}
		return ret.substr(1);
	}

	std::string GetCurrentWorkingPath()
	{
		char pt[MAX_PATH * 2];
		memset(pt, 0, 2 * MAX_PATH);
		GetCurrentDirectoryA(2 * MAX_PATH, pt);
		return std::string(pt);
	}

	bool SetCurrentWorkingPath(std::string path)
	{
		if (0 < SetCurrentDirectoryA(path.c_str()))return true;
		return false;
	}

	DWORD CurrentProcessPID()
	{
		return GetCurrentProcessId();
	}

	std::string CurrentProcessCommandLine()
	{
		return std::string(GetCommandLineA());
	}

	std::string CurrentProcessName()
	{
		char exeFullPath[MAX_PATH];
		GetModuleFileNameA(NULL, exeFullPath, MAX_PATH);
		auto strPath = (std::string)exeFullPath;
		for (size_t i = 0; i < strPath.length(); i++)if (strPath[i] == '/')strPath[i] = '\\';
		size_t pos = strPath.find_last_of('\\', strPath.length());
		return strPath.substr(pos + 1, strPath.length());
	}

	std::string CurrentProcessExcultFilePath()
	{
		char exeFullPath[MAX_PATH];
		GetModuleFileNameA(NULL, exeFullPath, MAX_PATH);
		auto strPath = (std::string)exeFullPath;
		for (size_t i = 0; i < strPath.length(); i++)if (strPath[i] == '/')strPath[i] = '\\';
		size_t pos = strPath.find_last_of('\\', strPath.length());
		return strPath.substr(0, pos);
	}

	std::string CurrentProcessExcultFileFullPath()
	{
		char exeFullPath[MAX_PATH];
		GetModuleFileNameA(NULL, exeFullPath, MAX_PATH);
		return (std::string)exeFullPath;
	}

	OSVERSIONINFOA GetOSVersion()
	{
		OSVERSIONINFOA osinfo = { 0 };
		osinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		GetVersionExA(&osinfo);
		return osinfo;//todo:�Ͻ��Ժ�˵��
	}

	// �ж��Ƿ��ظ�����
	BOOL IsAlreadyRun(const char *mutexName)
	{
		HANDLE hMutex = NULL;
		hMutex = ::CreateMutexA(NULL, FALSE, mutexName);
		if (hMutex)
		{
			if (ERROR_ALREADY_EXISTS == ::GetLastError())
			{
				return TRUE;
			}
		}
		return FALSE;
	}


	std::vector<DWORD> GetProcessIdByProcessName(PCSTR pszProcessName)
	{
		std::vector<DWORD> pids;

		// ��ȡ���̿���
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (NULL == hSnapshot)return pids;

		PROCESSENTRY32 pe32 = { 0 };
		RtlZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);

		// ��ȡ��һ�����̿�����Ϣ
		BOOL bRet = Process32First(hSnapshot, &pe32);
		if (!bRet) return pids;
		while (bRet)
		{
			// ��ȡ������Ϣ
			if (0 == lstrcmpiA(pe32.szExeFile, pszProcessName))
			{
				pids.push_back(pe32.th32ProcessID);
			}
			// ������һ�����̿�����Ϣ
			bRet = Process32Next(hSnapshot, &pe32);
		}
		return pids;
	}

	// ����PID��ȡ���е���Ӧ�߳�ID
	std::vector<DWORD> GetAllThreadIdByProcessId(DWORD dwProcessId)
	{
		std::vector<DWORD> vecThreadId;

		THREADENTRY32 te32 = { 0 };
		HANDLE hSnapshot = NULL;
		BOOL bRet = TRUE;

		// ��ȡ�߳̿���
		RtlZeroMemory(&te32, sizeof(te32));
		te32.dwSize = sizeof(te32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (NULL == hSnapshot)return vecThreadId;

		// ��ȡ��һ���߳̿�����Ϣ
		bRet = Thread32First(hSnapshot, &te32);
		if (!bRet) return vecThreadId;
		while (bRet)
		{
			// ��ȡ���̶�Ӧ���߳�ID
			if (te32.th32OwnerProcessID == dwProcessId)
			{
				vecThreadId.push_back(te32.th32ThreadID);
			}
			// ������һ���߳̿�����Ϣ
			bRet = Thread32Next(hSnapshot, &te32);
		}
		return vecThreadId;
	}

	//����򿪽���ʧ�ܣ�Ӧ����������Ȩ�ޡ������Ȼʧ�ܣ���ʹ�ù���Աģʽ��
	BOOL EnableDebugPrivilege() 
	{
		HANDLE hToken;
		BOOL ret = FALSE;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

			ret = (GetLastError() == ERROR_SUCCESS);
			CloseHandle(hToken);
		}
		return ret;
	}

	BOOL Is64bitProcess(DWORD dwProcessId)
	{
		if (dwProcessId == 0)
		{
			int pointLength = sizeof(PVOID);
			if (pointLength == 8) return TRUE;
			return FALSE;
		}
		if (Is64bitOS() == FALSE)
			return FALSE;
		EnableDebugPrivilege();
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
		if (!hProcess)
		{
			DbgPrint("Is64bitProcess() : OpenProcess() failed!!! [%d], Please run this program with administrator privileges.", GetLastError());
			return FALSE;
		}

		typedef BOOL(WINAPI *PFIsWow64Process) (HANDLE, PBOOL);
		PFIsWow64Process pfIsWow64Process = (PFIsWow64Process)(PVOID)GetProcAddress(
			GetModuleHandleA("kernel32"),
			"IsWow64Process"
		);
		if (!pfIsWow64Process)
		{
			DbgPrint("Is64bitProcess() : GetProcAddress(GetModuleHandleA(\"kernel32\"),\"IsWow64Process\") failed!!! [%d]", GetLastError());

			return FALSE;
		}
		BOOL bIsWow64 = FALSE;
		pfIsWow64Process(hProcess, &bIsWow64);
		CloseHandle(hProcess);
		if (bIsWow64)return FALSE;
		else return TRUE;
	}


	BOOL Is64bitOS()
	{
		typedef VOID(WINAPI *PFGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
		PFGetNativeSystemInfo pfGetNativeSystemInfo = (PFGetNativeSystemInfo)(PVOID)GetProcAddress(
			GetModuleHandleA("kernel32"),
			"GetNativeSystemInfo"
		);
		if (pfGetNativeSystemInfo)
		{
			SYSTEM_INFO stInfo = { 0 };
			pfGetNativeSystemInfo(&stInfo);
			if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
				|| stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	std::vector<MODULEENTRY32> ListProcessModules(DWORD dwProcessId)
	{
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		std::vector<MODULEENTRY32> ret;
		MODULEENTRY32 me32;

		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hModuleSnap == INVALID_HANDLE_VALUE)return ret;
		me32.dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(hModuleSnap, &me32))
		{
			CloseHandle(hModuleSnap);
			return ret;
		}

		do
		{
			ret.push_back(me32);

		} while (Module32Next(hModuleSnap, &me32));

		CloseHandle(hModuleSnap);
		return ret;
	}

	PBYTE GetFileAllBytes(std::string filepath, DWORD &dwFileSize)
	{
		BYTE * pBuffer = NULL;
		HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)return NULL;
		dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize == 0) return NULL;
		pBuffer = new BYTE[dwFileSize + 2];
		if (pBuffer == 0)
		{
			dwFileSize = 0;
			return NULL;
		}
		pBuffer[dwFileSize] = 0;
		pBuffer[dwFileSize + 1] = 0;
		DWORD dwRead = 0;
		ReadFile(hFile, pBuffer, dwFileSize, &dwRead, NULL);
		if (dwRead == dwFileSize) return pBuffer;
		dwFileSize = 0;
		return NULL;
	}

	//�����̵߳Ĵ���ʱ��
	ULONGLONG ThreadStartTime(DWORD dwThreadId)
	{
		FILETIME times[4] = { };
		HANDLE threadhandle = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		if (threadhandle == NULL)
		{
			DbgPrint("ThreadStartTime() : OpenThread() failed!!! [%d]\n", GetLastError());
			return (-1);
		}
		if (GetThreadTimes(threadhandle, &times[0], &times[1], &times[2], &times[3]))
			return (static_cast<ULONGLONG>(times[0].dwHighDateTime) << 32) | times[0].dwLowDateTime;
		return (-1);
	}

	DWORD ProcessMainThread(DWORD dwProcessId)
	{
		DWORD ret = 0;
		ULONGLONG mintime = (-1);
		auto tids = GetAllThreadIdByProcessId(dwProcessId);
		for (const auto& tid : tids)
		{
			ULONGLONG time = ThreadStartTime(tid);
			if (time < mintime)
			{
				mintime = time;
				ret = tid;
			}
		}
		return ret;
	}

	BOOL IsRunasAdmin()
	{
		BOOL bElevated = FALSE;
		HANDLE hToken = NULL;

		// Get current process token
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			return FALSE;

		TOKEN_ELEVATION tokenEle;
		DWORD dwRetLen = 0;


		if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
		{
			if (dwRetLen == sizeof(tokenEle))
			{
				bElevated = tokenEle.TokenIsElevated;
			}
		}

		CloseHandle(hToken);
		return bElevated;

	}
}

namespace puppet
{
#ifndef _WIN64
	BOOL IsPE32File(const LPBYTE lpPEFileData);
	BOOL UnMapTargetProcess(HANDLE hProcess, CONTEXT& stThreadContext);

	BOOL CreatePuppetProcess(std::string strTargetProcess, std::string strPuppetProcess)
	{
		BOOL bSucess = TRUE;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		LPBYTE lpBuffer = NULL;
		do
		{
			hFile = CreateFileA(
				strPuppetProcess.c_str(),
				GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				0);
			if (INVALID_HANDLE_VALUE == hFile)
			{
				bSucess = FALSE;
				break;
			}
			DWORD dwFileSize = GetFileSize(hFile, 0);
			if (!dwFileSize)
			{
				bSucess = FALSE;
				break;
			}

			lpBuffer = new(std::nothrow) BYTE[dwFileSize];

			DWORD dwNumofRead = 0;
			if (!ReadFile(hFile, lpBuffer, dwFileSize, &dwNumofRead, 0)
				|| dwFileSize != dwNumofRead)
			{
				bSucess = FALSE;
				break;
			}

			bSucess = CreatePuppetProcess(strTargetProcess, lpBuffer);

		} while (FALSE);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
		if (lpBuffer != NULL)
		{
			delete[] lpBuffer;
			lpBuffer = NULL;
		}
		return bSucess;
	}

	BOOL CreatePuppetProcess(std::string strTargetProcess, LPBYTE lpPuppetProcessData)
	{
		STARTUPINFOA stSi = { 0 };
		PROCESS_INFORMATION stPi = { 0 };
		stSi.cb = sizeof(stSi);

		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeaders;
		//�����ʵPE�ļ�����Ч��
		pDosHeader = (PIMAGE_DOS_HEADER)lpPuppetProcessData;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}
		pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpPuppetProcessData + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}
		//�Թ���ģʽ�������ܽ���
		if (CreateProcessA(strTargetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &stSi, &stPi) == 0)
		{
			return FALSE;
		}

		CONTEXT stThreadContext;
		stThreadContext.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(stPi.hThread, &stThreadContext) == 0)
		{
			return FALSE;
		}
		//ж��ԭʼ���̿ռ�
		if (!UnMapTargetProcess(stPi.hProcess, stThreadContext))
		{
			return FALSE;
		}
		//�����µ�PE��ִ���ļ��ľ����С������ָ�������Ļ�ַ
		LPVOID lpPuppetProcessBaseAddr = VirtualAllocEx(stPi.hProcess,
			(LPVOID)pNtHeaders->OptionalHeader.ImageBase,
			pNtHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (lpPuppetProcessBaseAddr == NULL)
		{
			return FALSE;
		}

		//��PE�ļ�ͷд���µ������ڴ��У�ģ���ļ�ӳ�䣩
		BOOL bRet = WriteProcessMemory(stPi.hProcess, lpPuppetProcessBaseAddr, lpPuppetProcessData, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
		if (!bRet)
		{
			return FALSE;
		}
		//��PE�ĸ�����д���µ������ڴ��У�ģ���ļ�ӳ�䣩
		LPVOID lpSectionBaseAddr = (LPVOID)((DWORD)lpPuppetProcessData + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		PIMAGE_SECTION_HEADER pSectionHeader;
		for (DWORD dwIndex = 0; dwIndex < pNtHeaders->FileHeader.NumberOfSections; ++dwIndex)
		{
			pSectionHeader = (PIMAGE_SECTION_HEADER)lpSectionBaseAddr;
			bRet = WriteProcessMemory(stPi.hProcess,
				(LPVOID)((DWORD)lpPuppetProcessBaseAddr + pSectionHeader->VirtualAddress),
				(LPCVOID)((DWORD)lpPuppetProcessData + pSectionHeader->PointerToRawData),
				pSectionHeader->SizeOfRawData,
				NULL);
			if (!bRet)
			{
				return FALSE;
			}
			lpSectionBaseAddr = (LPVOID)((DWORD)lpSectionBaseAddr + sizeof(IMAGE_SECTION_HEADER));
		}

		//�޸�PEB��ʹ�õ�ImageBase
		DWORD dwImageBase = pNtHeaders->OptionalHeader.ImageBase;
		bRet = WriteProcessMemory(stPi.hProcess, (LPVOID)(stThreadContext.Ebx + 8), (LPCVOID)&dwImageBase, sizeof(PVOID), NULL);
		if (!bRet)
		{
			return FALSE;
		}
		//�޸�EP����ĵ�ַ
		stThreadContext.Eax = dwImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
		bRet = SetThreadContext(stPi.hThread, &stThreadContext);
		if (!bRet)
		{
			return FALSE;
		}
		//ʹ�������-1���ָ��̣߳�
		ResumeThread(stPi.hThread);

		return TRUE;
	}

	BOOL IsPE32File(const LPBYTE lpPEFileData)
	{
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeaders;
		// Check DOS header magic
		pDosHeader = (PIMAGE_DOS_HEADER)lpPEFileData;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}

		// Check PE header magic
		pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpPEFileData + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}

		return TRUE;
	}

	BOOL UnMapTargetProcess(HANDLE hProcess, CONTEXT& stThreadContext)
	{
		typedef ULONG(WINAPI *PNtUnmapViewOfSection) (HANDLE hProcess, PVOID lpBaseAddress);//ntdll!NtUnmapViewOfSection ����ָ��
		DWORD dwProcessBaseAddr = 0;
		// EBX points to PEB, offset 8 is the pointer to the base address
		if (ReadProcessMemory(hProcess, (LPCVOID)(stThreadContext.Ebx + 8), &dwProcessBaseAddr, sizeof(PVOID), NULL) == 0)
		{
			return FALSE;
		}

		HMODULE hNtModule = GetModuleHandleA("ntdll.dll");
		if (hNtModule == NULL)
		{
			return FALSE;
		}

		PNtUnmapViewOfSection pfnNtUnmapViewOfSection = (PNtUnmapViewOfSection)(PVOID)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
		if (pfnNtUnmapViewOfSection == NULL)
		{
			return FALSE;
		}

		return (pfnNtUnmapViewOfSection(hProcess, (PVOID)dwProcessBaseAddr) == 0);
	}
#endif
}

namespace inject
{
	//�жϲ���ϵͳ�Ƿ���vista֮��Ĳ���ϵͳ�汾
	BOOL IsVistaLater()
	{
		OSVERSIONINFO osvi;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		GetVersionEx(&osvi);//�ú���ֻ����win8֮ǰ��ϵͳʹ��

		if (osvi.dwMajorVersion >= 6)
			return TRUE;

		return FALSE;
	}

#ifdef _WIN64
	typedef DWORD64(WINAPI *PFNTCREATETHREADEX)//����ָ�룺NtCreateThreadEx x64
		(
			PHANDLE ThreadHandle,
			ACCESS_MASK DesiredAccess,
			LPVOID ObjectAttributes,
			HANDLE ProcessHandle,
			LPTHREAD_START_ROUTINE lpStartAddress,
			LPVOID lpParameter,
			BOOL CreateSuspended,
			DWORD64 dwStackSize,
			DWORD64 dw1,
			DWORD64 dw2,
			LPVOID Unknown
			);
#else
	typedef DWORD(WINAPI *PFNTCREATETHREADEX)//����ָ�룺NtCreateThreadEx x86
		(
			PHANDLE                 ThreadHandle,
			ACCESS_MASK             DesiredAccess,
			LPVOID                  ObjectAttributes,
			HANDLE                  ProcessHandle,
			LPTHREAD_START_ROUTINE  lpStartAddress,
			LPVOID                  lpParameter,
			BOOL	                CreateSuspended,
			DWORD                   dwStackSize,
			DWORD                   dw1,
			DWORD                   dw2,
			LPVOID                  Unknown
			);
#endif // _WIN64

	//��Ŀ������д���Զ���߳�(������Զ���߳�ע�뺯��)
	//����
	//	hProcess		Ŀ����̵ľ��
	//	pThreadProc		�̴߳�����ִ�еĺ����ĵ�ַ
	//	pRemoteBuf		ִ�еĺ����Ĳ����ĵ�ַ�������ַ��ָ��Ŀ����̵ĵ�ַ�ռ��У�
	//˵����
	//	�����д����Զ���̵߳ķ�����ҪĿ����Ϊ�˼��ݲ�ͬ�汾�Ĳ���ϵͳ��
	//	�����vista����vista����İ汾Ӧ��ʹ��NtCreateThreadEx����������Զ���߳�
	//	�����vista֮ǰ�İ汾�ǿ����ֽ�ʹ��CreateRemoteThread
	//	��Ҫ����Ϊvista�Ժ�İ汾�Ĳ���ϵͳ������windows 7��ʹ��kernel32.dll!createremotethread��0�Ự�Ľ��̴����߳�ʧ��
	//	�۲�kernel32.dll!createremotethread�ĵ�����
	//	xp��->ntdll.dll!ZwCreateThread
	//	win7 : ->kernelBase!createremotethreadEx->ntdll.dll!ZwCreateThreadEx
	//	�����ֱ�ӵ�����ײ�ĺ�����ע�����7���Ƿ����ѡ�����Ϊʹ��createremotethreadʱ�ڲ�ʹ�ù���ģʽ������
	//	����win7��ntdll.dll���ж�Ŀ����̵ĻỰ�Ƿ�����0�������0�򲻻�ָ�������̡߳�
	BOOL CreateRemoteThreadRevised(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
	{
		HANDLE					hThread = NULL;
		PFNTCREATETHREADEX	    pFunc = NULL;
		//ϵͳ�汾��vista�Ժ����NtCreateThreadEx��ע��dll����vista֮ǰ��ϵͳ�汾��CreateRemoteThread ��ע��dll
		if (IsVistaLater())//�� Vista, 7, Server2008
		{
			//��ú��� NtCreateThreadEx �ĵ�ַ
			pFunc = (PFNTCREATETHREADEX)(PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
			if (pFunc == NULL)
			{
				DbgPrint("CreateRemoteThreadRevised() : GetProcAddress() failed!!! [%d]\n", GetLastError());
				return FALSE;
			}

			pFunc(&hThread,
				0x1FFFFF,
				NULL,
				hProcess,
				pThreadProc,
				pRemoteBuf,
				FALSE,
				NULL,
				NULL,
				NULL,
				NULL);/*ִ�к��� NtCreateThreadEx */
			if (hThread == NULL)
			{
				DbgPrint("CreateRemoteThreadRevised() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
				return FALSE;
			}
		}
		else//��2000, XP, Server2003
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
			if (hThread == NULL)
			{
				DbgPrint("CreateRemoteThreadRevised() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
				return FALSE;
			}
		}
		//���ִ�� WaitForSingleObject�ȴ��̰߳�ȫ���˳����ȴ��ɹ������ע���Ѿ�����
		if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
		{
			DbgPrint("CreateRemoteThreadRevised() : WaitForSingleObject() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}

		return TRUE;
	}

	BOOL InjectByCreateRemoteThread(DWORD dwProcessId, LPCTSTR pszDllName)
	{
		HANDLE                  hProcess = NULL;
		HANDLE                  hThread = NULL;
		LPVOID                  pRemoteBuf = NULL;
		DWORD                   dwBufSize = (DWORD)(_tcslen(pszDllName) + 1) * sizeof(TCHAR);
		LPTHREAD_START_ROUTINE  pThreadProc = NULL;
		BOOL                    bRet = FALSE;
		HMODULE                 hMod = NULL;
		//��ȡĿ����̵ľ��
		if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId)))
		{
			DbgPrint("InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwProcessId, GetLastError());
			goto INJECTDLL_EXIT;
		}
		//��Ŀ����̵��ڴ��з��� dwBufSize ��С���ڴ棬��������ע���dll������·��
		pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
		if (pRemoteBuf == NULL)
		{
			DbgPrint("InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
			goto INJECTDLL_EXIT;
		}
		//�������ڴ���д��dll������·��
		if (!WriteProcessMemory(
			hProcess,				//Ŀ����̾��
			pRemoteBuf,				//д��ĵ�ַָ��
			(LPVOID)pszDllName,		//д������ݵ�ָ�� 
			dwBufSize,				//д��Ĵ�С
			NULL					//����ʵ��д�����ݴ�С�ĵ�ַ
		))
		{
			DbgPrint("InjectDll() : WriteProcessMemory() failed!!! [%d]\n", GetLastError());
			goto INJECTDLL_EXIT;
		}
		//���kernel32!LoadLibraryW API �ĵ�ַ��֮��ִ�иú���
		hMod = GetModuleHandleA("kernel32.dll");
		if (hMod == NULL)
		{
			DbgPrint("InjectDll() : GetModuleHandleA() failed!!! [%d]\n", GetLastError());
			goto INJECTDLL_EXIT;
		}
		pThreadProc = (LPTHREAD_START_ROUTINE)(PVOID)GetProcAddress(hMod, "LoadLibraryA");
		if (pThreadProc == NULL)
		{
			DbgPrint("InjectDll() : GetProcAddress() failed!!! [%d]\n", GetLastError());
			goto INJECTDLL_EXIT;
		}

		//ʹ�ô���Զ���̷߳�����Ŀ������д����߳�
		if (!CreateRemoteThreadRevised(hProcess, pThreadProc, pRemoteBuf))
		{
			DbgPrint("InjectDll() : MyCreateRemoteThread() failed!!!\n");
			goto INJECTDLL_EXIT;
		}

		bRet = TRUE;

	INJECTDLL_EXIT://ע��������׶�

		if (pRemoteBuf)
			VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

		if (hThread)
			CloseHandle(hThread);

		if (hProcess)
			CloseHandle(hProcess);

		return bRet;
	}

	DWORD InjectByApc(DWORD dwProcessId, PCSTR pszDllName)
	{
		DWORD dwRet = FALSE;
		DWORD *pThreadId = NULL;
		DWORD dwThreadIdLength = 0;
		HANDLE hProcess = NULL, hThread = NULL;
		PVOID pBaseAddress = NULL;
		PVOID pLoadLibraryAFunc = NULL;
		SIZE_T dwDllPathLen = 1 + strlen(pszDllName);

		// ��ȡ LoadLibraryA ��ַ
		pLoadLibraryAFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (!pLoadLibraryAFunc)
		{
			DbgPrint("InjectByApc() : GetProcAddress(GetModuleHandleA(\"kernel32.dll\"),\"LoadLibraryA\") failed!!! [%d]", GetLastError());
			return FALSE;
		}
		// ��ע�����
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (!hProcess)
		{
			DbgPrint("InjectByApc() : OpenProcess() failed!!! [%d]", GetLastError());
			return FALSE;
		}

		// ��ע����̿ռ������ڴ�
		pBaseAddress = VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pBaseAddress)
		{
			DbgPrint("InjectByApc() : VirtualAllocEx() failed!!! [%d]", GetLastError());
			CloseHandle(hProcess);
			return FALSE;
		};

		// ������Ŀռ���д��DLL·������ 
		WriteProcessMemory(hProcess, pBaseAddress, pszDllName, dwDllPathLen, NULL);

		std::vector<DWORD> tids = path::GetAllThreadIdByProcessId(dwProcessId);
		// ����PID��ȡ���е���Ӧ�߳�ID
		if (tids.size() == 0)
		{
			DbgPrint("InjectByApc() : GetAllThreadIdByProcessId() failed!!! [No thread find!]");
			return FALSE;
		}
		// �����߳�, ����APC
		for (auto tid : tids)
		{
			// ���߳�
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (!hThread)
			{
				DbgPrint("InjectByApc() : OpenThread() failed!!! [%d]", GetLastError());
			}
			else
			{
				// ����APC
				if (0 != QueueUserAPC((PAPCFUNC)pLoadLibraryAFunc, hThread, (ULONG_PTR)pBaseAddress))
					dwRet++;
				// �ر��߳̾��
				CloseHandle(hThread);
				hThread = NULL;
			}
		}
		if (hProcess)CloseHandle(hProcess);
		hProcess = NULL;
		return dwRet;
	}


	//����ʱ�����߳�SetThreadContextע��
#ifdef _WIN64
//x64
	unsigned char sc[] = {
		0x50,																	// push rax (save rax)
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,				// mov rax, 0CCCCCCCCCCCCCCCCh (place holder for return address)
		0x9c,                                                                   // pushfq
		0x51,                                                                   // push rcx
		0x52,                                                                   // push rdx
		0x53,                                                                   // push rbx
		0x55,                                                                   // push rbp
		0x56,                                                                   // push rsi
		0x57,                                                                   // push rdi
		0x41, 0x50,                                                             // push r8
		0x41, 0x51,                                                             // push r9
		0x41, 0x52,                                                             // push r10
		0x41, 0x53,                                                             // push r11
		0x41, 0x54,                                                             // push r12
		0x41, 0x55,                                                             // push r13
		0x41, 0x56,                                                             // push r14
		0x41, 0x57,                                                             // push r15
		0x68, 0xef,0xbe,0xad,0xde,
		0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,				// mov rcx, 0CCCCCCCCCCCCCCCCh (place holder for DLL path name)
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,				// mov rax, 0CCCCCCCCCCCCCCCCh (place holder for LoadLibrary)
		0xFF, 0xD0,																// call rax (call LoadLibrary)
		0x58,																	// pop dummy
		0x41, 0x5F,                                                             // pop r15
		0x41, 0x5E,                                                             // pop r14
		0x41, 0x5D,                                                             // pop r13
		0x41, 0x5C,                                                             // pop r12
		0x41, 0x5B,                                                             // pop r11
		0x41, 0x5A,                                                             // pop r10
		0x41, 0x59,                                                             // pop r9
		0x41, 0x58,                                                             // pop r8
		0x5F,                                                                   // pop rdi
		0x5E,                                                                   // pop rsi
		0x5D,                                                                   // pop rbp
		0x5B,                                                                   // pop rbx
		0x5A,                                                                   // pop rdx
		0x59,                                                                   // pop rcx
		0x9D,                                                                   // popfq
		0x58,                                                                   // pop rax
		0xC3                                                                    // ret
	};

#else
//x86
	unsigned char sc[] = {
		0x68, 0xcc, 0xcc, 0xcc, 0xcc,	// push 0xcccccccc(���ص�ַ)
		0x9c,							// pushfd
		0x60,							// pushad
		0x68, 0xcc, 0xcc, 0xcc, 0xcc,	// push 0xcccccccc(Dll·���ĵ�ַ)
		0xb8, 0xcc, 0xcc, 0xcc, 0xcc,	// mov eax,0xcccccccc(LoadLibraryA�����ĵ�ַ)
		0xff, 0xd0,						// call eax
		0x61,							// popad
		0x9d,							// popfd
		0xc3							// ret
	};
#endif

	//���ù����̺߳�ָ��߳��޸��̻߳������ע��
	//����
	//	dwProcessId		Ŀ����̵�PID
	//	pszDllName		��ע���DLL������·��
	//���أ��ɹ����ش���0��ʧ�ܷ���0
	DWORD InjectBySuspendResume(DWORD dwProcessId, PCSTR pszDllName)
	{
		SIZE_T stubLen = sizeof(sc);

		//��Ŀ�����
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			DbgPrint("InjectBySuspendResume(): OpenProcess() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}
		//���LoadLibraryA�����ĵ�ַ
		PVOID pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (pLoadLibraryA == NULL)
		{
			DbgPrint("InjectBySuspendResume():  GetProcAddress() failed!!! [%d]\n", GetLastError());
			CloseHandle(hProcess);
			return FALSE;
		}

		SIZE_T sdnLen = (strlen(pszDllName) + 1) * sizeof(char);
		//��Ŀ�����������һ���ڴ�,���ڱ��汻ע���dll��·����shellcode
		LPVOID lpDllAddr = VirtualAllocEx(hProcess, NULL, sdnLen + stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (lpDllAddr == NULL)
		{
			DbgPrint("InjectBySuspendResume(): VirtualAllocEx(#1) failed!!! [%d]\n", GetLastError());
			CloseHandle(hProcess);
			return FALSE;
		}
		//��dll������·�����Ƶ�Ŀ����̵ĵ�ַ�ռ���
		if (WriteProcessMemory(hProcess, lpDllAddr, pszDllName, sdnLen, NULL) == 0)
		{
			DbgPrint("InjectBySuspendResume(): WriteProcessMemory(#1) failed!!! [%d]\n", GetLastError());
			VirtualFreeEx(hProcess, lpDllAddr, sdnLen + stubLen, MEM_DECOMMIT);
			CloseHandle(hProcess);
			return FALSE;
		}

		//�������ҵ����̵�һ��û�б���������̣߳����û���ҵ���ѡ���һ���߳�
		HANDLE hThread = NULL;
		bool threadSelected = false;
		std::vector<DWORD> tids = path::GetAllThreadIdByProcessId(dwProcessId);
		for (DWORD tid : tids)
		{
			hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), false, tid);
			if (hThread == NULL)
			{
				DbgPrint("InjectBySuspendResume(): OpenThread(#1) failed!!! [%d] thread id is [%d]\n", GetLastError(), tid);
				VirtualFreeEx(hProcess, lpDllAddr, sdnLen + stubLen, MEM_DECOMMIT);
				CloseHandle(hProcess);
				return FALSE;
			}
			////����̵߳�״̬
			//DWORD exitcode = 0;
			//GetExitCodeThread(hThread,&exitcode);//�������1��״̬��0x103˵������ͣ��

			//�����߳�
			int suspendCount = SuspendThread(hThread);
			if (suspendCount == -1)//����ʧ��
			{
				CloseHandle(hThread);
				continue;
			}
			else if (suspendCount == 0)//����ǰ��ǰ�߳��������У�ʹ������߳�

			{
				threadSelected = true;
				break;
			}
			else
			{
				ResumeThread(hThread);//��ǰ�߳�֮ǰ���������Ӧ���ָ�����
				CloseHandle(hThread);
				continue;
			}
		}
		if (!threadSelected)//���û��ѡ����Ч���̣߳���ѡ���һ���߳�
		{
			hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), false, tids[0]);
			if (hThread == NULL)
			{
				DbgPrint("InjectBySuspendResume(): OpenThread(#2) failed!!! [%d] thread id is [%d]\n", GetLastError(), tids[0]);
				VirtualFreeEx(hProcess, lpDllAddr, sdnLen + stubLen, MEM_DECOMMIT);
				CloseHandle(hProcess);
				return FALSE;
			}
		}

#ifdef _WIN64

		//����̵߳�������
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		//�����̵߳�������
		DWORD64 oldIP = ctx.Rip;
		ctx.Rip = (DWORD64)lpDllAddr + sdnLen;
		ctx.ContextFlags = CONTEXT_CONTROL;
		//����shellcode�е�����
		memcpy(sc + 3, &oldIP, 8);//����Ϊ�ϴι���ʱ�ĵ�ַ
		memcpy(sc + 41, &lpDllAddr, 8);//����Ϊ����dll·���ĵ�ַ
		memcpy(sc + 51, &pLoadLibraryA, 8);//����ΪLoadLibrary�����ĵ�ַ

#else
		//����̵߳�������
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		//�����̵߳�������
		DWORD oldIP = ctx.Eip;
		ctx.Eip = (DWORD)lpDllAddr + sdnLen;
		ctx.ContextFlags = CONTEXT_CONTROL;
		//����shellcode�е�����
		memcpy(sc + 1, &oldIP, 4);//����Ϊ�ϴι���ʱ�ĵ�ַ
		memcpy(sc + 8, &lpDllAddr, 4);//����Ϊ����dll·���ĵ�ַ
		memcpy(sc + 13, &pLoadLibraryA, 4);//����ΪLoadLibrary�����ĵ�ַ

#endif
	//��ShellCodeд��Ŀ����̵ĵ�ַ�ռ���
		if (WriteProcessMemory(hProcess, (void *)((size_t)lpDllAddr + sdnLen), &sc, stubLen, NULL) == 0)
		{
			DbgPrint("InjectBySuspendResume(): WriteProcessMemory(#2) failed!!! [%d]\n", GetLastError());
			CloseHandle(hThread);
			VirtualFreeEx(hProcess, lpDllAddr, sdnLen + stubLen, MEM_DECOMMIT);
			CloseHandle(hProcess);
			return FALSE;
		}
		//�����̵߳������Ĳ��ָ��߳�����
		SetThreadContext(hThread, &ctx);
		ResumeThread(hThread);

		if (hThread)CloseHandle(hThread);
		if (hProcess)CloseHandle(hProcess);
		return TRUE;
	}


	DWORD InjectByRtlCreateUserThread(DWORD dwProcessId, PCSTR pszDllName)
	{

		typedef DWORD(WINAPI * PFRtlCreateUserThread)(
			IN HANDLE 					ProcessHandle,
			IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
			IN BOOL 					CreateSuspended,
			IN ULONG					StackZeroBits,
			IN OUT PULONG				StackReserved,
			IN OUT PULONG				StackCommit,
			IN LPVOID					StartAddress,
			IN LPVOID					StartParameter,
			OUT HANDLE 					ThreadHandle,
			OUT LPVOID					ClientID
			);

		PFRtlCreateUserThread pRtlCreateUserThread = NULL;
		HANDLE  hRemoteThread = NULL;

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			DbgPrint("[-] Error: Could not open process for PID (%d).\n", dwProcessId);
			return FALSE;
		}

		LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (LoadLibraryAddress == NULL)
		{
			DbgPrint("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
			return FALSE;
		}

		pRtlCreateUserThread = (PFRtlCreateUserThread)(LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
		if (pRtlCreateUserThread == NULL)
		{
			DbgPrint("[-] Error: Could not find RtlCreateUserThread function inside ntdll.dll library.\n");
			return FALSE;
		}

		DWORD dwSize = (DWORD)((strlen(pszDllName) + 1) * sizeof(wchar_t));

		LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpBaseAddress == NULL)
		{
			DbgPrint("[-] Error: Could not allocate memory inside PID (%d).\n", dwProcessId);
			return FALSE;
		}

		BOOL bStatus = WriteProcessMemory(hProcess, lpBaseAddress, pszDllName, dwSize, NULL);
		if (bStatus == 0)
		{
			DbgPrint("[-] Error: Could not write any bytes into the PID (%d) address space.\n", dwProcessId);
			return FALSE;
		}

		bStatus = (BOOL)pRtlCreateUserThread(
			hProcess,							//Ŀ����̾��
			NULL,
			0,
			0,
			0,
			0,
			LoadLibraryAddress,
			lpBaseAddress,
			&hRemoteThread,
			NULL);
		if (bStatus < 0)
		{
			DbgPrint("[-] Error: RtlCreateUserThread failed\n");
			return FALSE;
		}
		else
		{
			DbgPrint("[+] Remote thread has been created successfully ...\n");
			WaitForSingleObject(hRemoteThread, INFINITE);

			CloseHandle(hProcess);
			VirtualFreeEx(hProcess, lpBaseAddress, dwSize, MEM_RELEASE);
			return TRUE;
		}

		return TRUE;
	}
}

namespace hook
{
	void Detours_HookInit()
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
	}

	BOOL Detours_Hook(PVOID *oldFunAddr, PVOID newFunAddr)
	{
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)*oldFunAddr, newFunAddr);
		if (DetourTransactionCommit() == 0)return FALSE;
		return TRUE;
	}

	BOOL Detours_UnHook(PVOID *oldFunAddr, PVOID newFunAddr)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)*oldFunAddr, newFunAddr);
		if (DetourTransactionCommit() == 0)return TRUE;
		return FALSE;
	}


	BOOL MinHook_Init()
	{
		if (MH_Initialize() != MH_STATUS::MH_OK)
		{
			DbgPrint("%d:%s->%s", __LINE__, __FUNCTION__, "MH_Initialize failed!");
			return FALSE;
		}
		return TRUE;
	}

	BOOL MinHook_Hook(PVOID oldFunOriginalAddr, PVOID &oldFunNewAddr, PVOID detourFunAddr)
	{
		if (MH_CreateHook(oldFunOriginalAddr, detourFunAddr, reinterpret_cast<LPVOID*>((&oldFunNewAddr))) != MH_OK)
		{
			DbgPrint("%d:%s->%s", __LINE__, __FUNCTION__, "MH_CreateHook failed!");
			return FALSE;
		}
		if (MH_EnableHook(oldFunOriginalAddr) != MH_OK)
		{
			DbgPrint("%d:%s->%s", __LINE__, __FUNCTION__, "MH_EnableHook failed!");
			return FALSE;
		}
		return TRUE;
	}

	BOOL MinHook_UnHook(PVOID oldFunOriginalAddr)
	{
		if (MH_DisableHook(oldFunOriginalAddr) != MH_OK)
		{
			DbgPrint("%d:%s->%s", __LINE__, __FUNCTION__, "MH_DisableHook failed!");
			return FALSE;
		}
		return TRUE;
	}
}

namespace crypt
{
	CryptoPP::RandomPool & GlobalRNG();


	BOOL AES_GenerateKey(BYTE *pAESKey, DWORD dwBufferSize, DWORD &dwAESKeyLength)
	{
		srand((UINT)time(NULL));

		if (CryptoPP::AES::MIN_KEYLENGTH > dwAESKeyLength)
		{
			dwAESKeyLength = CryptoPP::AES::MIN_KEYLENGTH;
		}
		else if (CryptoPP::AES::MAX_KEYLENGTH < dwAESKeyLength)
		{
			dwAESKeyLength = CryptoPP::AES::MAX_KEYLENGTH;
		}


		// ��Կ���ȴ��ڻ�����
		if (dwBufferSize < dwAESKeyLength)
		{
			return FALSE;
		}

		// ���������Կ(��Сд��ĸ�����֡��ַ��ȿ���ʾ�ַ�)
		// 33 - 126
		int i = 0;
		RtlZeroMemory(pAESKey, dwBufferSize);
		for (DWORD i = 0; i < dwAESKeyLength; i++)
		{
			pAESKey[i] = 33 + (rand() % 94);
		}

		return TRUE;
	}

	BOOL AES_Encrypt(BYTE *pOriginalData, DWORD dwOriginalDataSize, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppEncryptData, DWORD *pdwEncryptData)
	{
		// ������
		CryptoPP::AESEncryption aesEncryptor;
		// ����ԭ�����ݿ�
		unsigned char inBlock[CryptoPP::AES::BLOCKSIZE];
		// ���ܺ��������ݿ�
		unsigned char outBlock[CryptoPP::AES::BLOCKSIZE];
		// �����趨ȫΪ0
		unsigned char xorBlock[CryptoPP::AES::BLOCKSIZE];

		DWORD dwOffset = 0;
		BYTE *pEncryptData = NULL;
		DWORD dwEncryptDataSize = 0;

		// ����ԭ�ĳ���, ���� 128λ �� 16�ֽ� ����, ������ ���0 ����
		// ��
		DWORD dwQuotient = dwOriginalDataSize / CryptoPP::AES::BLOCKSIZE;
		// ����
		DWORD dwRemaind = dwOriginalDataSize % CryptoPP::AES::BLOCKSIZE;
		if (0 != dwRemaind)
		{
			dwQuotient++;
		}

		// ���붯̬�ڴ�
		dwEncryptDataSize = dwQuotient * CryptoPP::AES::BLOCKSIZE;
		pEncryptData = new BYTE[dwEncryptDataSize];
		if (NULL == pEncryptData)
		{
			return FALSE;
		}

		// ������Կ
		aesEncryptor.SetKey(pAESKey, dwAESKeySize);

		do
		{
			// ����
			RtlZeroMemory(inBlock, CryptoPP::AES::BLOCKSIZE);
			RtlZeroMemory(xorBlock, CryptoPP::AES::BLOCKSIZE);
			RtlZeroMemory(outBlock, CryptoPP::AES::BLOCKSIZE);

			// ��ȡ���ܿ�
			if (dwOffset <= (dwOriginalDataSize - CryptoPP::AES::BLOCKSIZE))
			{
				RtlCopyMemory(inBlock, (PVOID)(pOriginalData + dwOffset), CryptoPP::AES::BLOCKSIZE);
			}
			else
			{
				RtlCopyMemory(inBlock, (PVOID)(pOriginalData + dwOffset), (dwOriginalDataSize - dwOffset));
			}

			// ����
			aesEncryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);

			// ����
			RtlCopyMemory((PVOID)(pEncryptData + dwOffset), outBlock, CryptoPP::AES::BLOCKSIZE);

			// ��������
			dwOffset = dwOffset + CryptoPP::AES::BLOCKSIZE;
			dwQuotient--;
		} while (0 < dwQuotient);

		// ��������
		*ppEncryptData = pEncryptData;
		*pdwEncryptData = dwEncryptDataSize;

		return TRUE;
	}

	BOOL AES_Decrypt(BYTE *pEncryptData, DWORD dwEncryptData, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppDecryptData, DWORD *pdwDecryptData)
	{
		// ������
		CryptoPP::AESDecryption aesDecryptor;
		// �����������ݿ�
		unsigned char inBlock[CryptoPP::AES::BLOCKSIZE];
		// ���ܺ���������ݿ�
		unsigned char outBlock[CryptoPP::AES::BLOCKSIZE];
		// �����趨ȫΪ0
		unsigned char xorBlock[CryptoPP::AES::BLOCKSIZE];
		DWORD dwOffset = 0;
		BYTE *pDecryptData = NULL;
		DWORD dwDecryptDataSize = 0;

		// �������ĳ���, ���� 128λ �� 16�ֽ� ����, ���������0����
		// ��
		DWORD dwQuotient = dwEncryptData / CryptoPP::AES::BLOCKSIZE;
		// ����
		DWORD dwRemaind = dwEncryptData % CryptoPP::AES::BLOCKSIZE;
		if (0 != dwRemaind)
		{
			dwQuotient++;
		}

		// ���붯̬�ڴ�
		dwDecryptDataSize = dwQuotient * CryptoPP::AES::BLOCKSIZE;
		pDecryptData = new BYTE[dwDecryptDataSize];
		if (NULL == pDecryptData)
		{
			return FALSE;
		}

		// ������Կ
		aesDecryptor.SetKey(pAESKey, dwAESKeySize);

		do
		{
			// ����
			RtlZeroMemory(inBlock, CryptoPP::AES::BLOCKSIZE);
			RtlZeroMemory(xorBlock, CryptoPP::AES::BLOCKSIZE);
			RtlZeroMemory(outBlock, CryptoPP::AES::BLOCKSIZE);

			// ��ȡ���ܿ�
			if (dwOffset <= (dwDecryptDataSize - CryptoPP::AES::BLOCKSIZE))
			{
				RtlCopyMemory(inBlock, (PVOID)(pEncryptData + dwOffset), CryptoPP::AES::BLOCKSIZE);
			}
			else
			{
				RtlCopyMemory(inBlock, (PVOID)(pEncryptData + dwOffset), (dwEncryptData - dwOffset));
			}

			// ����
			aesDecryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);

			// ����
			RtlCopyMemory((PVOID)(pDecryptData + dwOffset), outBlock, CryptoPP::AES::BLOCKSIZE);

			// ��������
			dwOffset = dwOffset + CryptoPP::AES::BLOCKSIZE;
			dwQuotient--;
		} while (0 < dwQuotient);

		// ��������
		*ppDecryptData = pDecryptData;
		*pdwDecryptData = dwDecryptDataSize;

		return TRUE;
	}

	std::string MD5_File(const char *pszFileName)
	{
		std::string value;
		CryptoPP::Weak::MD5 md5;
		CryptoPP::FileSource(pszFileName, true, new CryptoPP::HashFilter(md5, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string MD5_Bytes(PBYTE pData, DWORD dwDataSize)
	{
		std::string value;
		CryptoPP::Weak::MD5 md5;
		CryptoPP::StringSource(pData, dwDataSize, true, new CryptoPP::HashFilter(md5, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string SHA1_File(const char *pszFileName)
	{
		std::string value;
		CryptoPP::SHA1 sha1;
		CryptoPP::FileSource(pszFileName, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string SHA1_Bytes(PBYTE pData, DWORD dwDataSize)
	{
		std::string value;
		CryptoPP::SHA1 sha1;
		CryptoPP::StringSource(pData, dwDataSize, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string SHA256_File(const char *pszFileName)
	{
		std::string value;
		CryptoPP::SHA256 sha256;
		CryptoPP::FileSource(pszFileName, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string SHA256_Bytes(PBYTE pData, DWORD dwDataSize)
	{
		std::string value;
		CryptoPP::SHA256 sha256;
		CryptoPP::StringSource(pData, dwDataSize, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string CRC32_File(const char *pszFileName)
	{
		std::string value;
		CryptoPP::CRC32 crc32;
		CryptoPP::FileSource(pszFileName, true, new CryptoPP::HashFilter(crc32, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	std::string CRC32_Bytes(PBYTE pData, DWORD dwDataSize)
	{
		std::string value;
		CryptoPP::CRC32 crc32;
		CryptoPP::StringSource(pData, dwDataSize, true, new CryptoPP::HashFilter(crc32, new CryptoPP::HexEncoder(new CryptoPP::StringSink(value))));
		return value;
	}

	BOOL RSA_GenerateKey(DWORD dwRSAKeyLength, const char *pszPrivateKeyFileName, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength)
	{
		CryptoPP::RandomPool randPool;
		randPool.GenerateBlock(pSeed, dwSeedLength);//������������ӳ�ʼ��һ��α�����������

		// ����RSA˽Կ
		CryptoPP::RSAES_OAEP_SHA_Decryptor priv(randPool, dwRSAKeyLength);
		CryptoPP::HexEncoder privFile(new CryptoPP::FileSink(pszPrivateKeyFileName));	// ���ļ�ʵ�����л�����

		priv.GetPrivateKey().Save(privFile);
		privFile.MessageEnd();

		// ����RSA��Կ
		CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
		CryptoPP::HexEncoder pubFile(new CryptoPP::FileSink(pszPublicKeyFileName));		// ���ļ�ʵ�����л�����

		pub.GetPublicKey().Save(pubFile);							// д�������pub���ļ�����pubFile��
		pubFile.MessageEnd();

		return TRUE;
	}

	CryptoPP::RandomPool & GlobalRNG()
	{
		static CryptoPP::RandomPool randomPool;

		return randomPool;
	}

	std::string RSA_Encrypt_ByFile(const char *pszOriginaString, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength)
	{
		CryptoPP::RandomPool randPool;
		randPool.GenerateBlock(pSeed, dwSeedLength);

		CryptoPP::FileSource pubFile(pszPublicKeyFileName, TRUE, new CryptoPP::HexDecoder);
		CryptoPP::RSAES_OAEP_SHA_Encryptor pub(pubFile);

		// ����
		std::string strEncryptString;
		CryptoPP::StringSource(pszOriginaString, TRUE, new CryptoPP::PK_EncryptorFilter(randPool, pub, new CryptoPP::HexEncoder(new CryptoPP::StringSink(strEncryptString))));

		return strEncryptString;
	}

	std::string RSA_Decrypt_ByFile(const char *pszEncryptString, const char *pszPrivateKeyFileName)
	{
		CryptoPP::FileSource privFile(pszPrivateKeyFileName, TRUE, new CryptoPP::HexDecoder);
		CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privFile);

		std::string strDecryptString;
		CryptoPP::StringSource(pszEncryptString, TRUE, new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv, new CryptoPP::StringSink(strDecryptString))));

		return strDecryptString;
	}

	std::string RSA_Encrypt_ByMem(const char *pszOriginaString, const char *pszMemPublicKey, BYTE *pSeed, DWORD dwSeedLength)
	{
		CryptoPP::RandomPool randPool;
		randPool.GenerateBlock(pSeed, dwSeedLength);
		CryptoPP::StringSource pubStr(pszMemPublicKey, TRUE, new CryptoPP::HexDecoder);
		CryptoPP::RSAES_OAEP_SHA_Encryptor pub(pubStr);

		std::string strEncryptString;
		CryptoPP::StringSource(pszOriginaString, TRUE, new CryptoPP::PK_EncryptorFilter(randPool, pub, new CryptoPP::HexEncoder(new CryptoPP::StringSink(strEncryptString))));

		return strEncryptString;
	}

	std::string RSA_Decrypt_ByMem(const char *pszEncryptString, const char *pszMemPrivateKey)
	{
		CryptoPP::StringSource privStr(pszMemPrivateKey, TRUE, new CryptoPP::HexDecoder);
		CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privStr);

		std::string strDecryptString;
		CryptoPP::StringSource(pszEncryptString, TRUE, new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv, new CryptoPP::StringSink(strDecryptString))));

		return strDecryptString;
	}
}

namespace mm
{

#if _MSC_VER
#pragma warning(disable:4996)
	// Disable warning about data -> function pointer conversion
#pragma warning(disable:4055)
 // C4244: conversion from 'uintptr_t' to 'DWORD', possible loss of data.
#pragma warning(error: 4244)
// C4267: conversion from 'size_t' to 'int', possible loss of data.
#pragma warning(error: 4267)

#define inline __inline
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

	struct ExportNameEntry {
		LPCSTR name;
		WORD idx;
	};

	typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
	typedef int (WINAPI *ExeEntryProc)(void);

#ifdef _WIN64
	typedef struct POINTER_LIST {
		struct POINTER_LIST *next;
		void *address;
} POINTER_LIST;
#endif

	typedef struct {
		PIMAGE_NT_HEADERS headers;
		unsigned char *codeBase;
		HCUSTOMMODULE *modules;
		int numModules;
		BOOL initialized;
		BOOL isDLL;
		BOOL isRelocated;
		CustomAllocFunc alloc;
		CustomFreeFunc free;
		CustomLoadLibraryFunc loadLibrary;
		CustomGetProcAddressFunc getProcAddress;
		CustomFreeLibraryFunc freeLibrary;
		struct ExportNameEntry *nameExportsTable;
		void *userdata;
		ExeEntryProc exeEntry;
		DWORD pageSize;
#ifdef _WIN64
		POINTER_LIST *blockedMemory;
#endif
	} MEMORYMODULE, *PMEMORYMODULE;

	typedef struct {
		LPVOID address;
		LPVOID alignedAddress;
		SIZE_T size;
		DWORD characteristics;
		BOOL last;
	} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]

	static inline uintptr_t
		AlignValueDown(uintptr_t value, uintptr_t alignment) {
		return value & ~(alignment - 1);
	}

	static inline LPVOID
		AlignAddressDown(LPVOID address, uintptr_t alignment) {
		return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
	}

	static inline size_t
		AlignValueUp(size_t value, size_t alignment) {
		return (value + alignment - 1) & ~(alignment - 1);
	}

	static inline void*
		OffsetPointer(void* data, ptrdiff_t offset) {
		return (void*)((uintptr_t)data + offset);
	}

#ifdef _WIN64
	static void
		FreePointerList(POINTER_LIST *head, CustomFreeFunc freeMemory, void *userdata)
	{
		POINTER_LIST *node = head;
		while (node) {
			POINTER_LIST *next;
			freeMemory(node->address, 0, MEM_RELEASE, userdata);
			next = node->next;
			free(node);
			node = next;
		}
	}
#endif

	static BOOL
		CheckSize(size_t size, size_t expected) {
		if (size < expected) {
			SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}

		return TRUE;
	}

	static BOOL
		CopySections(const unsigned char *data, size_t size, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
	{
		int i, section_size;
		unsigned char *codeBase = module->codeBase;
		unsigned char *dest;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
		for (i = 0; i < module->headers->FileHeader.NumberOfSections; i++, section++) {
			if (section->SizeOfRawData == 0) {
				// section doesn't contain data in the dll itself, but may define
				// uninitialized data
				section_size = old_headers->OptionalHeader.SectionAlignment;
				if (section_size > 0) {
					dest = (unsigned char *)module->alloc(codeBase + section->VirtualAddress,
						section_size,
						MEM_COMMIT,
						PAGE_READWRITE,
						module->userdata);
					if (dest == NULL) {
						return FALSE;
					}

					// Always use position from file to support alignments smaller
					// than page size (allocation above will align to page size).
					dest = codeBase + section->VirtualAddress;
					// NOTE: On 64bit systems we truncate to 32bit here but expand
					// again later when "PhysicalAddress" is used.
					section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
					memset(dest, 0, section_size);
				}

				// section is empty
				continue;
			}

			if (!CheckSize(size, section->PointerToRawData + section->SizeOfRawData)) {
				return FALSE;
			}

			// commit memory block and copy data from dll
			dest = (unsigned char *)module->alloc(codeBase + section->VirtualAddress,
				section->SizeOfRawData,
				MEM_COMMIT,
				PAGE_READWRITE,
				module->userdata);
			if (dest == NULL) {
				return FALSE;
			}

			// Always use position from file to support alignments smaller
			// than page size (allocation above will align to page size).
			dest = codeBase + section->VirtualAddress;
			memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
			// NOTE: On 64bit systems we truncate to 32bit here but expand
			// again later when "PhysicalAddress" is used.
			section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
		}

		return TRUE;
	}

	// Protection flags for memory pages (Executable, Readable, Writeable)
	static int ProtectionFlags[2][2][2] = {
		{
			// not executable
			{PAGE_NOACCESS, PAGE_WRITECOPY},
			{PAGE_READONLY, PAGE_READWRITE},
		}, {
			// executable
			{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
			{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
		},
	};

	static SIZE_T
		GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
		DWORD size = section->SizeOfRawData;
		if (size == 0) {
			if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
				size = module->headers->OptionalHeader.SizeOfInitializedData;
			}
			else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
				size = module->headers->OptionalHeader.SizeOfUninitializedData;
			}
		}
		return (SIZE_T)size;
	}

	static BOOL
		FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
		DWORD protect, oldProtect;
		BOOL executable;
		BOOL readable;
		BOOL writeable;

		if (sectionData->size == 0) {
			return TRUE;
		}

		if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			// section is not needed any more and can safely be freed
			if (sectionData->address == sectionData->alignedAddress &&
				(sectionData->last ||
					module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
					(sectionData->size % module->pageSize) == 0)
				) {
				// Only allowed to decommit whole pages
				module->free(sectionData->address, sectionData->size, MEM_DECOMMIT, module->userdata);
			}
			return TRUE;
		}

		// determine protection flags based on characteristics
		executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
		writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		protect = ProtectionFlags[executable][readable][writeable];
		if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			protect |= PAGE_NOCACHE;
		}

		// change memory access flags
		if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
			DbgPrint("FinalizeSection() : VirtualProtect() failed!!! [%d]", GetLastError());
			return FALSE;
		}

		return TRUE;
	}

	static BOOL
		FinalizeSections(PMEMORYMODULE module)
	{
		int i;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
		// "PhysicalAddress" might have been truncated to 32bit above, expand to
		// 64bits again.
		uintptr_t imageOffset = ((uintptr_t)module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
		static const uintptr_t imageOffset = 0;
#endif
		SECTIONFINALIZEDATA sectionData;
		sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
		sectionData.size = GetRealSectionSize(module, section);
		sectionData.characteristics = section->Characteristics;
		sectionData.last = FALSE;
		section++;

		// loop through all sections and change access flags
		for (i = 1; i < module->headers->FileHeader.NumberOfSections; i++, section++) {
			LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
			LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
			SIZE_T sectionSize = GetRealSectionSize(module, section);
			// Combine access flags of all sections that share a page
			// TODO(fancycode): We currently share flags of a trailing large section
			//   with the page of a first small section. This should be optimized.
			if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
				// Section shares page with previous
				if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
					sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
				}
				else {
					sectionData.characteristics |= section->Characteristics;
				}
				sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
				continue;
			}

			if (!FinalizeSection(module, &sectionData)) {
				return FALSE;
			}
			sectionData.address = sectionAddress;
			sectionData.alignedAddress = alignedAddress;
			sectionData.size = sectionSize;
			sectionData.characteristics = section->Characteristics;
		}
		sectionData.last = TRUE;
		if (!FinalizeSection(module, &sectionData)) {
			return FALSE;
		}
		return TRUE;
	}

	static BOOL
		ExecuteTLS(PMEMORYMODULE module)
	{
		unsigned char *codeBase = module->codeBase;
		PIMAGE_TLS_DIRECTORY tls;
		PIMAGE_TLS_CALLBACK* callback;

		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
		if (directory->VirtualAddress == 0) {
			return TRUE;
		}

		tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
		callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
		if (callback) {
			while (*callback) {
				(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}
		return TRUE;
	}

	static BOOL
		PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta)
	{
		unsigned char *codeBase = module->codeBase;
		PIMAGE_BASE_RELOCATION relocation;

		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		if (directory->Size == 0) {
			return (delta == 0);
		}

		relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
		for (; relocation->VirtualAddress > 0; ) {
			DWORD i;
			unsigned char *dest = codeBase + relocation->VirtualAddress;
			unsigned short *relInfo = (unsigned short*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
			for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
				// the upper 4 bits define the type of relocation
				int type = *relInfo >> 12;
				// the lower 12 bits define the offset
				int offset = *relInfo & 0xfff;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					// skip relocation
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					// change complete 32 bit address
				{
					DWORD *patchAddrHL = (DWORD *)(dest + offset);
					*patchAddrHL += (DWORD)delta;
				}
				break;

#ifdef _WIN64
				case IMAGE_REL_BASED_DIR64:
				{
					ULONGLONG *patchAddr64 = (ULONGLONG *)(dest + offset);
					*patchAddr64 += (ULONGLONG)delta;
				}
				break;
#endif

				default:
					//printf("Unknown relocation: %d\n", type);
					break;
				}
			}

			// advance to next relocation block
			relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
		}
		return TRUE;
	}

	static BOOL
		BuildImportTable(PMEMORYMODULE module)
	{
		unsigned char *codeBase = module->codeBase;
		PIMAGE_IMPORT_DESCRIPTOR importDesc;
		BOOL result = TRUE;

		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (directory->Size == 0) {
			return TRUE;
		}

		importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + directory->VirtualAddress);
		for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
			uintptr_t *thunkRef;
			FARPROC *funcRef;
			HCUSTOMMODULE *tmp;
			HCUSTOMMODULE handle = module->loadLibrary((LPCSTR)(codeBase + importDesc->Name), module->userdata);
			if (handle == NULL) {
				SetLastError(ERROR_MOD_NOT_FOUND);
				result = FALSE;
				break;
			}

			tmp = (HCUSTOMMODULE *)realloc(module->modules, (module->numModules + 1)*(sizeof(HCUSTOMMODULE)));
			if (tmp == NULL) {
				module->freeLibrary(handle, module->userdata);
				SetLastError(ERROR_OUTOFMEMORY);
				result = FALSE;
				break;
			}
			module->modules = tmp;

			module->modules[module->numModules++] = handle;
			if (importDesc->OriginalFirstThunk) {
				thunkRef = (uintptr_t *)(codeBase + importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
			}
			else {
				// no hint table
				thunkRef = (uintptr_t *)(codeBase + importDesc->FirstThunk);
				funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
			}
			for (; *thunkRef; thunkRef++, funcRef++) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
					*funcRef = module->getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef), module->userdata);
				}
				else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
					*funcRef = module->getProcAddress(handle, (LPCSTR)&thunkData->Name, module->userdata);
				}
				if (*funcRef == 0) {
					result = FALSE;
					break;
				}
			}

			if (!result) {
				module->freeLibrary(handle, module->userdata);
				SetLastError(ERROR_PROC_NOT_FOUND);
				break;
			}
		}

		return result;
	}

	LPVOID MemoryDefaultAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect, void* userdata)
	{
		UNREFERENCED_PARAMETER(userdata);
		return VirtualAlloc(address, size, allocationType, protect);
	}

	BOOL MemoryDefaultFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, void* userdata)
	{
		UNREFERENCED_PARAMETER(userdata);
		return VirtualFree(lpAddress, dwSize, dwFreeType);
	}

	HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR filename, void *userdata)
	{
		HMODULE result;
		UNREFERENCED_PARAMETER(userdata);
		result = LoadLibraryA(filename);
		if (result == NULL) {
			return NULL;
		}

		return (HCUSTOMMODULE)result;
	}

	FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE module, LPCSTR name, void *userdata)
	{
		UNREFERENCED_PARAMETER(userdata);
		return (FARPROC)GetProcAddress((HMODULE)module, name);
	}

	void MemoryDefaultFreeLibrary(HCUSTOMMODULE module, void *userdata)
	{
		UNREFERENCED_PARAMETER(userdata);
		FreeLibrary((HMODULE)module);
	}

	HMEMORYMODULE MemoryLoadLibrary(const void *data, size_t size)
	{
		return MemoryLoadLibraryEx(data, size, MemoryDefaultAlloc, MemoryDefaultFree, MemoryDefaultLoadLibrary, MemoryDefaultGetProcAddress, MemoryDefaultFreeLibrary, NULL);
	}

	HMEMORYMODULE MemoryLoadLibraryEx(const void *data, size_t size,
		CustomAllocFunc allocMemory,
		CustomFreeFunc freeMemory,
		CustomLoadLibraryFunc loadLibrary,
		CustomGetProcAddressFunc getProcAddress,
		CustomFreeLibraryFunc freeLibrary,
		void *userdata)
	{
		PMEMORYMODULE result = NULL;
		PIMAGE_DOS_HEADER dos_header;
		PIMAGE_NT_HEADERS old_header;
		unsigned char *code, *headers;
		ptrdiff_t locationDelta;
		SYSTEM_INFO sysInfo;
		PIMAGE_SECTION_HEADER section;
		DWORD i;
		size_t optionalSectionSize;
		size_t lastSectionEnd = 0;
		size_t alignedImageSize;
#ifdef _WIN64
		POINTER_LIST *blockedMemory = NULL;
#endif

		if (!CheckSize(size, sizeof(IMAGE_DOS_HEADER))) {
			return NULL;
		}
		dos_header = (PIMAGE_DOS_HEADER)data;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		if (!CheckSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) {
			return NULL;
		}
		old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
		if (old_header->Signature != IMAGE_NT_SIGNATURE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		if (old_header->FileHeader.Machine != HOST_MACHINE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		if (old_header->OptionalHeader.SectionAlignment & 1) {
			// Only support section alignments that are a multiple of 2
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		section = IMAGE_FIRST_SECTION(old_header);
		optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
		for (i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) {
			size_t endOfSection;
			if (section->SizeOfRawData == 0) {
				// Section without data in the DLL
				endOfSection = section->VirtualAddress + optionalSectionSize;
			}
			else {
				endOfSection = section->VirtualAddress + section->SizeOfRawData;
			}

			if (endOfSection > lastSectionEnd) {
				lastSectionEnd = endOfSection;
			}
		}

		GetNativeSystemInfo(&sysInfo);
		alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
		if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		// reserve memory for image of library
		// XXX: is it correct to commit the complete memory region at once?
		//      calling DllEntry raises an exception if we don't...
		code = (unsigned char *)allocMemory((LPVOID)(old_header->OptionalHeader.ImageBase),
			alignedImageSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE,
			userdata);

		if (code == NULL) {
			// try to allocate memory at arbitrary position
			code = (unsigned char *)allocMemory(NULL,
				alignedImageSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE,
				userdata);
			if (code == NULL) {
				SetLastError(ERROR_OUTOFMEMORY);
				return NULL;
			}
		}

#ifdef _WIN64
		// Memory block may not span 4 GB boundaries.
		while ((((uintptr_t)code) >> 32) < (((uintptr_t)(code + alignedImageSize)) >> 32)) {
			POINTER_LIST *node = (POINTER_LIST*)malloc(sizeof(POINTER_LIST));
			if (!node) {
				freeMemory(code, 0, MEM_RELEASE, userdata);
				FreePointerList(blockedMemory, freeMemory, userdata);
				SetLastError(ERROR_OUTOFMEMORY);
				return NULL;
			}

			node->next = blockedMemory;
			node->address = code;
			blockedMemory = node;

			code = (unsigned char *)allocMemory(NULL,
				alignedImageSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE,
				userdata);
			if (code == NULL) {
				FreePointerList(blockedMemory, freeMemory, userdata);
				SetLastError(ERROR_OUTOFMEMORY);
				return NULL;
			}
	}
#endif

		result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
		if (result == NULL) {
			freeMemory(code, 0, MEM_RELEASE, userdata);
#ifdef _WIN64
			FreePointerList(blockedMemory, freeMemory, userdata);
#endif
			SetLastError(ERROR_OUTOFMEMORY);
			return NULL;
		}

		result->codeBase = code;
		result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
		result->alloc = allocMemory;
		result->free = freeMemory;
		result->loadLibrary = loadLibrary;
		result->getProcAddress = getProcAddress;
		result->freeLibrary = freeLibrary;
		result->userdata = userdata;
		result->pageSize = sysInfo.dwPageSize;
#ifdef _WIN64
		result->blockedMemory = blockedMemory;
#endif

		if (!CheckSize(size, old_header->OptionalHeader.SizeOfHeaders)) {
			goto error;
		}

		// commit memory for headers
		headers = (unsigned char *)allocMemory(code,
			old_header->OptionalHeader.SizeOfHeaders,
			MEM_COMMIT,
			PAGE_READWRITE,
			userdata);

		// copy PE header to code
		memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);
		result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];

		// update position
		result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

		// copy sections from DLL file block to new memory location
		if (!CopySections((const unsigned char *)data, size, old_header, result)) {
			goto error;
		}

		// adjust base address of imported data
		locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase);
		if (locationDelta != 0) {
			result->isRelocated = PerformBaseRelocation(result, locationDelta);
		}
		else {
			result->isRelocated = TRUE;
		}

		// load required dlls and adjust function table of imports
		if (!BuildImportTable(result)) {
			goto error;
		}

		// mark memory pages depending on section headers and release
		// sections that are marked as "discardable"
		if (!FinalizeSections(result)) {
			goto error;
		}

		// TLS callbacks are executed BEFORE the main loading
		if (!ExecuteTLS(result)) {
			goto error;
		}

		// get entry point of loaded library
		if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
			if (result->isDLL) {
				DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
				// notify library about attaching to process
				BOOL successfull = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
				if (!successfull) {
					SetLastError(ERROR_DLL_INIT_FAILED);
					goto error;
				}
				result->initialized = TRUE;
			}
			else {
				result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
			}
		}
		else {
			result->exeEntry = NULL;
		}

		return (HMEMORYMODULE)result;

	error:
		// cleanup
		MemoryFreeLibrary(result);
		return NULL;
	}

	static int _compare(const void *a, const void *b)
	{
		const struct ExportNameEntry *p1 = (const struct ExportNameEntry*) a;
		const struct ExportNameEntry *p2 = (const struct ExportNameEntry*) b;
		return strcmp(p1->name, p2->name);
	}

	static int _find(const void *a, const void *b)
	{
		LPCSTR *name = (LPCSTR *)a;
		const struct ExportNameEntry *p = (const struct ExportNameEntry*) b;
		return strcmp(*name, p->name);
	}

	FARPROC MemoryGetProcAddress(HMEMORYMODULE mod, LPCSTR name)
	{
		PMEMORYMODULE module = (PMEMORYMODULE)mod;
		unsigned char *codeBase = module->codeBase;
		DWORD idx = 0;
		PIMAGE_EXPORT_DIRECTORY exports;
		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (directory->Size == 0) {
			// no export table found
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		exports = (PIMAGE_EXPORT_DIRECTORY)(codeBase + directory->VirtualAddress);
		if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
			// DLL doesn't export anything
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		if (HIWORD(name) == 0) {
			// load function by ordinal value
			if (LOWORD(name) < exports->Base) {
				SetLastError(ERROR_PROC_NOT_FOUND);
				return NULL;
			}

			idx = LOWORD(name) - exports->Base;
		}
		else if (!exports->NumberOfNames) {
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}
		else {
			const struct ExportNameEntry *found;

			// Lazily build name table and sort it by names
			if (!module->nameExportsTable) {
				DWORD i;
				DWORD *nameRef = (DWORD *)(codeBase + exports->AddressOfNames);
				WORD *ordinal = (WORD *)(codeBase + exports->AddressOfNameOrdinals);
				struct ExportNameEntry *entry = (struct ExportNameEntry*) malloc(exports->NumberOfNames * sizeof(struct ExportNameEntry));
				module->nameExportsTable = entry;
				if (!entry) {
					SetLastError(ERROR_OUTOFMEMORY);
					return NULL;
				}
				for (i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++, entry++) {
					entry->name = (const char *)(codeBase + (*nameRef));
					entry->idx = *ordinal;
				}
				qsort(module->nameExportsTable,
					exports->NumberOfNames,
					sizeof(struct ExportNameEntry), _compare);
			}

			// search function name in list of exported names with binary search
			found = (const struct ExportNameEntry*) bsearch(&name,
				module->nameExportsTable,
				exports->NumberOfNames,
				sizeof(struct ExportNameEntry), _find);
			if (!found) {
				// exported symbol not found
				SetLastError(ERROR_PROC_NOT_FOUND);
				return NULL;
			}

			idx = found->idx;
		}

		if (idx > exports->NumberOfFunctions) {
			// name <-> ordinal number don't match
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		// AddressOfFunctions contains the RVAs to the "real" functions
		return (FARPROC)(LPVOID)(codeBase + (*(DWORD *)(codeBase + exports->AddressOfFunctions + (idx * 4))));
	}

	void MemoryFreeLibrary(HMEMORYMODULE mod)
	{
		PMEMORYMODULE module = (PMEMORYMODULE)mod;

		if (module == NULL) {
			return;
		}
		if (module->initialized) {
			// notify library about detaching from process
			DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
			(*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
		}

		free(module->nameExportsTable);
		if (module->modules != NULL) {
			// free previously opened libraries
			int i;
			for (i = 0; i < module->numModules; i++) {
				if (module->modules[i] != NULL) {
					module->freeLibrary(module->modules[i], module->userdata);
				}
			}

			free(module->modules);
		}

		if (module->codeBase != NULL) {
			// release memory of library
			module->free(module->codeBase, 0, MEM_RELEASE, module->userdata);
		}

#ifdef _WIN64
		FreePointerList(module->blockedMemory, module->free, module->userdata);
#endif
		HeapFree(GetProcessHeap(), 0, module);
	}

	int MemoryCallEntryPoint(HMEMORYMODULE mod)
	{
		PMEMORYMODULE module = (PMEMORYMODULE)mod;

		if (module == NULL || module->isDLL || module->exeEntry == NULL || !module->isRelocated) {
			return -1;
		}

		return module->exeEntry();
	}

#define DEFAULT_LANGUAGE        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)

	HMEMORYRSRC MemoryFindResource(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type)
	{
		return MemoryFindResourceEx(module, name, type, DEFAULT_LANGUAGE);
	}

	static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(
		void *root,
		PIMAGE_RESOURCE_DIRECTORY resources,
		LPCTSTR key)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resources + 1);
		PIMAGE_RESOURCE_DIRECTORY_ENTRY result = NULL;
		DWORD start;
		DWORD end;
		DWORD middle;

		if (!IS_INTRESOURCE(key) && key[0] == TEXT('#')) {
			// special case: resource id given as string
			TCHAR *endpos = NULL;
			long int tmpkey = (WORD)_tcstol((TCHAR *)&key[1], &endpos, 10);
			if (tmpkey <= 0xffff && lstrlen(endpos) == 0) {
				key = MAKEINTRESOURCE(tmpkey);
			}
		}

		// entries are stored as ordered list of named entries,
		// followed by an ordered list of id entries - we can do
		// a binary search to find faster...
		if (IS_INTRESOURCE(key)) {
			WORD check = (WORD)(uintptr_t)key;
			start = resources->NumberOfNamedEntries;
			end = start + resources->NumberOfIdEntries;

			while (end > start) {
				WORD entryName;
				middle = (start + end) >> 1;
				entryName = (WORD)entries[middle].Name;
				if (check < entryName) {
					end = (end != middle ? middle : middle - 1);
				}
				else if (check > entryName) {
					start = (start != middle ? middle : middle + 1);
				}
				else {
					result = &entries[middle];
					break;
				}
			}
		}
		else {
			LPCWSTR searchKey;
			size_t searchKeyLen = _tcslen(key);
#if defined(UNICODE)
			searchKey = key;
#else
			// Resource names are always stored using 16bit characters, need to
			// convert string we search for.
#define MAX_LOCAL_KEY_LENGTH 2048
		// In most cases resource names are short, so optimize for that by
		// using a pre-allocated array.
			wchar_t _searchKeySpace[MAX_LOCAL_KEY_LENGTH + 1];
			LPWSTR _searchKey;
			if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
				size_t _searchKeySize = (searchKeyLen + 1) * sizeof(wchar_t);
				_searchKey = (LPWSTR)malloc(_searchKeySize);
				if (_searchKey == NULL) {
					SetLastError(ERROR_OUTOFMEMORY);
					return NULL;
				}
			}
			else {
				_searchKey = &_searchKeySpace[0];
			}

			mbstowcs(_searchKey, key, searchKeyLen);
			_searchKey[searchKeyLen] = 0;
			searchKey = _searchKey;
#endif
			start = 0;
			end = resources->NumberOfNamedEntries;
			while (end > start) {
				int cmp;
				PIMAGE_RESOURCE_DIR_STRING_U resourceString;
				middle = (start + end) >> 1;
				resourceString = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(root, entries[middle].Name & 0x7FFFFFFF);
				cmp = _wcsnicmp(searchKey, resourceString->NameString, resourceString->Length);
				if (cmp == 0) {
					// Handle partial match
					if (searchKeyLen > resourceString->Length) {
						cmp = 1;
					}
					else if (searchKeyLen < resourceString->Length) {
						cmp = -1;
					}
				}
				if (cmp < 0) {
					end = (middle != end ? middle : middle - 1);
				}
				else if (cmp > 0) {
					start = (middle != start ? middle : middle + 1);
				}
				else {
					result = &entries[middle];
					break;
				}
			}
#if !defined(UNICODE)
			if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
				free(_searchKey);
			}
#undef MAX_LOCAL_KEY_LENGTH
#endif
		}

		return result;
	}

	HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type, WORD language)
	{
		unsigned char *codeBase = ((PMEMORYMODULE)module)->codeBase;
		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY((PMEMORYMODULE)module, IMAGE_DIRECTORY_ENTRY_RESOURCE);
		PIMAGE_RESOURCE_DIRECTORY rootResources;
		PIMAGE_RESOURCE_DIRECTORY nameResources;
		PIMAGE_RESOURCE_DIRECTORY typeResources;
		PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
		PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
		PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;
		if (directory->Size == 0) {
			// no resource table found
			SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
			return NULL;
		}

		if (language == DEFAULT_LANGUAGE) {
			// use language from current thread
			language = LANGIDFROMLCID(GetThreadLocale());
		}

		// resources are stored as three-level tree
		// - first node is the type
		// - second node is the name
		// - third node is the language
		rootResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress);
		foundType = _MemorySearchResourceEntry(rootResources, rootResources, type);
		if (foundType == NULL) {
			SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
			return NULL;
		}

		typeResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundType->OffsetToData & 0x7fffffff));
		foundName = _MemorySearchResourceEntry(rootResources, typeResources, name);
		if (foundName == NULL) {
			SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
			return NULL;
		}

		nameResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundName->OffsetToData & 0x7fffffff));
		foundLanguage = _MemorySearchResourceEntry(rootResources, nameResources, (LPCTSTR)(uintptr_t)language);
		if (foundLanguage == NULL) {
			// requested language not found, use first available
			if (nameResources->NumberOfIdEntries == 0) {
				SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
				return NULL;
			}

			foundLanguage = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameResources + 1);
		}

		return (codeBase + directory->VirtualAddress + (foundLanguage->OffsetToData & 0x7fffffff));
	}

	DWORD MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource)
	{
		PIMAGE_RESOURCE_DATA_ENTRY entry;
		UNREFERENCED_PARAMETER(module);
		entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
		if (entry == NULL) {
			return 0;
		}

		return entry->Size;
	}

	LPVOID MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource)
	{
		unsigned char *codeBase = ((PMEMORYMODULE)module)->codeBase;
		PIMAGE_RESOURCE_DATA_ENTRY entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
		if (entry == NULL) {
			return NULL;
		}

		return codeBase + entry->OffsetToData;
	}

	int
		MemoryLoadString(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize)
	{
		return MemoryLoadStringEx(module, id, buffer, maxsize, DEFAULT_LANGUAGE);
	}

	int
		MemoryLoadStringEx(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize, WORD language)
	{
		HMEMORYRSRC resource;
		PIMAGE_RESOURCE_DIR_STRING_U data;
		DWORD size;
		if (maxsize == 0) {
			return 0;
		}

		resource = MemoryFindResourceEx(module, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING, language);
		if (resource == NULL) {
			buffer[0] = 0;
			return 0;
		}

		data = (PIMAGE_RESOURCE_DIR_STRING_U)MemoryLoadResource(module, resource);
		id = id & 0x0f;
		while (id--) {
			data = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(data, (data->Length + 1) * sizeof(WCHAR));
		}
		if (data->Length == 0) {
			SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
			buffer[0] = 0;
			return 0;
		}

		size = data->Length;
		if (size >= (DWORD)maxsize) {
			size = maxsize;
		}
		else {
			buffer[size] = 0;
		}
#if defined(UNICODE)
		wcsncpy(buffer, data->NameString, size);
#else
		wcstombs(buffer, data->NameString, size);
#endif
		return size;
		}

#ifdef TESTSUITE
#include <stdio.h>

#ifndef PRIxPTR
#ifdef _WIN64
#define PRIxPTR "I64x"
#else
#define PRIxPTR "x"
#endif
#endif

	static const uintptr_t AlignValueDownTests[][3] = {
		{16, 16, 16},
		{17, 16, 16},
		{32, 16, 32},
		{33, 16, 32},
	#ifdef _WIN64
		{0x12345678abcd1000, 0x1000, 0x12345678abcd1000},
		{0x12345678abcd101f, 0x1000, 0x12345678abcd1000},
	#endif
		{0, 0, 0},
	};

	static const uintptr_t AlignValueUpTests[][3] = {
		{16, 16, 16},
		{17, 16, 32},
		{32, 16, 32},
		{33, 16, 48},
	#ifdef _WIN64
		{0x12345678abcd1000, 0x1000, 0x12345678abcd1000},
		{0x12345678abcd101f, 0x1000, 0x12345678abcd2000},
	#endif
		{0, 0, 0},
	};

	BOOL MemoryModuleTestsuite() {
		BOOL success = TRUE;
		size_t idx;
		for (idx = 0; AlignValueDownTests[idx][0]; ++idx) {
			const uintptr_t* tests = AlignValueDownTests[idx];
			uintptr_t value = AlignValueDown(tests[0], tests[1]);
			if (value != tests[2]) {
				printf("AlignValueDown failed for 0x%" PRIxPTR "/0x%" PRIxPTR ": expected 0x%" PRIxPTR ", got 0x%" PRIxPTR "\n",
					tests[0], tests[1], tests[2], value);
				success = FALSE;
			}
		}
		for (idx = 0; AlignValueDownTests[idx][0]; ++idx) {
			const uintptr_t* tests = AlignValueUpTests[idx];
			uintptr_t value = AlignValueUp(tests[0], tests[1]);
			if (value != tests[2]) {
				printf("AlignValueUp failed for 0x%" PRIxPTR "/0x%" PRIxPTR ": expected 0x%" PRIxPTR ", got 0x%" PRIxPTR "\n",
					tests[0], tests[1], tests[2], value);
				success = FALSE;
			}
		}
		if (success) {
			printf("OK\n");
		}
		return success;
	}
#endif
}