#pragma once
/*
ע�⣺
	������x86����x64��int��long��ֻռ4�ֽ�,long longռ8�ֽ�.x64�����е�ָ�붼ռ8���ֽ�
	ʹ��WIndowes APIʱһ��Ҫʹ��windows����ĺ��������ͣ�����������x86��x64֮�������л�
���õĿ�ݼ���
	CTRL+M O,P����ȫ���۵���չ��
	CTRL+K C,U����ѡ�п�ע�ͺ�ȡ��ע��
����Ԥ�����˵����
	_WIN32�����������windows���򽫱����壬������32λ������64λ����
	_WIN64�����������64λwindows���򽫱�����
	_M_IX86��������򽫱������Ϊ32ΪӦ�ó���32bit��������
	_M_AMD64��������򱻱����64λӦ�ó���64bit AMD������ (VC2008��ǰ)��
	__FILE__�����ڵ�ǰ�����ļ��ľ���·��
	__LINE__�����ڵ�ǰ���������е�����
	_DLL�������������п�ʹ�õ���MD��MDd����ʱ���ú꽫�����塣���û������ʹ�õ���MT��MTd
	_DEBUG�����뽫����debug��Ϣ
	MIDL_PASS�����������֧��64λ����
MFC��
	ʹ�ô��ļ�ʱ������MFCӦ�ó������ʱ���صġ�LINK2005�����󣬱����lib�ļ�ֻ��Ҫ�����MFC��Ŀ->����->������->����
	����	������������͡������ض�Ĭ�Ͽ⡱��������lib�ļ����ļ���������׺�����ɣ�lib�ļ�֮���á�;��������
	���⣬debugģʽ�ĺ�releaseģʽ��Ӧ��lib�ļ�����һ����
XP����:
	��ʹ��OpenProcess��OpenThread�Ⱥ���ʱ���ʹ�õĵ�һ��������xxx_ALL_ACCESSʱ��ʧ�ܣ���Ϊ������ı�־λ��������xpϵͳ
��Ŀ�����������⣺
	����x86:
		���Ŀ¼��		$(SolutionDir)build\x86\$(Configuration)\
		�м�Ŀ¼��		$(SolutionDir)obj\x86\$(Configuration)\$(ProjectName)
	����x64
		���Ŀ¼��		$(SolutionDir)build\$(Platform)\$(Configuration)\
		�м�Ŀ¼��		$(SolutionDir)obj\$(Platform)\$(Configuration)\$(ProjectName)
	����
		����Ŀ¼��		$(OutDir)
	c/c++(���XP)
		����->��������:��
	��������
		���еĵ�����ģ������ṩ�˾�̬���ӿ�Ӧ������ʹ�þ�̬���ӿ⡣����������Σ�ʹ��dll��
		include��Ҫ�����ͷ�ļ�
		lib��Ҫ����ľ�̬���ӿ⣬�ļ����ڵ�ÿһ��lib�ļ�Ӧ����ѭlib{����}-x86/x64-v140{vs���߰汾}-����ģʽ.lib������ԭ�������ʹ��vs����ģ�������Ͳ�����ѭ
		dll��Ҫ����Ķ�̬���ӿ�
*/

#ifndef COMMON_H
#define COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN // �� Windows ͷ���ų�����ʹ�õ�����,����ͷ�ļ��ظ�����
#endif

//c++ headers
#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <list>
#include <queue>
#include <algorithm>
#include <cstring>
#include <set>
//c headers
#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <ras.h>
#include <io.h>
#include <tchar.h>
#include <atltime.h>
#include <ws2spi.h>
#pragma comment(lib,"ws2_32.lib")
#include <shlwapi.h>   
#pragma comment(lib,"shlwapi.lib") 
#include <wininet.h>
//detours for Hook
#ifdef _WIN64
#include "../user_thirdparty/detours/lib/X64/detours.h"
#pragma comment(lib,"../user_thirdparty/detours/lib/X64/detours.lib")
#else
#include "../user_thirdparty/detours/lib/X86/detours.h"
#pragma comment(lib,"../user_thirdparty/detours/lib/X86/detours.lib")
#endif

//MinHook
#include "../user_thirdparty/MinHook/include/MinHook.h"
#ifdef _DEBUG
#ifdef _WIN64
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x64-v141-mdd.lib")
#else
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x64-v141-mtd.lib")
#endif
#else
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x86-v141-mdd.lib")
#else
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x86-v141-mtd.lib")
#endif
#endif
#else
#ifdef _WIN64
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x64-v141-md.lib")
#else
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x64-v141-mt.lib")
#endif
#else
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x86-v141-md.lib")
#else
#pragma comment(lib, "../user_thirdparty/MinHook/lib/libMinHook-x86-v141-mt.lib")
#endif
#endif
#endif


//cryptlib
#include "../user_thirdparty/crypt/include/aes.h"//AES
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "../user_thirdparty/crypt/include/md5.h"//MD5
#include "../user_thirdparty/crypt/include/sha.h"//SHA1��SHA256
#include "../user_thirdparty/crypt/include/crc.h"//CRC32
#include "../user_thirdparty/crypt/include/crc.h"//CRC32
#include "../user_thirdparty/crypt/include/rsa.h"//RSA
#include "../user_thirdparty/crypt/include/randpool.h"//α�������
#include "../user_thirdparty/crypt/include/files.h"
#include "../user_thirdparty/crypt/include/hex.h"
#ifdef _DEBUG
#ifdef _WIN64
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x64-v140-mdd.lib")
#else
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x64-v140-mtd.lib")
#endif
#else
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x86-v140-mdd.lib")
#else
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x86-v140-mtd.lib")
#endif
#endif
#else
#ifdef _WIN64
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x64-v140-md.lib")
#else
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x64-v140-mt.lib")
#endif
#else
#ifdef _DLL
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x86-v140-md.lib")
#else
#pragma comment(lib, "../user_thirdparty/crypt/lib/libcrypt-x86-v140-mt.lib")
#endif
#endif
#endif

////XEDParse
//#include "../user_thirdparty/XEDParse/include/XEDParse.h"
//#ifdef _DEBUG
//#ifdef _WIN64
//#ifdef _DLL
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x64-v141-mdd.lib")
//#else
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x64-v141-mtd.lib")
//#endif
//#else
//#ifdef _DLL
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x86-v141-mdd.lib")
//#else
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x86-v141-mtd.lib")
//#endif
//#endif
//#else
//#ifdef _WIN64
//#ifdef _DLL
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x64-v141-md.lib")
//#else
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x64-v141-mt.lib")
//#endif
//#else
//#ifdef _DLL
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x86-v141-md.lib")
//#else
//#pragma comment(lib, "../user_thirdparty/XEDParse/lib/libXEDParse-x86-v141-mt.lib")
//#endif
//#endif
//#endif
//
//#include "../user_thirdparty/capstone/x64/include/windowsce/stdint.h"
//#include "../user_thirdparty/capstone/x64/include/windowsce/intrin.h"
//#include "../user_thirdparty/capstone/x64/include/capstone/capstone.h"
//#pragma comment(lib,"../user_thirdparty/capstone/x64/capstone_static.lib")


//��4996����Ϊ���棬��������ʹ�ò���ȫ�ĺ�������scanf...
#pragma warning(disable : 4996)


//���������Ϣ,�����Ƿ���debug����ģʽ�¶������������Ϣ
//ע�⣺
//	�벻Ҫֱ�ӵ��������������ʹ�� DbgPrint �������������Ϣ
//	��ͨ��DebugView.exe���߲鿴����ĵ�����Ϣ
//	����ĵ�����䲻�ܺ��л��еȷ���
void DebugPrint(const char *format, ...);

#ifdef _DEBUG
#define DbgPrint DebugPrint//debug����ģʽ�½����������Ϣ
#else
#define DbgPrint(format,...)//Release����ģʽ�²������������Ϣ
#endif

//��õ�ǰ���̵�PEB��ַ
PVOID __stdcall GetPeb();

//���ؾ�ȷ��ʱ�����
LARGE_INTEGER GetTimeCount();

//���ؾ�ȷ��ʱ�����Ƶ�ʣ�һ���ӵļ���Ƶ�ʣ�
LARGE_INTEGER GetTimeFrequency();

//��ansi�ַ�ת��ΪUnicode�ַ�
//lpChar		ansi�ַ�������ʼ��ַ
//lpTchar		ת���󱣴�unicode�ַ�����ʼ��ַ
//lengthTchar	����unicode�ַ�����󳤶�
bool Char8ToUnicode16(char *lpChar, wchar_t *lpTchar, DWORD lengthTchar);

//��Unicode�ַ�ת��Ϊansi�ַ�
//lpTchar		unicode�ַ�������ʼ��ַ
//lpAnsi		ת���󱣴�ansi�ַ�����ʼ��ַ
//lengthChar	����ansi�ַ�����󳤶�
bool Unicode16ToChar8(wchar_t *lpTcharStr, char *lpAnsiStr, DWORD lengthChar);

//����·�����ļ������̡��̡߳�ģ�������
namespace path
{
	BOOLEAN NtPathToDosPathW(const wchar_t *FullNtPath, wchar_t *FullDosPath);
	BOOLEAN DosPathToNtPathW(const wchar_t *FullDosPath, wchar_t *FullNtPath);
	BOOLEAN NtPathToDosPathA(const char *FullNtPath, char *FullDosPath);
	BOOLEAN DosPathToNtPathA(const char *FullDosPath, char *FullNtPath);
	//���豸��ʽ���ļ�·��ת����NTĿ¼�µ�·����ʽ
	//eg:\\Device\\HarddiskVolume1\x86.sys ==> c:\x86.sys
	//pszNtPath		���룬�ں�ģʽ�µ��ļ�·��
	//pszDosPath	������û�ģʽ�µ�·����ʽ
	BOOL DeviceNtPathToDosPath(const wchar_t* pszNtPath, wchar_t* pszDosPath);
	//�ж��ļ��Ƿ���ڣ������Ǿ���·��
	bool Exists(std::string path);
	//�Ƴ�һ���ļ��������Ǿ���·��
	bool RemoveFile(std::string path);
	//����·�����õ����Ӻ��·��
	//���磺
	//	string a="123";
	//	Join({ "c:\\","a/b/bc\\d//","\\e.exe",a + "////" })
	//���أ�c:\a/b/bc\d\e.exe\123
	std::string Join(std::initializer_list<std::string> li);
	//��õ�ǰ���̵Ĺ���Ŀ¼�ľ���·��
	//ע�⣺
	//	���ص�·�����ǽ��̶������ļ����ڵ�·��
	//	���������˫�����е���ô���Ĺ���Ŀ¼�ľ���·���ͽ��̿�ִ���ļ��ľ���·��һ��
	//	��������Ǳ��������̴���������߿��ܲ�һ��
	std::string GetCurrentWorkingPath();
	//���õ�ǰ���̵Ĺ���·���ľ���·���������ǽ��̶������ļ����ڵ�·��
	bool SetCurrentWorkingPath(std::string path);
	//��õ�ǰ����ϵͳ����Ϣ
	OSVERSIONINFOA GetOSVersion();
	//��õ�ǰ���̵Ľ���ID��PID
	DWORD CurrentProcessPID();
	//��õ�ǰ���̵Ŀ�ִ���ļ������֡�ע�⣺����·�������緵��a.exe
	std::string CurrentProcessName();
	//��õ�ǰ����ʹ�õ��������ַ���������������
	std::string CurrentProcessCommandLine();
	//��ó����ִ���ļ���·��,������ִ���ļ�������
	std::string CurrentProcessExcultFilePath();
	//��ó����ִ���ļ�������·��,������ִ���ļ������֣����ؾ���·����
	std::string CurrentProcessExcultFileFullPath();
	//�ж��Ƿ��ظ�����
	//ע�⣺�����ṩ��mutexName�ַ���Ӧ��һ��
	BOOL IsAlreadyRun(const char *mutexName);
	//���ݽ������ƻ�ȡPID
	//����
	//	pszProcessName		��������
	// ����ֵ��PID��ɵ�����
	std::vector<DWORD> GetProcessIdByProcessName(PCSTR pszProcessName);
	//����PID��ȡ���������е��߳�TID
	//����
	//	dwProcessId�����̵�PID
	//����ֵ��TID��ɵ�����
	std::vector<DWORD> GetAllThreadIdByProcessId(DWORD dwProcessId);
	//�жϽ����Ƿ���64λ����
	//�������Ϊ0����ʾ��ǰ����
	//ע�⣺
	//	ϵͳ�����޷���ý��̵�����
	BOOL Is64bitProcess(DWORD dwProcessId);
	//�жϵ�ǰ����ϵͳ�Ƿ���64λ����ϵͳ
	BOOL Is64bitOS();
	//ö��ָ�������ڵ�����ģ��
	std::vector<MODULEENTRY32> ListProcessModules(DWORD dwProcessId);
	//���ش�����һ���ļ��������ֽ�
	//����
	//	filepath	��ȡ���ļ�������·��
	//	filesize	����������ȡ����ɺ󣬶�ȡ���ļ��Ĵ�С���������Ĵ�С��
	//���أ������ȡʧ�ܷ���NULL�����򷵻ر����ļ����ݵĻ�������ַ��
	//ע�⣺
	//	�ļ���С���ܲ���4GB�������ȡ���ļ����Ӧ���Ƚ�С��
	//	��ʹ����ɺ�Ӧ��ʹ��free�����ͷŻ�����
	PBYTE GetFileAllBytes(std::string filepath, DWORD &filesize);
	//���ؽ��̵����̵߳��߳�ID
	DWORD ProcessMainThread(DWORD dwProcessId);
	//��������Ȩ��
	//ע�⣺
	//	����򿪽�����ʾʧ�ܣ���ʹ�ô˺�����������Ȩ�ޡ�
	//	�����Ȼʧ�ܣ���ʹ�ù���Աģʽ���г���
	BOOL EnableDebugPrivilege();
	//�������Ƿ���й���ԱȨ��
	BOOL IsRunasAdmin();
};
//ʵ�ֿ��ܽ���
namespace puppet
{
#ifndef _WIN64  //x86
	//����һ�����ܽ���
	//����
	//	strTargetProcess	������Ŀ���������·��
	//	strPuppetProcess	ʵ�����еĿ�ִ���ļ�������·��
	BOOL CreatePuppetProcess(std::string strTargetProcess, std::string strPuppetProcess);
	//����һ�����ܽ���
	//����
	//	strTargetProcess	������Ŀ���������·��
	//	strPuppetProcess	ʵ�����еĿ�ִ���ļ��Ķ��������ݻ��������׵�ַ(ֻ���ǿ�ִ���ļ�����������)
	BOOL CreatePuppetProcess(std::string strTargetProcess, LPBYTE lpPuppetProcessData);
#endif
};
//ʵ��dllע��
namespace inject
{
	//ʹ�ô���Զ���߳���Ŀ��������dllע��
	//����
	//	dwProcessId		Ŀ����̵�PID
	//	pszDllName		��ע���dll������·��
	//ע�⣺
	//	�������ϵͳ�汾��vista���Ժ�ʵ����ʹ�õ���NtCreateThreadEx������Զ���߳�
	//	�������ϵͳ�汾��vista֮ǰ��ʵ����ʹ�õ���CreateRemoteThread������Զ���߳�
	BOOL InjectByCreateRemoteThread(DWORD dwProcessId, LPCTSTR pszDllName);
	//APCע�룬��ĳ��dll��APCע�뷽ʽע�뵽Ŀ�����
	//����
	//	pszProcessName����ע����̵Ľ�����
	//	pszDllName����ע���dll������·��
	//����ֵ��ʧ�ܷ���0���ɹ�����ֵ����0
	//ע�⣺
	//	ע��ǰ��ȷ�ϱ�ע���dll��ƽ̨��Ŀ����̵�ƽ̨һ�£�����ֻ����Ŀ����̵��������º���֮һ�Ż�ʹע��ɹ���
	//	SleepEx;SignalObjectAndWait;WaitForSignalObjectEx;WaitForMultipleObjectsEx;MsgWaitForMultipleObjectsEx
	//	����Ա����̴������ӽ��̺� ���� ʹ��APCע������������ɹ�����ʹ�ӽ��̵��̲߳��߱����������ĵ��á�
	//	ʲô��Alertable����ָ���̵߳ȴ������п��Ա���϶����߳�ȥִ�����������顣
	DWORD InjectByApc(DWORD dwProcessId, PCSTR pszDllName);
	//���ù����̺߳�ָ��߳��޸��̻߳������ע��
	//����
	//	dwProcessId		Ŀ����̵�PID
	//	pszDllName		��ע���DLL������·��
	//���أ��ɹ����ش���0��ʧ�ܷ���0
	DWORD InjectBySuspendResume(DWORD dwProcessId, PCSTR pszDllName);

	//����RtlCreateUserThread����ʵ��Զ��ע��dll
	//����
	//	dwProcessId		Ŀ����̵�PID
	//	pszDllName		��ע���DLL������·��
	//���أ��ɹ����ش���0��ʧ�ܷ���0
	DWORD InjectByRtlCreateUserThread(DWORD dwProcessId, PCSTR pszDllName);
};
//ʵ�ֱ���hook
namespace hook
{
	//ʹ��Hookǰ������ô˺��������ڳ�ʼ��Hook����
	//ע�⣺
	//	�������ͷ�ļ�detours.h�͵���detours.lib�ļ�
	//	��ʹ��Vs2015 tools������detours��Դ��Ŀ�ľ�̬��汾
	void Detours_HookInit();
	/*
	��һ����������hook,�ɹ�����TRUE�����򷵻�FALSE
	Hook������oldFunAddr�������ԭʼ��������Ч��ʼ��ַ
	ע�⣺�����һ�ε��ô˺���ǰ�������HookInit����
	ʾ����
	Hook MessageBoxA������
		//���庯��ָ��
		typedef int (WINAPI *PFMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
		//���庯��ָ��Ԥ�ȱ���ԭʼ������ַ
		PFMessageBoxA User32_MessageBoxA = MessageBoxA;
		//����Hook��ĺ���
		int WINAPI HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
		{
			DbgPrint("MessageBoxA(0x%08x,\"%s\",\"%s\")", hWnd, lpCaption, lpText);
			return User32_MessageBoxA(hWnd, lpText, lpCaption, uType);
		 }
	���ã�
		HookInit();
		Hook(&(PVOID&)User32_MessageBoxA,HookMessageBoxA);
		MessageBoxA(NULL, "Hello", "Hello",MB_YESNOCANCEL);
		UnHook(&(PVOID&)User32_MessageBoxA, HookMessageBoxA);
	*/
	BOOL Detours_Hook(PVOID *oldFunAddr, PVOID newFunAddr);
	//��һ����������hook���ɹ�����TRUE�����򷵻�FALSE
	//UnHook������oldFunAddr���ָ�Ϊԭʼ��������ʼ��ַ
	BOOL Detours_UnHook(PVOID *oldFunAddr, PVOID newFunAddr);


	//��ʼ��MinHook��
	BOOL MinHook_Init();
	/*
	�Ժ�������Hook
	oldFunOriginalAddr		����Ŀ�꺯����ַ��ָ��
	oldFunRealAddr			���������hook��ԭʼ������������ʼ��ַ��ָ��
	newFunAddr				����detour������ַ��ָ��
	ע�⣺����֮ǰӦ���ȵ���MinHook_Init����
	ʾ����
	Hook MessageBoxW������
	PVOID pfMessageBoxW = 0;	//point to save messageboxw function real entry while hooked
	PVOID pmsgbox;				//point to save messageboxw function entry
	PVOID pdetour_msgbox;		//point to save messageboxw function's detour entry
	// Detour function which overrides MessageBoxW.
	int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
	{
		return ((decltype(&MessageBoxW))pfMessageBoxW)  (hWnd, L"Hooked!", lpCaption, uType);
	}
	int main(int argc, TCHAR* argv[], TCHAR* envp[])
	{
		pmsgbox = (PVOID)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxW");
		pdetour_msgbox = DetourMessageBoxW;
		MinHook_Init();
		MinHook_Hook(pmsgbox, pfMessageBoxW, pdetour_msgbox);
		MessageBoxW(NULL, L"UnHook", L"Test", MB_RETRYCANCEL);//actually message hooked!
		MinHook_UnHook(pmsgbox);
		MessageBoxW(NULL, L"UnHook", L"Test", MB_OK);
		system("pause");
		return 0;
	}*/
	BOOL MinHook_Hook(PVOID oldFunOriginalAddr, PVOID &oldFunNewAddr, PVOID detourFunAddr);
	//�����Ŀ�꺯����hook
	//oldFunOriginalAddr		����Ŀ�꺯����ַ��ָ��
	BOOL MinHook_UnHook(PVOID oldFunOriginalAddr);
};
//ʵ�ּӽ��ܲ���
namespace crypt
{

	//����AES��Կ
	//	AESKey ����AES��Կ������
	//	dwAESKeyLength ����õ���Կ�ĳ��ȣ����Ȳ�����ᱻ�Զ�������
	//	dwBufferSize AESKey���鳤�ȣ�������ȹ�С���޷�������Կ�����޷�������Կ��
	BOOL AES_GenerateKey(BYTE *pAESKey, DWORD dwBufferSize, DWORD &dwAESKeyLength);

	//ʹ��AES�����㷨�����ݼ���
	//	pOriginalData �������ݵ�ַ
	//	dwOriginalDataSize ���ĳ��ȣ��ֽڣ�
	//	pAESKey ��Կ
	//	dwAESKeySize ��Կ����
	//	ppEncryptData ������ܺ�����ݻ�������ָ�루������Ϊ��̬���룬ʹ�ú�Ӧ���ͷţ�
	//	pdwEncryptData ���ܺ󱣴����ĵĻ����������ݵĳ���
	BOOL AES_Encrypt(BYTE *pOriginalData, DWORD dwOriginalDataSize, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppEncryptData, DWORD *pdwEncryptData);

	//ʹ��AES�����㷨���Ѿ����ܵ����ݽ��н���
	//	pEncryptData ��������
	//	dwEncryptData �������ݵĳ���
	//	pAESKey ��Կָ��
	//	dwAESKeySize ��Կ����
	//	ppDecryptData ������ܺ�����ݻ�������ָ�루������Ϊ��̬���룬ʹ�ú�Ӧ���ͷţ�
	//	pdwDecryptData ���ܺ󱣴����ĵĻ����������ݵĳ���
	BOOL AES_Decrypt(BYTE *pEncryptData, DWORD dwEncryptData, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppDecryptData, DWORD *pdwDecryptData);


	// �����ļ��� MD5 ֵ
	std::string MD5_File(const char *pszFileName);

	// �������ݵ� MD5 ֵ
	std::string MD5_Bytes(PBYTE pData, DWORD dwDataSize);

	// �����ļ��� SHA1 ֵ
	std::string SHA1_File(const char *pszFileName);

	// �������ݵ� SHA1 ֵ
	std::string SHA1_Bytes(PBYTE pData, DWORD dwDataSize);

	// �����ļ��� SHA256 ֵ
	std::string SHA256_File(const char *pszFileName);

	// �������ݵ� SHA256 ֵ
	std::string SHA256_Bytes(PBYTE pData, DWORD dwDataSize);

	// �����ļ��� CRC32 ֵ
	// ע�⣺��ǰ�汾��CRC32�������
	std::string CRC32_File(const char *pszFileName);

	// �������ݵ� CRC32 ֵ
	// ע�⣺��ǰ�汾��CRC32�������
	std::string CRC32_Bytes(PBYTE pData, DWORD dwDataSize);

	//����RSA�Ĺ�Կ��˽Կ���������Ľ��������ļ���.
	//	keyLength ��Կ����, 
	//	PrivFilename ���˽Կ���ļ���, 
	//	pubFilename ��Ź�Կ���ļ���, 
	//	seed ������Կ������, 
	//	dwSeedLength seedʱ������Կ�����ӳ���.
	BOOL RSA_GenerateKey(DWORD dwRSAKeyLength, const char *pszPrivateKeyFileName, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength);


	//RSA�����ַ���
	//	pszOriginaString Ҫ���ܵ��ַ��������ģ�,
	//	pszPublicKeyFileName ��Ź�Կ���ļ���,
	//	pSeed �������ӣ������ᱻ�޸�,
	//	dwSeedLength ������ӵ�����ĳ���
	std::string RSA_Encrypt_ByFile(const char *pszOriginaString, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength);


	//RSA�����ַ���
	//	pszEncryptString Ҫ���ܵ��ַ��������ģ�,
	//	pszPrivateKeyFileName ���˽Կ���ļ���
	std::string RSA_Decrypt_ByFile(const char *pszEncryptString, const char *pszPrivateKeyFileName);

	//RSA�����ַ���������ַ������ȹ������������μ���
	// pszOriginaString ���ģ�����������87�ֽ��ڣ�С��87��
	// pszMemPublicKey ��Կ
	// pSeed ���ӣ������ᱻ�޸�,
	// dwSeedLength ������ӵ�����ĳ���
	std::string RSA_Encrypt_ByMem(const char *pszOriginaString, const char *pszMemPublicKey, BYTE *pSeed, DWORD dwSeedLength);


	//RSA�����ַ���
	//	pszEncryptString ����
	//	pszMemPrivateKey ˽Կ
	std::string RSA_Decrypt_ByMem(const char *pszEncryptString, const char *pszMemPrivateKey);

};

namespace mm
{
	typedef void *HMEMORYMODULE;

	typedef void *HMEMORYRSRC;

	typedef void *HCUSTOMMODULE;

#ifdef __cplusplus
	extern "C" {
#endif

		typedef LPVOID(*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
		typedef BOOL(*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
		typedef HCUSTOMMODULE(*CustomLoadLibraryFunc)(LPCSTR, void *);
		typedef FARPROC(*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
		typedef void(*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);

		/**
		 * Load EXE/DLL from memory location with the given size.
		 *
		 * All dependencies are resolved using default LoadLibrary/GetProcAddress
		 * calls through the Windows API.
		 */
		HMEMORYMODULE MemoryLoadLibrary(const void *, size_t);

		/**
		 * Load EXE/DLL from memory location with the given size using custom dependency
		 * resolvers.
		 *
		 * Dependencies will be resolved using passed callback methods.
		 */
		HMEMORYMODULE MemoryLoadLibraryEx(const void *, size_t,
			CustomAllocFunc,
			CustomFreeFunc,
			CustomLoadLibraryFunc,
			CustomGetProcAddressFunc,
			CustomFreeLibraryFunc,
			void *);

		/**
		 * Get address of exported method. Supports loading both by name and by
		 * ordinal value.
		 */
		FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

		/**
		 * Free previously loaded EXE/DLL.
		 */
		void MemoryFreeLibrary(HMEMORYMODULE);

		/**
		 * Execute entry point (EXE only). The entry point can only be executed
		 * if the EXE has been loaded to the correct base address or it could
		 * be relocated (i.e. relocation information have not been stripped by
		 * the linker).
		 *
		 * Important: calling this function will not return, i.e. once the loaded
		 * EXE finished running, the process will terminate.
		 *
		 * Returns a negative value if the entry point could not be executed.
		 */
		int MemoryCallEntryPoint(HMEMORYMODULE);

		/**
		 * Find the location of a resource with the specified type and name.
		 */
		HMEMORYRSRC MemoryFindResource(HMEMORYMODULE, LPCTSTR, LPCTSTR);

		/**
		 * Find the location of a resource with the specified type, name and language.
		 */
		HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

		/**
		 * Get the size of the resource in bytes.
		 */
		DWORD MemorySizeofResource(HMEMORYMODULE, HMEMORYRSRC);

		/**
		 * Get a pointer to the contents of the resource.
		 */
		LPVOID MemoryLoadResource(HMEMORYMODULE, HMEMORYRSRC);

		/**
		 * Load a string resource.
		 */
		int MemoryLoadString(HMEMORYMODULE, UINT, LPTSTR, int);

		/**
		 * Load a string resource with a given language.
		 */
		int MemoryLoadStringEx(HMEMORYMODULE, UINT, LPTSTR, int, WORD);

		/**
		* Default implementation of CustomAllocFunc that calls VirtualAlloc
		* internally to allocate memory for a library
		*
		* This is the default as used by MemoryLoadLibrary.
		*/
		LPVOID MemoryDefaultAlloc(LPVOID, SIZE_T, DWORD, DWORD, void *);

		/**
		* Default implementation of CustomFreeFunc that calls VirtualFree
		* internally to free the memory used by a library
		*
		* This is the default as used by MemoryLoadLibrary.
		*/
		BOOL MemoryDefaultFree(LPVOID, SIZE_T, DWORD, void *);

		/**
		 * Default implementation of CustomLoadLibraryFunc that calls LoadLibraryA
		 * internally to load an additional libary.
		 *
		 * This is the default as used by MemoryLoadLibrary.
		 */
		HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR, void *);

		/**
		 * Default implementation of CustomGetProcAddressFunc that calls GetProcAddress
		 * internally to get the address of an exported function.
		 *
		 * This is the default as used by MemoryLoadLibrary.
		 */
		FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE, LPCSTR, void *);

		/**
		 * Default implementation of CustomFreeLibraryFunc that calls FreeLibrary
		 * internally to release an additional libary.
		 *
		 * This is the default as used by MemoryLoadLibrary.
		 */
		void MemoryDefaultFreeLibrary(HCUSTOMMODULE, void *);

#ifdef __cplusplus
	}
#endif
};


#endif//COMMON_H