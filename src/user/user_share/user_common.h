#pragma once
/*
注意：
	无论是x86还是x64：int和long都只占4字节,long long占8字节.x64下所有的指针都占8个字节
	使用WIndowes API时一定要使用windows定义的宏数据类型，这样可以在x86和x64之间任意切换
常用的快捷键：
	CTRL+M O,P代码全部折叠和展开
	CTRL+K C,U代码选中块注释和取消注释
部分预定义宏说明：
	_WIN32：如果程序是windows程序将被定义，不论是32位程序还是64位程序
	_WIN64：如果程序是64位windows程序将被定义
	_M_IX86：如果程序将被编译成为32为应用程序（32bit处理器）
	_M_AMD64：如果程序被编译成64位应用程序（64bit AMD处理器 (VC2008以前)）
	__FILE__：等于当前代码文件的绝对路径
	__LINE__：等于当前代码所在行的行数
	_DLL：如果编译的运行库使用的是MD或MDd编译时，该宏将被定义。如果没定义则使用的是MT或MTd
	_DEBUG：编译将包含debug信息
	MIDL_PASS：如果编译器支持64位整数
MFC：
	使用此文件时，对于MFC应用程序编译时返回的“LINK2005”错误，报错的lib文件只需要添加在MFC项目->属性->连接器->输入
	里面	“附加依赖项”和“忽略特定默认库”中添加这个lib文件的文件名（含后缀）即可，lib文件之间用“;”隔开。
	另外，debug模式的和release模式对应的lib文件名不一样。
XP问题:
	当使用OpenProcess、OpenThread等函数时如果使用的第一个参数是xxx_ALL_ACCESS时会失败，因为这里面的标志位不适用于xp系统
项目属性配置问题：
	基本x86:
		输出目录：		$(SolutionDir)build\x86\$(Configuration)\
		中间目录：		$(SolutionDir)obj\x86\$(Configuration)\$(ProjectName)
	基本x64
		输出目录：		$(SolutionDir)build\$(Platform)\$(Configuration)\
		中间目录：		$(SolutionDir)obj\$(Platform)\$(Configuration)\$(ProjectName)
	调试
		工作目录：		$(OutDir)
	c/c++(针对XP)
		语言->符合语言:否
	第三方：
		所有的第三方模块如果提供了静态链接库应当仅仅使用静态链接库。否则（万般无奈）使用dll。
		include：要引入的头文件
		lib：要引入的静态链接库，文件夹内的每一个lib文件应当遵循lib{库名}-x86/x64-v140{vs工具版本}-编译模式.lib的命名原则（如果是使用vs编译的），否则就不用遵循
		dll：要引入的动态链接库
*/

#ifndef COMMON_H
#define COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN // 从 Windows 头中排除极少使用的资料,否则头文件重复定义
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
#include "../user_thirdparty/crypt/include/sha.h"//SHA1、SHA256
#include "../user_thirdparty/crypt/include/crc.h"//CRC32
#include "../user_thirdparty/crypt/include/crc.h"//CRC32
#include "../user_thirdparty/crypt/include/rsa.h"//RSA
#include "../user_thirdparty/crypt/include/randpool.h"//伪随机函数
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


//视4996错误为警告，这样可以使用不安全的函数，如scanf...
#pragma warning(disable : 4996)


//输出调试信息,无论是否是debug生成模式下都会输出调试信息
//注意：
//	请不要直接调用这个函数，请使用 DbgPrint 宏来输出调试信息
//	可通过DebugView.exe工具查看输出的调试信息
//	输出的调试语句不能含有换行等符号
void DebugPrint(const char *format, ...);

#ifdef _DEBUG
#define DbgPrint DebugPrint//debug生成模式下将输出调试信息
#else
#define DbgPrint(format,...)//Release生成模式下不会输出调试信息
#endif

//获得当前进程的PEB地址
PVOID __stdcall GetPeb();

//返回精确的时间计数
LARGE_INTEGER GetTimeCount();

//返回精确的时间计数频率（一秒钟的计数频率）
LARGE_INTEGER GetTimeFrequency();

//将ansi字符转化为Unicode字符
//lpChar		ansi字符串的起始地址
//lpTchar		转换后保存unicode字符的起始地址
//lengthTchar	保存unicode字符的最大长度
bool Char8ToUnicode16(char *lpChar, wchar_t *lpTchar, DWORD lengthTchar);

//将Unicode字符转化为ansi字符
//lpTchar		unicode字符串的起始地址
//lpAnsi		转换后保存ansi字符的起始地址
//lengthChar	保存ansi字符的最大长度
bool Unicode16ToChar8(wchar_t *lpTcharStr, char *lpAnsiStr, DWORD lengthChar);

//处理路径、文件、进程、线程、模块的问题
namespace path
{
	BOOLEAN NtPathToDosPathW(const wchar_t *FullNtPath, wchar_t *FullDosPath);
	BOOLEAN DosPathToNtPathW(const wchar_t *FullDosPath, wchar_t *FullNtPath);
	BOOLEAN NtPathToDosPathA(const char *FullNtPath, char *FullDosPath);
	BOOLEAN DosPathToNtPathA(const char *FullDosPath, char *FullNtPath);
	//将设备形式的文件路径转换成NT目录下的路径格式
	//eg:\\Device\\HarddiskVolume1\x86.sys ==> c:\x86.sys
	//pszNtPath		输入，内核模式下的文件路径
	//pszDosPath	输出，用户模式下的路径格式
	BOOL DeviceNtPathToDosPath(const wchar_t* pszNtPath, wchar_t* pszDosPath);
	//判断文件是否存在，参数是绝对路径
	bool Exists(std::string path);
	//移除一个文件，参数是绝对路径
	bool RemoveFile(std::string path);
	//连接路径，得到连接后的路径
	//例如：
	//	string a="123";
	//	Join({ "c:\\","a/b/bc\\d//","\\e.exe",a + "////" })
	//返回：c:\a/b/bc\d\e.exe\123
	std::string Join(std::initializer_list<std::string> li);
	//获得当前进程的工作目录的绝对路径
	//注意：
	//	返回的路径不是进程二进制文件所在的路径
	//	如果进程是双击运行的那么他的工作目录的绝对路径和进程可执行文件的绝对路径一致
	//	如果进程是被其他进程创建的则二者可能不一致
	std::string GetCurrentWorkingPath();
	//设置当前进程的工作路径的绝对路径，并不是进程二进制文件所在的路径
	bool SetCurrentWorkingPath(std::string path);
	//获得当前操作系统的信息
	OSVERSIONINFOA GetOSVersion();
	//获得当前进程的进程ID即PID
	DWORD CurrentProcessPID();
	//获得当前进程的可执行文件的名字。注意：不含路径，例如返回a.exe
	std::string CurrentProcessName();
	//获得当前进程使用的命令行字符串（包括参数）
	std::string CurrentProcessCommandLine();
	//获得程序的执行文件的路径,不含可执行文件的名字
	std::string CurrentProcessExcultFilePath();
	//获得程序的执行文件的完整路径,包含可执行文件的名字（返回绝对路径）
	std::string CurrentProcessExcultFileFullPath();
	//判断是否重复运行
	//注意：两次提供的mutexName字符串应当一样
	BOOL IsAlreadyRun(const char *mutexName);
	//根据进程名称获取PID
	//参数
	//	pszProcessName		进程名字
	// 返回值：PID组成的向量
	std::vector<DWORD> GetProcessIdByProcessName(PCSTR pszProcessName);
	//根据PID获取进程内所有的线程TID
	//参数
	//	dwProcessId：进程的PID
	//返回值：TID组成的向量
	std::vector<DWORD> GetAllThreadIdByProcessId(DWORD dwProcessId);
	//判断进程是否是64位进程
	//如果参数为0，表示当前进程
	//注意：
	//	系统进程无法获得进程的属性
	BOOL Is64bitProcess(DWORD dwProcessId);
	//判断当前操作系统是否是64位操作系统
	BOOL Is64bitOS();
	//枚举指定进程内的所有模块
	std::vector<MODULEENTRY32> ListProcessModules(DWORD dwProcessId);
	//返回磁盘上一个文件的所有字节
	//参数
	//	filepath	读取的文件的完整路径
	//	filesize	输出，输出读取后完成后，读取到文件的大小（缓冲区的大小）
	//返回：如果读取失败返回NULL；否则返回保存文件内容的缓冲区地址。
	//注意：
	//	文件大小不能操作4GB，另外读取的文件体积应当比较小。
	//	在使用完成后应当使用free函数释放缓冲区
	PBYTE GetFileAllBytes(std::string filepath, DWORD &filesize);
	//返回进程的主线程的线程ID
	DWORD ProcessMainThread(DWORD dwProcessId);
	//开启调试权限
	//注意：
	//	如果打开进程提示失败，请使用此函数开启调试权限。
	//	如果依然失败，请使用管理员模式运行程序
	BOOL EnableDebugPrivilege();
	//检查进程是否具有管理员权限
	BOOL IsRunasAdmin();
};
//实现傀儡进程
namespace puppet
{
#ifndef _WIN64  //x86
	//创建一个傀儡进程
	//参数
	//	strTargetProcess	依附的目标进程完整路径
	//	strPuppetProcess	实际运行的可执行文件的完整路径
	BOOL CreatePuppetProcess(std::string strTargetProcess, std::string strPuppetProcess);
	//创建一个傀儡进程
	//参数
	//	strTargetProcess	依附的目标进程完整路径
	//	strPuppetProcess	实际运行的可执行文件的二进制数据缓冲区的首地址(只能是可执行文件的完整数据)
	BOOL CreatePuppetProcess(std::string strTargetProcess, LPBYTE lpPuppetProcessData);
#endif
};
//实现dll注入
namespace inject
{
	//使用创建远程线程向目标进程完成dll注入
	//参数
	//	dwProcessId		目标进程的PID
	//	pszDllName		被注入的dll的完整路径
	//注意：
	//	如果操作系统版本是vista及以后，实际上使用的是NtCreateThreadEx来创建远程线程
	//	如果操作系统版本是vista之前，实际上使用的是CreateRemoteThread来创建远程线程
	BOOL InjectByCreateRemoteThread(DWORD dwProcessId, LPCTSTR pszDllName);
	//APC注入，将某个dll以APC注入方式注入到目标进程
	//参数
	//	pszProcessName：被注入进程的进程名
	//	pszDllName：被注入的dll的完整路径
	//返回值：失败返回0，成功返回值大于0
	//注意：
	//	注入前请确认被注入的dll的平台和目标进程的平台一致，另外只有在目标进程调用了以下函数之一才会使注入成功。
	//	SleepEx;SignalObjectAndWait;WaitForSignalObjectEx;WaitForMultipleObjectsEx;MsgWaitForMultipleObjectsEx
	//	如果对本进程创建的子进程后 立即 使用APC注入则可能立即成功，即使子进程的线程不具备上述函数的调用。
	//	什么是Alertable？是指在线程等待过程中可以被打断而让线程去执行其他的事情。
	DWORD InjectByApc(DWORD dwProcessId, PCSTR pszDllName);
	//利用挂起线程后恢复线程修改线程环境完成注入
	//参数
	//	dwProcessId		目标进程的PID
	//	pszDllName		被注入的DLL的完整路径
	//返回：成功返回大于0，失败返回0
	DWORD InjectBySuspendResume(DWORD dwProcessId, PCSTR pszDllName);

	//利用RtlCreateUserThread函数实现远程注入dll
	//参数
	//	dwProcessId		目标进程的PID
	//	pszDllName		被注入的DLL的完整路径
	//返回：成功返回大于0，失败返回0
	DWORD InjectByRtlCreateUserThread(DWORD dwProcessId, PCSTR pszDllName);
};
//实现本地hook
namespace hook
{
	//使用Hook前必须调用此函数，用于初始化Hook环境
	//注意：
	//	必须包含头文件detours.h和导入detours.lib文件
	//	请使用Vs2015 tools来编译detours开源项目的静态库版本
	void Detours_HookInit();
	/*
	对一个函数进行hook,成功返回TRUE，否则返回FALSE
	Hook结束后oldFunAddr保存的是原始函数的有效起始地址
	注意：程序第一次调用此函数前必须调用HookInit函数
	示例：
	Hook MessageBoxA函数：
		//定义函数指针
		typedef int (WINAPI *PFMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
		//定义函数指针预先保存原始函数地址
		PFMessageBoxA User32_MessageBoxA = MessageBoxA;
		//定义Hook后的函数
		int WINAPI HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
		{
			DbgPrint("MessageBoxA(0x%08x,\"%s\",\"%s\")", hWnd, lpCaption, lpText);
			return User32_MessageBoxA(hWnd, lpText, lpCaption, uType);
		 }
	调用：
		HookInit();
		Hook(&(PVOID&)User32_MessageBoxA,HookMessageBoxA);
		MessageBoxA(NULL, "Hello", "Hello",MB_YESNOCANCEL);
		UnHook(&(PVOID&)User32_MessageBoxA, HookMessageBoxA);
	*/
	BOOL Detours_Hook(PVOID *oldFunAddr, PVOID newFunAddr);
	//对一个函数进行hook，成功返回TRUE，否则返回FALSE
	//UnHook结束后oldFunAddr将恢复为原始函数的起始地址
	BOOL Detours_UnHook(PVOID *oldFunAddr, PVOID newFunAddr);


	//初始化MinHook库
	BOOL MinHook_Init();
	/*
	对函数进行Hook
	oldFunOriginalAddr		保存目标函数地址的指针
	oldFunRealAddr			输出，保存hook后原始函数的真正起始地址的指针
	newFunAddr				保存detour函数地址的指针
	注意：调用之前应当先调用MinHook_Init函数
	示例：
	Hook MessageBoxW函数：
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
	//解除对目标函数的hook
	//oldFunOriginalAddr		保存目标函数地址的指针
	BOOL MinHook_UnHook(PVOID oldFunOriginalAddr);
};
//实现加解密操作
namespace crypt
{

	//生成AES密钥
	//	AESKey 保存AES密钥的数组
	//	dwAESKeyLength 欲获得的密钥的长度（长度不合理会被自动修正）
	//	dwBufferSize AESKey数组长度（如果长度过小，无法保存密钥，将无法产生密钥）
	BOOL AES_GenerateKey(BYTE *pAESKey, DWORD dwBufferSize, DWORD &dwAESKeyLength);

	//使用AES加密算法将数据加密
	//	pOriginalData 明文数据地址
	//	dwOriginalDataSize 明文长度（字节）
	//	pAESKey 密钥
	//	dwAESKeySize 密钥长度
	//	ppEncryptData 保存加密后的数据缓冲区的指针（缓冲区为动态申请，使用后应当释放）
	//	pdwEncryptData 加密后保存密文的缓冲区中数据的长度
	BOOL AES_Encrypt(BYTE *pOriginalData, DWORD dwOriginalDataSize, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppEncryptData, DWORD *pdwEncryptData);

	//使用AES解密算法将已经加密的数据进行解密
	//	pEncryptData 密文数据
	//	dwEncryptData 密文数据的长度
	//	pAESKey 密钥指针
	//	dwAESKeySize 密钥长度
	//	ppDecryptData 保存解密后的数据缓冲区的指针（缓冲区为动态申请，使用后应当释放）
	//	pdwDecryptData 解密后保存明文的缓冲区中数据的长度
	BOOL AES_Decrypt(BYTE *pEncryptData, DWORD dwEncryptData, BYTE *pAESKey, DWORD dwAESKeySize, BYTE **ppDecryptData, DWORD *pdwDecryptData);


	// 计算文件的 MD5 值
	std::string MD5_File(const char *pszFileName);

	// 计算数据的 MD5 值
	std::string MD5_Bytes(PBYTE pData, DWORD dwDataSize);

	// 计算文件的 SHA1 值
	std::string SHA1_File(const char *pszFileName);

	// 计算数据的 SHA1 值
	std::string SHA1_Bytes(PBYTE pData, DWORD dwDataSize);

	// 计算文件的 SHA256 值
	std::string SHA256_File(const char *pszFileName);

	// 计算数据的 SHA256 值
	std::string SHA256_Bytes(PBYTE pData, DWORD dwDataSize);

	// 计算文件的 CRC32 值
	// 注意：当前版本的CRC32计算错误
	std::string CRC32_File(const char *pszFileName);

	// 计算数据的 CRC32 值
	// 注意：当前版本的CRC32计算错误
	std::string CRC32_Bytes(PBYTE pData, DWORD dwDataSize);

	//产生RSA的公钥和私钥并将产生的结果存放在文件中.
	//	keyLength 密钥长度, 
	//	PrivFilename 存放私钥的文件名, 
	//	pubFilename 存放公钥的文件名, 
	//	seed 产生密钥的种子, 
	//	dwSeedLength seed时产生密钥的种子长度.
	BOOL RSA_GenerateKey(DWORD dwRSAKeyLength, const char *pszPrivateKeyFileName, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength);


	//RSA加密字符串
	//	pszOriginaString 要加密的字符串（明文）,
	//	pszPublicKeyFileName 存放公钥的文件名,
	//	pSeed 加密种子，参数会被修改,
	//	dwSeedLength 存放种子的数组的长度
	std::string RSA_Encrypt_ByFile(const char *pszOriginaString, const char *pszPublicKeyFileName, BYTE *pSeed, DWORD dwSeedLength);


	//RSA解密字符串
	//	pszEncryptString 要解密的字符串（密文）,
	//	pszPrivateKeyFileName 存放私钥的文件名
	std::string RSA_Decrypt_ByFile(const char *pszEncryptString, const char *pszPrivateKeyFileName);

	//RSA加密字符串，如果字符串长度过长请分组后依次加密
	// pszOriginaString 明文，长度限制在87字节内（小于87）
	// pszMemPublicKey 公钥
	// pSeed 种子，参数会被修改,
	// dwSeedLength 存放种子的数组的长度
	std::string RSA_Encrypt_ByMem(const char *pszOriginaString, const char *pszMemPublicKey, BYTE *pSeed, DWORD dwSeedLength);


	//RSA解密字符串
	//	pszEncryptString 密文
	//	pszMemPrivateKey 私钥
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