#ifndef PCH_H
#define PCH_H

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
#include <map>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <fstream>

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
#include <psapi.h>
//视4996错误为警告，这样可以使用不安全的函数，如scanf...
#pragma warning(disable : 4996)

#define	CS_DEFINE(name)	\
CRITICAL_SECTION	name##_cs

#define CS_INIT(name)	\
InitializeCriticalSection(&name##_cs)

#define CS_ENTER(name)	\
EnterCriticalSection(&name##_cs)

#define CS_LEAVE(name)	\
LeaveCriticalSection(&name##_cs)

#define CS_DEL(name)	\
DeleteCriticalSection(&name##_cs);

using namespace std;

#endif //PCH_H

/*
注意：
	无论是x86还是x64：int和long都只占4字节,long long占8字节.x64下所有的指针都占8个字节
	使用WIndowes API时一定要使用windows定义的宏数据类型，这样可以在x86和x64之间任意切换
常用的快捷键：
	CTRL+M O,P代码全部折叠和展开
	CTRL+M L代码全部折叠和全部展开之间切换
	CTRL+K C,U代码选中块注释和取消注释
	Shift+Alt+鼠标左键：多列选择，如果只选择1列则可以多行同时插入内容
部分预定义宏说明：
	_WIN32：如果程序是windows程序将被定义，不论是32位程序还是64位程序
	_WIN64：如果程序是64位windows程序将被定义


*/
