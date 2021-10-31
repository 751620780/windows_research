#ifndef PCH_H
#define PCH_H
//这个头文件是预编译头文件，所有的其他库都可以包含这个头文件。不过，包含了这个头文件的文件A，被B包含了后，B文件无需包含这个头文件 
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <Ntifs.h>
#include <ntdef.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <windef.h>
//注意：offsetof宏的使用
#endif




