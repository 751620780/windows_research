
#pragma once

///
/// Structures and typedefs.
///

typedef void (__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

///
/// Forward declarations.
///

NTSTATUS IfhInitialize(
	_In_ INFINITYHOOKCALLBACK InfinityHookCallback);

void IfhRelease();

/*
关于InfinityHook的注意事项：
对于系统提供的ssdt函数系统有三种调用途径：
1.内核直接call zw开头的函数，而在zw系列的函数开头都会将先前模式设置为0，然后跳转到KiSystemServiceStart继续执行会来到InfinityHook准备的函数中，最后执行nt开头的函数，而nt开头的函数则是该服务函数的真正实现。
2.内核层直接发起nt开头的函数，这里不会修改先前模式，而是会查看先前模式的值来决定是否进行参数检查。即保持之前的先前模式，但是先前模式一般为0
3.用户层通过syscall完成的服务函数调用经过InfinityHook给定的函数后继续执行nt开头的服务函数，在这一过程中先前模式不会改变且一直为1
可以看出：
	InfinityHook并不能完全监控所有的ssdt函数的调用，因为有内核直接发起调用nt开头的函数
	但是InfinityHook可以监控两类函数：1.用户层通过zw开头的函数 2.用户层的syscall发起的服务函数调用
实际表现：
	部分服务函数在内核中不会出现call nt开头的函数，这样该服务函数都会被监控到
	部分函数会被call nt开头的函数，此情况下无法被监控。
	例如：ntcreatefile 有直接调用


//zw开头的函数会
*/