
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
����InfinityHook��ע�����
����ϵͳ�ṩ��ssdt����ϵͳ�����ֵ���;����
1.�ں�ֱ��call zw��ͷ�ĺ���������zwϵ�еĺ�����ͷ���Ὣ��ǰģʽ����Ϊ0��Ȼ����ת��KiSystemServiceStart����ִ�л�����InfinityHook׼���ĺ����У����ִ��nt��ͷ�ĺ�������nt��ͷ�ĺ������Ǹ÷�����������ʵ�֡�
2.�ں˲�ֱ�ӷ���nt��ͷ�ĺ��������ﲻ���޸���ǰģʽ�����ǻ�鿴��ǰģʽ��ֵ�������Ƿ���в�����顣������֮ǰ����ǰģʽ��������ǰģʽһ��Ϊ0
3.�û���ͨ��syscall��ɵķ��������þ���InfinityHook�����ĺ��������ִ��nt��ͷ�ķ�����������һ��������ǰģʽ����ı���һֱΪ1
���Կ�����
	InfinityHook��������ȫ������е�ssdt�����ĵ��ã���Ϊ���ں�ֱ�ӷ������nt��ͷ�ĺ���
	����InfinityHook���Լ�����ຯ����1.�û���ͨ��zw��ͷ�ĺ��� 2.�û����syscall����ķ���������
ʵ�ʱ��֣�
	���ַ��������ں��в������call nt��ͷ�ĺ����������÷��������ᱻ��ص�
	���ֺ����ᱻcall nt��ͷ�ĺ�������������޷�����ء�
	���磺ntcreatefile ��ֱ�ӵ���


//zw��ͷ�ĺ�����
*/