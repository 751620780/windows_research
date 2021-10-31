
// JcpDlg.h: 头文件
//

#pragma once

#include "../user_share/user_common.h"
#include "../user_share/user_sr.h"



// CJcpDlg 对话框


#define MAX_SIZE_WORK 15

typedef struct _REG_STRING
{
	UINT8  type;															//0:无效，1：匹配进程全路径（区分大小写），2：进程路径中包含字符串（区分大小写）
	WCHAR  str[261 * 2];													//保存字符串的缓冲区
}REG_STRING, *PREG_STRING;

typedef struct _ADPS														//ANDY DEBUG PROTECT SYSTEM
{
	UINT8			kernel_mode_debug_port_protect;							//是否开启内核的debugport保护
	UINT8			user_mode_debug_port_protect;							//是否开启用户层的debugport保护
	DWORD			explorer_pid;											//保存explorer.exe进程的pid
	PVOID64			process_protect[MAX_SIZE_WORK];							//需要保护的调试器进程的EPROCESS地址数组
	PVOID64			process_crack[MAX_SIZE_WORK];							//需要反反调试的进程的EPROCESS地址数组
	REG_STRING		protect_name_list[MAX_SIZE_WORK];
	REG_STRING		crack_name_list[MAX_SIZE_WORK];
	REG_STRING		process_name_create_forbid[MAX_SIZE_WORK];				//禁止被创建的进程的名单，保存的是用户层的完整路径
}ADPS, *PADPS;



class CJcpDlg : public CDialogEx
{
// 构造
public:
	CJcpDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_JCP_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	HMODULE hntdll=NULL;
	PFNtQueryInformationProcess  NtQueryInformationProcess=NULL;
	std::string driver_path;
	BOOL driver_loaded = FALSE;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	NTSTATUS communicate_to_driver(DWORD type, PVOID data, DWORD length);
public:
	afx_msg void OnBnClickedLoadDriver();
	afx_msg void OnBnClickedButtonInitSetting();
	afx_msg void OnBnClickedButtonUnloadDriver();
	afx_msg void OnBnClickedButtonChoseFile();
	afx_msg void OnBnClickedButtonAddCrackFile();
	afx_msg void OnBnClickedButtonAddProtectFile();
};
