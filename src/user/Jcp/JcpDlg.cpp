
// JcpDlg.cpp: 实现文件
//

#include "stdafx.h"
#include <winsvc.h>
#include "Jcp.h"
#include "JcpDlg.h"
#include "afxdialogex.h"
extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define DRIVER_NAME "JcpDriver"
#define COMMUNICATE_SERVICE	1000



//装载NT驱动程序
BOOL load_driver(const char* lpszDriverName, const char* lpszDriverPath)
{
	char szDriverImagePath[256];
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hServiceMgr == NULL)
	{
		//OpenSCManager失败
		DbgPrint("OpenSCManager() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager成功
		DbgPrint("OpenSCManager() ok ! \n");
	}

	//创建驱动所对应的服务
	hServiceDDK = CreateService(hServiceMgr,
		lpszDriverName, //驱动程序的在注册表中的名字 
		lpszDriverName, // 注册表驱动程序的 DisplayName 值 
		SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限 
		SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序 
		SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值 
		SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值 
		szDriverImagePath, // 注册表驱动程序的 ImagePath 值 
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);

	DWORD dwRtn;
	//判断服务是否失败
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			//由于其他原因创建服务失败
			DbgPrint("CrateService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			//服务创建失败，是由于服务已经创立过
			DbgPrint("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
		}

		// 驱动程序已经加载，只需要打开 
		hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			//如果打开服务也失败，则意味错误
			dwRtn = GetLastError();
			DbgPrint("OpenService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			DbgPrint("OpenService() ok ! \n");
		}
	}
	else
	{
		DbgPrint("CrateService() ok ! \n");
	}

	//开启此项服务
	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			DbgPrint("StartService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				//设备被挂住
				DbgPrint("StartService() Faild ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}
			else
			{
				//服务已经开启
				DbgPrint("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}
		}
	}
	bRet = TRUE;
	//离开前关闭句柄
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

//卸载驱动程序 
BOOL unload_driver(const char * szSvrName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	//打开SCM管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		//带开SCM管理器失败
		DbgPrint("OpenSCManager() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		//带开SCM管理器失败成功
		DbgPrint("OpenSCManager() ok ! \n");
	}
	//打开驱动所对应的服务
	hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

	if (hServiceDDK == NULL)
	{
		//打开驱动所对应的服务失败
		DbgPrint("OpenService() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		DbgPrint("OpenService() ok ! \n");
	}
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。 
	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
	{
		DbgPrint("ControlService() Faild %d !\n", GetLastError());
	}
	else
	{
		//打开驱动所对应的失败
		DbgPrint("ControlService() ok !\n");
	}
	//动态卸载驱动程序。 
	if (!DeleteService(hServiceDDK))
	{
		//卸载失败
		DbgPrint("DeleteSrevice() Faild %d !\n", GetLastError());
	}
	else
	{
		//卸载成功
		DbgPrint("DelServer:eleteSrevice() ok !\n");
	}
	bRet = TRUE;
BeforeLeave:
	//离开前关闭打开的句柄
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

DWORD get_eplore_process_pid()
{
	DWORD dwProcessId = 0;

	// Get the PID of explorer by its windows handle
	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);

	return dwProcessId;
}

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CJcpDlg 对话框



CJcpDlg::CJcpDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_JCP_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CJcpDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CJcpDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_LOAD_DRIVER, &CJcpDlg::OnBnClickedLoadDriver)
	ON_BN_CLICKED(IDC_BUTTON_INIT_SETTING, &CJcpDlg::OnBnClickedButtonInitSetting)
	ON_BN_CLICKED(IDC_BUTTON_UNLOAD_DRIVER, &CJcpDlg::OnBnClickedButtonUnloadDriver)
	ON_BN_CLICKED(IDC_BUTTON_CHOSE_FILE, &CJcpDlg::OnBnClickedButtonChoseFile)
	ON_BN_CLICKED(IDC_BUTTON_ADD_CRACK_FILE, &CJcpDlg::OnBnClickedButtonAddCrackFile)
	ON_BN_CLICKED(IDC_BUTTON_ADD_PROTECT_FILE, &CJcpDlg::OnBnClickedButtonAddProtectFile)
END_MESSAGE_MAP()


// CJcpDlg 消息处理程序

BOOL CJcpDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	if (!path::IsRunasAdmin())
	{
		MessageBox("请重新启动本程序，在启动的时候以右键管理员方式运行！", "权限不够", MB_OK | MB_ICONINFORMATION);
		exit(0);
	}
	ShowWindow(SW_NORMAL);


	hntdll = GetModuleHandleA("ntdll.dll");
	NtQueryInformationProcess = (PFNtQueryInformationProcess)GetProcAddress(hntdll, "NtQueryInformationProcess");
	driver_path = path::Join({ path::CurrentProcessExcultFilePath() , DRIVER_NAME }) + ".sys";
//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
//	csh handle;
//	cs_insn *insn;
//	size_t count;
//
//	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
//		return -1;
//	count = cs_disasm(handle, (uint8_t*)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
//	//if (count > 0) {
//	//	size_t j;
//	//	for (j = 0; j < count; j++) {
//	//		sprintf("0x%\"PRIx64\":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
//	//			insn[j].op_str);
//	//	}
//
//	//	cs_free(insn, count);
//	//}
//	//else
//	//	printf("ERROR: Failed to disassemble given code!\n");
//
//	cs_close(&handle);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CJcpDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CJcpDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CJcpDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//NtQueryInformationProcess
//参数1：通信方式
//参数2：通信传递的数据地址
//参数3：通信传递的数据的长度
NTSTATUS CJcpDlg::communicate_to_driver(DWORD type, PVOID data, DWORD length)
{
	return NtQueryInformationProcess((HANDLE)type, (PROCESSINFOCLASS_SR)COMMUNICATE_SERVICE, data, length, NULL);
}


void CJcpDlg::OnBnClickedLoadDriver()
{
	auto driver_path = path::Join({ path::CurrentProcessExcultFilePath(),DRIVER_NAME }) + ".sys";
	auto status = load_driver(DRIVER_NAME, driver_path.c_str());
	if (!status) MessageBoxA("失败！驱动程序加载出现错误，请按如下提示解决问题:\n\
							\t1.请以管理员方式启动后再次尝试\n\
							\t2.先执行卸载工作后再次尝试\n\
							\t3.检查本程序路径下是否有驱动程序",
		"错误", MB_OK | MB_ICONERROR);
	if (status) driver_loaded = TRUE;

}


void CJcpDlg::OnBnClickedButtonInitSetting()
{
	DWORD pid = get_eplore_process_pid();
	auto status = communicate_to_driver(1, &pid, sizeof(DWORD));
	if (status != 0)
	{
		MessageBoxA("失败，请重新加载驱动后再次尝试！");
		return;
	}
}

//type的取值说明
/*
1-8需要带参数
9-16不需要参数
	1：提供explorer.exe的pid
	2：设置一个白名单进程的完整路径（区分大小写）
	3：设置一个白名单的包含字符串（区分大小写）
	4：设置一个黑名单的进程的完整路径（区分大小写）
	5：设置一个黑名单的进程名包含的字符串（区分大小写）
	6：删除一个白名单设置项
	7：删除一个黑名单设置项
	8：读取所有设置项

	9：通过修改代码方式禁用 线程、进程、loadimage回调
	10：恢复通过改代码方式禁用的 线程、进程、loadimage回调
*/

void CJcpDlg::OnBnClickedButtonUnloadDriver()
{
	auto status = unload_driver(DRIVER_NAME);
	if (TRUE !=status )
		MessageBoxA("失败！驱动程序卸载出现错误，请按如下提示解决问题:\n\
							\t1.请以管理员方式启动后再次尝试\n\
							\t2.你可能没有安装此驱动\n",
			"错误", MB_OK | MB_ICONERROR);
	if (status) driver_loaded = FALSE;

}


void CJcpDlg::OnBnClickedButtonChoseFile()
{
	CString strFile = "";
	char work_path[MAX_PATH + 1];
	GetCurrentDirectoryA(sizeof(work_path), work_path);
	CFileDialog    dlgFile(TRUE, NULL, work_path, OFN_HIDEREADONLY, _T("可执行PE文件(*.exe)|*.exe|All Files (*.*)|*.*||"), NULL);

	if (dlgFile.DoModal() == IDOK)
	{
		strFile = dlgFile.GetPathName();
		((CEdit*)GetDlgItem(IDC_EDIT_FILE_PATH))->SetWindowText(strFile);
	}
}


void CJcpDlg::OnBnClickedButtonAddCrackFile()
{
	//4：设置一个黑名单的进程的完整路径（区分大小写）
	CString file_full_path;
	((CEdit*)GetDlgItem(IDC_EDIT_FILE_PATH))->GetWindowTextA(file_full_path);
	WCHAR wfile_full_path_dos[262];
	WCHAR wfile_full_path_nt[262];
	if (!path::Exists(file_full_path.GetBuffer())) return;
	Char8ToUnicode16(file_full_path.GetBuffer(), wfile_full_path_dos, 262);
	path::DosPathToNtPathW(wfile_full_path_dos, wfile_full_path_nt);
	NTSTATUS status=communicate_to_driver(4, wfile_full_path_nt, wcslen(wfile_full_path_nt) + 2);
	if (status != 0)
	{
		MessageBoxA("操作失败！请按如下提示解决问题:\n\
							\t1.请以管理员方式启动后再次尝试\n\
							\t2.你可能没有安装此驱动\n",
			"错误", MB_OK | MB_ICONERROR);
	}
	else
	{
		MessageBoxA("添加要Crack的进程完整路径成功","信息", MB_OK | MB_ICONINFORMATION);
	}

}




void CJcpDlg::OnBnClickedButtonAddProtectFile()
{
	//2：设置一个白名单进程的完整路径（区分大小写）
	CString file_full_path;
	((CEdit*)GetDlgItem(IDC_EDIT_FILE_PATH))->GetWindowTextA(file_full_path);
	WCHAR wfile_full_path_dos[262];
	WCHAR wfile_full_path_nt[262];
	if (!path::Exists(file_full_path.GetBuffer())) return;
	Char8ToUnicode16(file_full_path.GetBuffer(), wfile_full_path_dos, 262);
	path::DosPathToNtPathW(wfile_full_path_dos, wfile_full_path_nt);
	NTSTATUS status = communicate_to_driver(2, wfile_full_path_nt, wcslen(wfile_full_path_nt) + 2);
	if (status != 0)
	{
		MessageBoxA("操作失败！请按如下提示解决问题:\n\
							\t1.请以管理员方式启动后再次尝试\n\
							\t2.你可能没有安装此驱动\n",
			"错误", MB_OK | MB_ICONERROR);
	}
	else
	{
		MessageBoxA("添加保护的进程完整路径成功", "信息", MB_OK | MB_ICONINFORMATION);
	}
}
