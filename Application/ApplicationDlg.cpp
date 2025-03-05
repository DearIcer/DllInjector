
// ApplicationDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include <TlHelp32.h>
#include "Application.h"
#include "ApplicationDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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


// CApplicationDlg 对话框



CApplicationDlg::CApplicationDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_APPLICATION_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CApplicationDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BUTTON1, m_btnBrowse);
	DDX_Control(pDX, IDC_EDIT2, m_editDllPath);
	DDX_Text(pDX, IDC_EDIT_DLLPATH, m_strDllPath);
	DDX_Control(pDX, IDC_COMBO1, m_comboProcesses);
}

BEGIN_MESSAGE_MAP(CApplicationDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CApplicationDlg::OnBnClickedButtonBrowse)
	ON_BN_CLICKED(IDC_BUTTON3, &CApplicationDlg::OnBnClickedInjector)

	ON_BN_CLICKED(IDC_BUTTON4, &CApplicationDlg::OnBnClickedUnloadDLL)
	ON_BN_CLICKED(IDC_BUTTON2, &CApplicationDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CApplicationDlg 消息处理程序

BOOL CApplicationDlg::OnInitDialog()
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

	// TODO: 在此添加额外的初始化代码
	RefreshProcessList();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CApplicationDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CApplicationDlg::OnPaint()
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
HCURSOR CApplicationDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CApplicationDlg::OnBnClickedButtonBrowse()
{
	// 创建文件选择对话框
	CFileDialog dlgFile(TRUE, // TRUE为打开文件，FALSE为保存文件
		_T("dll"), // 默认扩展名
		NULL, // 默认文件名
		OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, // 标志
		_T("DLL文件 (*.dll)|*.dll|所有文件 (*.*)|*.*||"), // 文件过滤器
		this); // 父窗口

	// 显示文件选择对话框
	if (dlgFile.DoModal() == IDOK)
	{
		// 获取选中的文件路径
		m_strDllPath = dlgFile.GetPathName();

		// 更新控件显示
		UpdateData(FALSE);
	}
}

void CApplicationDlg::RefreshProcessList()
{
	// 清空下拉框
	m_comboProcesses.ResetContent();

	// 创建进程快照
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		AfxMessageBox(_T("无法创建进程快照！"), MB_ICONERROR);
		return;
	}

	// 初始化进程条目结构
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// 获取第一个进程
	if (!Process32First(hProcessSnap, &pe32))
	{
		AfxMessageBox(_T("无法获取进程信息！"), MB_ICONERROR);
		CloseHandle(hProcessSnap);
		return;
	}

	// 遍历所有进程并添加到下拉框
	do
	{
		// 格式化进程信息：进程ID + 进程名称
		CString strProcessInfo;
		strProcessInfo.Format(_T("[%d] %s"), pe32.th32ProcessID, pe32.szExeFile);

		// 添加到下拉框，并存储进程ID作为项目数据
		int nIndex = m_comboProcesses.AddString(strProcessInfo);
		m_comboProcesses.SetItemData(nIndex, pe32.th32ProcessID);
	} while (Process32Next(hProcessSnap, &pe32));

	// 关闭进程快照句柄
	CloseHandle(hProcessSnap);

	// 如果有项目，则选择第一项
	if (m_comboProcesses.GetCount() > 0)
	{
		m_comboProcesses.SetCurSel(0);
	}
}




void CApplicationDlg::OnBnClickedInjector()
{
	// 更新数据变量
	UpdateData(TRUE);

	// 检查DLL路径
	if (m_strDllPath.IsEmpty())
	{
		MessageBox(_T("请先选择一个DLL文件！"), _T("错误"), MB_ICONERROR);
		return;
	}

	// 获取选中的进程ID
	int nSelectedIndex = m_comboProcesses.GetCurSel();
	if (nSelectedIndex == CB_ERR)
	{
		MessageBox(_T("请先选择一个目标进程！"), _T("错误"), MB_ICONERROR);
		return;
	}

	// 获取进程ID
	DWORD dwProcessID = (DWORD)m_comboProcesses.GetItemData(nSelectedIndex);

	// 弹出选择对话框让用户选择注入方式
	int nChoice = MessageBox(_T("选择注入方式:\n\n点击'是' - 使用可靠的CreateRemoteThread方式\n点击'否' - 使用改进的APC注入方式\n点击'取消' - 取消操作"),
		_T("选择注入方式"), MB_YESNOCANCEL | MB_ICONQUESTION);

	if (nChoice == IDYES)
	{
		// 使用直接CreateRemoteThread注入
		InjectDLLWithAPC(dwProcessID, m_strDllPath);
	}
	else if (nChoice == IDNO)
	{
		// 使用改进的APC注入
		InjectDLLWithAPCReliable(dwProcessID, m_strDllPath);
	}
}

bool CApplicationDlg::InjectDLLWithAPC(const DWORD processId, const wchar_t* dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL)
	{
		CString strError;
		strError.Format(_T("无法打开进程，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		return false;
	}

	// 计算DLL路径字符串长度（包括NULL结束符）
	SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

	// 在目标进程中分配内存用于DLL路径
	LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
	if (remoteMemory == NULL)
	{
		CString strError;
		strError.Format(_T("在目标进程中分配内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		CloseHandle(hProcess);
		return false;
	}

	// 将DLL路径写入目标进程内存
	if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, pathSize, NULL))
	{
		CString strError;
		strError.Format(_T("写入内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取LoadLibraryW函数地址
	PTHREAD_START_ROUTINE loadLibraryAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (loadLibraryAddr == NULL)
	{
		CString strError;
		strError.Format(_T("无法获取LoadLibraryW地址，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 创建一个远程线程来执行DLL加载
	// 这比APC更可靠，因为我们不依赖目标线程进入警告状态
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
		loadLibraryAddr, remoteMemory, 0, NULL);
	if (hRemoteThread == NULL)
	{
		CString strError;
		strError.Format(_T("创建远程线程失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 等待远程线程完成
	WaitForSingleObject(hRemoteThread, INFINITE);

	// 获取远程线程的退出码
	DWORD exitCode = 0;
	GetExitCodeThread(hRemoteThread, &exitCode);

	// 清理
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	if (exitCode == 0)
	{
		MessageBox(_T("DLL注入失败，LoadLibrary返回NULL"), _T("错误"), MB_ICONERROR);
		return false;
	}

	MessageBox(_T("DLL已成功注入到目标进程"), _T("成功"), MB_ICONINFORMATION);
	dllHandle = (HMODULE)exitCode;
	return true;
}

bool CApplicationDlg::InjectDLLWithAPCReliable(const DWORD processId, const wchar_t* dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL)
	{
		CString strError;
		strError.Format(_T("无法打开进程，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		return false;
	}

	// 计算DLL路径字符串长度
	SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

	// 在目标进程中分配内存用于DLL路径
	LPVOID dllPathMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
	if (dllPathMemory == NULL)
	{
		CString strError;
		strError.Format(_T("在目标进程中分配DLL路径内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		CloseHandle(hProcess);
		return false;
	}

	// 将DLL路径写入目标进程内存
	if (!WriteProcessMemory(hProcess, dllPathMemory, dllPath, pathSize, NULL))
	{
		CString strError;
		strError.Format(_T("写入内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 远程线程函数代码：进入可警告状态并等待APC
	const char sleepFuncCode[] =
		"\x48\x83\xEC\x28"              // sub rsp, 28h
		"\xBA\xFF\xFF\xFF\xFF"          // mov edx, 0FFFFFFFFh (INFINITE)
		"\xB9\x01\x00\x00\x00"          // mov ecx, 1 (TRUE - alertable)
		"\xFF\x15\x02\x00\x00\x00"      // call qword ptr [rip+2]
		"\xEB\xF0"                      // jmp short -16
		"\x00\x00\x00\x00\x00\x00\x00\x00"; // address placeholder for SleepEx

	// 分配内存用于远程线程代码
	SIZE_T codeSize = sizeof(sleepFuncCode) - 1;
	LPVOID remoteCodeMemory = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remoteCodeMemory == NULL)
	{
		CString strError;
		strError.Format(_T("在目标进程中分配代码内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 创建代码的副本，以便修改
	char* modifiedCode = new char[codeSize];
	memcpy(modifiedCode, sleepFuncCode, codeSize);

	// 获取SleepEx函数地址
	FARPROC sleepExAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SleepEx");
	if (sleepExAddr == NULL)
	{
		CString strError;
		strError.Format(_T("无法获取SleepEx地址，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		delete[] modifiedCode;
		VirtualFreeEx(hProcess, remoteCodeMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 修改代码，插入SleepEx函数地址
	*((FARPROC*)(modifiedCode + codeSize - sizeof(FARPROC))) = sleepExAddr;

	// 将修改后的代码写入目标进程
	if (!WriteProcessMemory(hProcess, remoteCodeMemory, modifiedCode, codeSize, NULL))
	{
		CString strError;
		strError.Format(_T("写入代码内存失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		delete[] modifiedCode;
		VirtualFreeEx(hProcess, remoteCodeMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	delete[] modifiedCode;

	// 创建远程线程执行代码
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeMemory, NULL, 0, NULL);
	if (hThread == NULL)
	{
		CString strError;
		strError.Format(_T("创建远程线程失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteCodeMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 等待线程启动
	Sleep(100);

	// 获取LoadLibraryW函数地址
	PTHREAD_START_ROUTINE loadLibraryAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (loadLibraryAddr == NULL)
	{
		CString strError;
		strError.Format(_T("无法获取LoadLibraryW地址，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, remoteCodeMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 将LoadLibraryW添加到APC队列
	DWORD queueStatus = QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)dllPathMemory);
	if (queueStatus == 0)
	{
		CString strError;
		strError.Format(_T("添加APC队列失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, remoteCodeMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, dllPathMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	MessageBox(_T("APC已成功排队，远程线程已创建，DLL将被加载"), _T("成功"), MB_ICONINFORMATION);

	// 注意：我们不关闭线程句柄或释放内存，因为它们需要保持存活
	// 如果需要，应用程序可以在稍后清理这些资源
	CloseHandle(hProcess);

	return true;
}

bool CApplicationDlg::GetThreadId(DWORD processId, DWORD& threadId)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;

	THREADENTRY32 threadEntry = { 0 };
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(snapshot, &threadEntry))
	{
		do {
			if (threadEntry.th32OwnerProcessID == processId)
			{
				threadId = threadEntry.th32ThreadID;
				CloseHandle(snapshot);
				return true;
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}

	CloseHandle(snapshot);
	return false;
}



void CApplicationDlg::OnBnClickedUnloadDLL()
{
	UpdateData(TRUE);
	if (dllHandle == 0)
	{
		CString strError;
		strError.Format(_T("Dll句柄为0，请检查是否成功注入，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		return;
	}

	int nSelectedIndex = m_comboProcesses.GetCurSel();
	if (nSelectedIndex == CB_ERR)
	{
		MessageBox(_T("请先选择一个目标进程！"), _T("错误"), MB_ICONERROR);
		return;
	}

	DWORD dwProcessID = (DWORD)m_comboProcesses.GetItemData(nSelectedIndex);
	UnloadDLLWithAPC(dwProcessID, dllHandle);
}


bool CApplicationDlg::UnloadDLLWithAPC(const DWORD processId, HMODULE hDllModule)
{
	// 打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL)
	{
		CString strError;
		strError.Format(_T("无法打开进程，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		return false;
	}

	// 获取FreeLibrary函数地址
	PTHREAD_START_ROUTINE freeLibraryAddr = (PTHREAD_START_ROUTINE)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"),
		"FreeLibrary"
	);

	if (freeLibraryAddr == NULL)
	{
		CString strError;
		strError.Format(_T("无法获取FreeLibrary地址，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		CloseHandle(hProcess);
		return false;
	}

	// 创建远程线程执行FreeLibrary
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
		freeLibraryAddr, (LPVOID)hDllModule, 0, NULL);

	if (hRemoteThread == NULL)
	{
		CString strError;
		strError.Format(_T("创建远程线程失败，错误码: %u"), GetLastError());
		MessageBox(strError, _T("错误"), MB_ICONERROR);
		CloseHandle(hProcess);
		return false;
	}

	// 等待远程线程完成
	WaitForSingleObject(hRemoteThread, INFINITE);

	// 获取线程退出码
	DWORD exitCode = 0;
	GetExitCodeThread(hRemoteThread, &exitCode);

	// 清理
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	if (exitCode == 0)
	{
		MessageBox(_T("DLL卸载失败"), _T("错误"), MB_ICONERROR);
		return false;
	}

	MessageBox(_T("DLL已成功从目标进程卸载"), _T("成功"), MB_ICONINFORMATION);
	return true;
}

void CApplicationDlg::OnBnClickedButton2()
{
	RefreshProcessList();
}
