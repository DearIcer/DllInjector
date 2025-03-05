
// ApplicationDlg.h: 头文件
//

#pragma once


// CApplicationDlg 对话框
class CApplicationDlg : public CDialogEx
{
// 构造
public:
	CApplicationDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_APPLICATION_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CButton m_btnBrowse;
	CEdit m_editDllPath;
	CString m_strDllPath;
	HMODULE dllHandle = 0;
	afx_msg void OnBnClickedButtonBrowse();

	void RefreshProcessList();
	CComboBox m_comboProcesses;

	afx_msg void OnBnClickedInjector();

private:
	bool InjectDLLWithAPC(const DWORD processId, const wchar_t* dllPath);
	bool InjectDLLWithAPCReliable(const DWORD processId, const wchar_t* dllPath);
	bool GetThreadId(DWORD processId, DWORD& threadId);
	bool UnloadDLLWithAPC(const DWORD processId, HMODULE hDllModule);
public:
	
	afx_msg void OnBnClickedUnloadDLL();
	afx_msg void OnBnClickedButton2();
};
