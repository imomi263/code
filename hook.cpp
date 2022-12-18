#include<iostream>
#include<Windows.h>
#include<stdio.h>
#include<vector>
#include<tlhelp32.h>
#include<string.h>
#include <mbstring.h>
using namespace std;
//bool Inject(DWORD dwid ) {
//	char szPath[] = "Dll1.dll";
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwid);
//	LPVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, sizeof(szPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	bool a=WriteProcessMemory(hProcess, pRemoteAddress, szPath,sizeof(szPath), NULL);
//	if (a) {
//		printf("111\n");
//	}
//	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteAddress, 0, 0);
//	CloseHandle(hProcess);
//	return true;
//}
//int main() {
//	
//	DWORD dwid = 0;
//	HWND hCalc = FindWindow(NULL, L"11");
//	if (hCalc == NULL) {
//		MessageBox(NULL, L"获取窗口句柄失败！", L"提示", MB_OK);
//	}
//	DWORD dwPid = 0;
//	DWORD dwRub = GetWindowThreadProcessId(hCalc, &dwPid);
//	if (dwPid == NULL) {
//		MessageBox(NULL, L"获取目标进程pid失败！", L"提示", MB_OK);
//	}
//	Inject(dwPid);
//	system("pause");
//	return 0;
//}
DWORD FindProcess(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_stricmp((char*)szProcessName, (char*)pe.szExeFile))
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe));
	CloseHandle(hSnapShot);
	return dwPID;
}

//void inject() {
//	DWORD dwProcess;
//	char myDLL[] = "D:\\vs2022\\Project2\\Debug\\1.dll";
//	vector<DWORD>tid;
//	DWORD id = FindProcess(L"11.exe");
//	printf("%d\n", id);
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
//	LPVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	bool a=WriteProcessMemory(hProcess, pRemoteAddress, myDLL,sizeof(myDLL), NULL);
//	
//	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteAddress, 0, 0);
//	CloseHandle(hProcess);
//}
int inject() {
	HWND hwnd = FindWindow(NULL, L"FlappyBird");
	if (hwnd == NULL) {
		return EXIT_FAILURE;
	}
	
	DWORD pid = NULL;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	if (tid == NULL) {
		return EXIT_FAILURE;
	}
	printf("pid=%d\n", tid);
	HMODULE dll = LoadLibraryEx(L"Dll1.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (dll == NULL) {
		return EXIT_FAILURE;
	}
	printf("dll=%p\n", dll);
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook");
	if (addr == NULL) {
		return EXIT_FAILURE;
	}
	printf("addr=%p\n", addr);
	HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid);
	if (handle == NULL) {
		return EXIT_FAILURE;
	}
	PostThreadMessageW(tid, WM_NULL, NULL, NULL);
	getchar();
	BOOL unhook = UnhookWindowsHookEx(handle);
	if (unhook == FALSE) {
		return EXIT_FAILURE;
	}

}
int main() {
	inject();
	return 0;
}
