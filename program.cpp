#include "Helper.h"
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <iostream>
#include <thread>
#include <chrono>
using namespace std;

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

void AdjustPrivilege(LPCTSTR privilege, BOOL enable = TRUE)
{
	LUID luid;
	if (!LookupPrivilegeValue(NULL, privilege, &luid))
	{
		ThrowSysError();
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;
	if (enable) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}

	HANDLE currentToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentToken)) {
		ThrowSysError();
	}

	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		ThrowSysError();
	}
	// Required secondarry check because AdjustTokenPrivileges returns successful if some but not all permissions were adjusted.
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		ThrowSysError();
	}

	CloseHandle(currentToken);
}
BOOL IsInteractive() {
	HANDLE hToken = GetCurrentProcessToken();

	DWORD activeConsoleSessionId = WTSGetActiveConsoleSessionId();

	DWORD sessionId = 0;
	DWORD returnLength = 0;
	GetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId), &returnLength);

	CloseHandle(hToken);

	return (sessionId == activeConsoleSessionId);
}
HANDLE CreateInteractiveToken() {
	// Give the current process the "Assign primary tokens" permission.
	AdjustPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

	// Give current process the "Act as part of the operating system" permission.
	AdjustPrivilege(SE_TCB_NAME);

	// Open the current process.
	HANDLE currentProcess = GetCurrentProcess();

	// Open the current process token.
	HANDLE currentToken = NULL;
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) {
		ThrowSysError();
	}

	// Duplicate the current process token.
	HANDLE currentTokenCopy;
	if (!DuplicateTokenEx(currentToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &currentTokenCopy)) {
		ThrowSysError();
	}

	// Get current session id.
	DWORD sessionID = WTSGetActiveConsoleSessionId();

	// Change the session ID of the current process token copy to the current session ID.
	if (!SetTokenInformation(currentTokenCopy, TokenSessionId, &sessionID, sizeof(sessionID))) {
		ThrowSysError();
	}

	//Return and cleanup
	CloseHandle(currentToken);
	return currentTokenCopy;
}

void RestartInteractively() {
	// Get an interactive copy of the current token.
	HANDLE uiAccessToken = CreateInteractiveToken();

	// Launch the current process again with the new token.
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	GetStartupInfo(&si);
	CreateProcessAsUser(uiAccessToken, NULL, GetCommandLine(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	// Cleanup and return
	CloseHandle(uiAccessToken);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

int main(int argc, char** argv) {
	if (!IsInteractive()) {
		RestartInteractively();
	}

	return 0;
}