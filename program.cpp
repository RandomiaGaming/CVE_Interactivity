#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <iostream>
#include <thread>
#include <chrono>
using namespace std;

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

void RestartInteractively() {
	// Get the session id of the current interactive session.
	DWORD sessionId = WTSGetActiveConsoleSessionId();

	// Get the token for the current user
	HANDLE userToken = NULL;
	WTSQueryUserToken(sessionId, &userToken);

	// Duplicate the user's token so we can use it.
	HANDLE userTokenCopy = NULL;
	DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &userTokenCopy);

	// Set up the startup info structure
	STARTUPINFO startupInfo = { sizeof(STARTUPINFO) };
	//const WCHAR* desktopConst = L"winsta0\\default";
	//WCHAR* desktop = new WCHAR[lstrlen(desktopConst)];
	//lstrcpy(desktop, desktopConst);
	//startupInfo.lpDesktop = desktop;
	PROCESS_INFORMATION processInfo = { };

	// Get the current executable path
	WCHAR exePath[MAX_PATH];
	GetModuleFileName(NULL, exePath, MAX_PATH);

	// Restart process in the user's session
	CreateProcessAsUser(
		userTokenCopy,
		exePath, // Application name
		NULL,   // Command line arguments
		NULL,   // Process attributes
		NULL,   // Thread attributes
		FALSE,  // Inherit handles
		CREATE_NEW_CONSOLE, // Creation flags
		NULL,   // Environment
		NULL,   // Current directory
		&startupInfo,
		&processInfo
	);

	// Cleanup and return
	CloseHandle(userToken);
	CloseHandle(userTokenCopy);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	return;
}

int main(int argc, char** argv) {
	cout << "Hello Interactive World!" << endl;

	this_thread::sleep_for(chrono::milliseconds(3000));

	system("start \"\" \"%comspec%\"");

	RestartInteractively();
}
