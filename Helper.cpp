#include "Helper.h"
#include <Windows.h>
#include <comdef.h>

// These handles are global to the entire process and all threads.
// Do not call CloseHandle for these handles as they will be perminantly closed for the entire process.
const HANDLE InputHandle = GetStdHandle(STD_INPUT_HANDLE);
const HANDLE OutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
const HANDLE ErrorHandle = GetStdHandle(STD_ERROR_HANDLE);

Error::Error(LPCWSTR message) {
	_wideMessage = TRUE;
	_constMessage = TRUE;
	_disposal = ErrorDisposal::Delete;
	_message = const_cast<void*>(reinterpret_cast<const void*>(message));
}
Error::Error(LPCSTR message) {
	_wideMessage = FALSE;
	_constMessage = TRUE;
	_disposal = ErrorDisposal::Delete;
	_message = const_cast<void*>(reinterpret_cast<const void*>(message));
}
Error::Error(LPWSTR message, ErrorDisposal disposal) {
	_wideMessage = TRUE;
	_constMessage = FALSE;
	_disposal = disposal;
	_message = const_cast<void*>(reinterpret_cast<const void*>(message));
}
Error::Error(LPSTR message, ErrorDisposal disposal) {
	_wideMessage = FALSE;
	_constMessage = FALSE;
	_disposal = disposal;
	_message = const_cast<void*>(reinterpret_cast<const void*>(message));
}
void Error::PrintAndFree() {
	PrintInColor(L"ERROR: ", ConsoleColor::Red);
	if (_wideMessage) {
		PrintInColor(reinterpret_cast<LPWSTR>(_message), ConsoleColor::Red);
	}
	else {
		PrintInColor(reinterpret_cast<LPSTR>(_message), ConsoleColor::Red);
	}
	if (!_constMessage) {
		switch (_disposal) {
		case ErrorDisposal::Free:
			free(const_cast<void*>(_message));
			break;
		case ErrorDisposal::Delete:
			delete[] const_cast<void*>(_message);
			break;
		case ErrorDisposal::LocalFree:
			::LocalFree(const_cast<void*>(_message));
			break;
		default: break;
		}
	}
}
Error::~Error() {
	_wideMessage = FALSE;
	_constMessage = FALSE;
	_disposal = ErrorDisposal::Delete;
	_message = nullptr;
}

void PrintError(LPCWSTR errorMessage) {
	PrintInternal(ErrorHandle, L"ERROR: ", 7, ConsoleColor::Red);
	PrintInternal(ErrorHandle, errorMessage, lstrlen(errorMessage), ConsoleColor::Red);
}
void PrintError(LPCSTR errorMessage) {
	PrintInternal(ErrorHandle, "ERROR: ", 7, ConsoleColor::Red);
	PrintInternal(ErrorHandle, errorMessage, strlen(errorMessage), ConsoleColor::Red);
}
void PrintWarning(LPCWSTR warningMessage) {
	PrintInternal(OutputHandle, L"Warning: ", 9, ConsoleColor::Yellow);
	PrintInternal(OutputHandle, warningMessage, lstrlen(warningMessage), ConsoleColor::Yellow);
}
void PrintWarning(LPCSTR warningMessage) {
	PrintInternal(OutputHandle, "Warning: ", 9, ConsoleColor::Yellow);
	PrintInternal(OutputHandle, warningMessage, strlen(warningMessage), ConsoleColor::Yellow);
}
void PrintInColor(LPCWSTR message, ConsoleColor color) {
	PrintInternal(OutputHandle, message, lstrlen(message), color);
}
void PrintInColor(LPCSTR message, ConsoleColor color) {
	PrintInternal(OutputHandle, message, strlen(message), color);
}
void PrintInternal(HANDLE consoleHandle, const void* message, DWORD messageLength, ConsoleColor color) {
	// Get initial console color.
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(consoleHandle, &consoleInfo);
	WORD originalColor = consoleInfo.wAttributes;

	// Set console color.
	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(color));

	// Print warning message.
	DWORD charsWritten;
	WriteConsole(consoleHandle, message, messageLength, &charsWritten, NULL);

	// Restore initial console attributes.
	SetConsoleTextAttribute(consoleHandle, originalColor);
}

void PressAnyKey() {
	DWORD originalConsoleMode;
	GetConsoleMode(InputHandle, &originalConsoleMode);

	SetConsoleMode(InputHandle, originalConsoleMode & ~ENABLE_ECHO_INPUT);

	INPUT_RECORD irInBuf[1];
	DWORD cNumRead;
	char ch = '\0';
	while (true) {
		if (ReadConsoleInput(InputHandle, irInBuf, 1, &cNumRead)) {
			if (irInBuf[0].EventType == KEY_EVENT) {
				KEY_EVENT_RECORD ker = irInBuf[0].Event.KeyEvent;
				if (ker.bKeyDown && !(ker.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED | SHIFT_PRESSED | NUMLOCK_ON | SCROLLLOCK_ON | CAPSLOCK_ON))) {
					ch = ker.uChar.AsciiChar;
					break;
				}
			}
		}
	}

	SetConsoleMode(InputHandle, originalConsoleMode);
}
void ThrowSysError() {
	ThrowSysError(GetLastError());
}
void ThrowSysError(HRESULT hResult) {
	if (SUCCEEDED(hResult)) {
		return;
	}

	WCHAR* errorMessage = nullptr;
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, hResult, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorMessage, 0, NULL) > 0) {
		throw Error(errorMessage, Error::ErrorDisposal::LocalFree);
	}
	else {
		_com_error comError(hResult);
		LPCWSTR comErrorMessage = comError.ErrorMessage();

		constexpr const WCHAR* unknownError = L"Unknown error";
		for (int i = 0; unknownError[i] != '\0'; i++)
		{
			if (comErrorMessage[i] != unknownError[i]) {
				goto comErrorKnown;
			}
		}
		{
			WORD code = HRESULT_CODE(hResult);
			throw Error(L"Unknown com error with code: " + code);
		}

	comErrorKnown:
		errorMessage = new WCHAR[lstrlen(comErrorMessage)];
		lstrcpy(errorMessage, comErrorMessage);
		throw Error(errorMessage, Error::ErrorDisposal::Delete);
	}
}
void ThrowSysError(DWORD errorCode) {
	if (errorCode == 0) {
		return;
	}

	WCHAR* errorMessage = nullptr;
	DWORD size = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorMessage, 0, NULL);

	throw Error(errorMessage, Error::ErrorDisposal::LocalFree);
}