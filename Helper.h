#pragma once
#include <Windows.h>

class Error {
public:
	enum class ErrorDisposal {
		Delete = 0, // Error message buffer is freed with C++ style delete[].
		Free = 1, // Error message buffer is freed with C-Style free(void* _Block) function.
		LocalFree = 3, // Message buffer is freed with Win32 API LocalFree(HLOCAL hMem) from WinBase.h.
	};

	Error(LPCWSTR message);
	Error(LPCSTR message);
	Error(LPWSTR message, ErrorDisposal disposal = ErrorDisposal::Delete);
	Error(LPSTR message, ErrorDisposal disposal = ErrorDisposal::Delete);
	void PrintAndFree();
	~Error();

private:
	BOOL _wideMessage = TRUE;
	BOOL _constMessage = TRUE;
	ErrorDisposal _disposal = ErrorDisposal::Delete;
	void* _message = NULL;
};

enum class ConsoleColor : WORD {
	Black = 0,
	DarkRed = FOREGROUND_RED,
	DarkGreen = FOREGROUND_GREEN,
	DarkBlue = FOREGROUND_BLUE,
	DarkYellow = FOREGROUND_RED | FOREGROUND_GREEN,
	DarkCyan = FOREGROUND_GREEN | FOREGROUND_BLUE,
	DarkMagenta = FOREGROUND_RED | FOREGROUND_BLUE,
	DarkGrey = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	Grey = FOREGROUND_INTENSITY,
	Red = FOREGROUND_RED | FOREGROUND_INTENSITY,
	Green = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	Blue = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	Yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	Cyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	Magenta = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	White = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
};

void PrintError(LPCWSTR errorMessage);
void PrintError(LPCSTR errorMessage);
void PrintWarning(LPCWSTR warningMessage);
void PrintWarning(LPCSTR warningMessage);
void PrintInColor(LPCWSTR message, ConsoleColor color);
void PrintInColor(LPCSTR message, ConsoleColor color);
void PrintInternal(HANDLE consoleHandle, const void* message, DWORD messageLength, ConsoleColor color);

void PressAnyKey();
void ThrowSysError();
void ThrowSysError(HRESULT hResult);
void ThrowSysError(DWORD errorCode);