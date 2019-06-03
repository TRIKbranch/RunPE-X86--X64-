# RunPE-X86--X64-
With this RunPE you can easily inject your payload in any x86 or x64 program.

There are two funcs. First is RunPE which needs an image of PE file, then it needs a path to the target program.

Here is a definition of func:
int	Inject::RunPE(void* lpFile, wchar_t* path, DWORD szFile, LPWSTR args);

The second func is to inject some itself.
int	Inject::RunPESelf(void* lpFile, DWORD szFile, LPWSTR args);
