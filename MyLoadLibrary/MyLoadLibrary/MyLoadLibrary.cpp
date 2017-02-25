// MyLoadLibrary.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>

PIMAGE_DOS_HEADER     m_DosHeader;
PIMAGE_NT_HEADERS     m_NtHeader;
PIMAGE_SECTION_HEADER m_SectionHeader;
PVOID                 m_ImageBase;

typedef   BOOL(__stdcall *ProcDllMain)(HINSTANCE, DWORD, LPVOID);

ProcDllMain m_DllMain;
BOOL        m_bIsLoadAlready;

BOOL MyLoadLibrary(char* szDllPath);
BOOL MapDllFile(char* szPath, ULONG_PTR* ulBaseAddress, DWORD* dwFileSize);
BOOL CheckDataValidity(VOID* szBufferData, int iBufferLength);
int GetAlignedSize(int iOriginalData, int iAlignment);
int CalcTotalImageSize();
VOID CopyDllDatas(VOID* ImageData, VOID* BufferData);
VOID DoRelocation(VOID* ImageData);
BOOL FixImportAddressTable(VOID* ImageData);

int main()
{
	if (!MyLoadLibrary("D:\\MyDll.dll"))
	{
		MessageBox(NULL, L"Error", L"Error", 0);
	}
	
	
    return 0;
}

BOOL MyLoadLibrary(char * szDllPath)
{
	VOID* ulBaseAddress = NULL;
	DWORD	  dwFileSize = 0;

	//将文件数据映射到内存中
	if (!MapDllFile(szDllPath, (ULONG_PTR*)&ulBaseAddress, &dwFileSize))
	{
		return FALSE;
	}
	
	//检查PE文件的有效性
	if (!CheckDataValidity(ulBaseAddress, dwFileSize))
	{
		return FALSE;
	}

	//计算所需要的加载空间
	int iImageLength = CalcTotalImageSize();

	//分配虚拟内存   该函数会自动将申请到的内存初始化成0
	VOID* ImageData = VirtualAlloc(NULL, iImageLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (ImageData == NULL)
	{
		return FALSE;
	}
	else
	{
		CopyDllDatas(ImageData, ulBaseAddress);      //复制DLL数据，并对其每个段

		if (m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			DoRelocation(ImageData);     //修复重定向表
		}

		if (!FixImportAddressTable(ImageData))    //修正导入表
		{
			VirtualFree(ImageData, 0, MEM_RELEASE);
			return FALSE;
		}

		ULONG ulOld;
		VirtualProtect(ImageData, iImageLength, PAGE_EXECUTE_READWRITE, &ulOld);
	}

	//修正基地址
#ifdef WIN32
	m_NtHeader->OptionalHeader.ImageBase = (UINT32)ImageData;
#else
	m_NtHeader->OptionalHeader.ImageBase = (UINT64)ImageData;
#endif
	m_DllMain = (ProcDllMain)(m_NtHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)ImageData);

	BOOL bInitResult = m_DllMain((HINSTANCE)ImageData, DLL_PROCESS_ATTACH, 0);

	if (!bInitResult)     //初始化失败
	{
		m_DllMain((HINSTANCE)ImageData, DLL_PROCESS_DETACH, 0);
		VirtualFree(ImageData, 0, MEM_RELEASE);
		m_DllMain = NULL;
		return FALSE;
	}

	m_bIsLoadAlready = TRUE;
	m_ImageBase = ImageData;
	return TRUE;
}

BOOL MapDllFile(char* szDllPath, ULONG_PTR* ulBaseAddress,DWORD* dwFileSize)
{
	HANDLE hFile = CreateFileA(
		szDllPath,   //文件名  
		GENERIC_READ | GENERIC_WRITE, //对文件进行读写操作  
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,  //打开已存在文件  
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Not exsit\r\n");
		return FALSE;
	}

	*dwFileSize = GetFileSize(hFile, NULL);

	HANDLE hMapFile = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READWRITE | SEC_COMMIT,  //对映射文件进行读写  
		0,
		0,			  //这两个参数共64位，所以支持的最大文件长度为16EB .这里往后申请4KB内存，为了写入新的导入表。保险起见，上面一个参数和这个参数都传0就可以。
		NULL);

	if (hMapFile == INVALID_HANDLE_VALUE)
	{
		printf("Can't create file mapping.Error%d:/n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	//把文件数据映射到进程的地址空间  
	void* pvFile = MapViewOfFile(
		hMapFile,
		FILE_MAP_READ | FILE_MAP_WRITE,
		0,
		0,
		0);
	if (pvFile == NULL)
	{
		CloseHandle(hFile);
		CloseHandle(hMapFile);
		return FALSE;
	}

	*ulBaseAddress = (ULONG_PTR)pvFile;
	return TRUE;
}

BOOL CheckDataValidity(VOID* szBufferData, int iBufferLength)
{
	//检查长度
	if (iBufferLength < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	m_DosHeader = (PIMAGE_DOS_HEADER)szBufferData;      //Dos头
														//检查Dos头的标记
	if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)    //0x5A4D    MZ
	{
		return FALSE;
	}

	//检查长度
	if ((UINT32)iBufferLength < (m_DosHeader->e_lfanew + sizeof(IMAGE_DOS_HEADER)))
	{
		return FALSE;
	}

	//取得PE头
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)szBufferData + m_DosHeader->e_lfanew);    //PE头
																					   //检查PE头的合法性
	if (m_NtHeader->Signature != IMAGE_NT_SIGNATURE)    //0x00004550   PE00
	{
		return FALSE;
	}

	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)   //0x2000    FIle is a Dll
	{
		return FALSE;
	}

	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)  //0x0002   指出文件可以运行
	{
		return FALSE;
	}

	if (m_NtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return FALSE;
	}

	//取得节表(段表)
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
	//验证每个节表的空间
	for (int i = 0; i<m_NtHeader->FileHeader.NumberOfSections; i++)
	{
		if ((m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData) >(DWORD)iBufferLength)
		{
			return FALSE;
		}
	}
	return TRUE;
}

int CalcTotalImageSize()
{
	int iLength = 0;

	if (m_NtHeader == NULL)
	{
		return 0;
	}

	int iMemoryAlign = m_NtHeader->OptionalHeader.SectionAlignment;   //段对齐字节数

																	  //计算所有头的尺寸，包括dos,coff,pe和段表的大小
	iLength = GetAlignedSize(m_NtHeader->OptionalHeader.SizeOfHeaders, iMemoryAlign);
	//计算所有节的大小
	for (int i = 0; i<m_NtHeader->FileHeader.NumberOfSections; ++i)
	{
		//得到该节的大小
		int iTureCodeSize = m_SectionHeader[i].Misc.VirtualSize;     //没有按照文件和内存粒度对齐
		int iFileAlignCodeSize = m_SectionHeader[i].SizeOfRawData;   //按照文件粒度对齐
		int iMaxSize = (iFileAlignCodeSize > iTureCodeSize) ? (iFileAlignCodeSize) : (iTureCodeSize);
		int iSectionSize = GetAlignedSize(m_SectionHeader[i].VirtualAddress + iMaxSize, iMemoryAlign);

		if (iLength < iSectionSize)
		{
			iLength = iSectionSize;   //Use the Max
		}
	}

	return iLength;
}

//计算对齐边界
int GetAlignedSize(int iOriginalData, int iAlignment)
{
	return (iOriginalData + iAlignment - 1) / iAlignment * iAlignment;
}

VOID CopyDllDatas(VOID* ImageData, VOID* BufferData)
{
	//计算需要复制的PE头+段表字节数
	int iHeaderLength = m_NtHeader->OptionalHeader.SizeOfHeaders;

	int iCopyLength = iHeaderLength;

	//复制头和段信息
	memcpy(ImageData, BufferData, iCopyLength);

	//复制每个节
	for (int i = 0; i<m_NtHeader->FileHeader.NumberOfSections; ++i)
	{
		if (m_SectionHeader[i].VirtualAddress == 0 || m_SectionHeader[i].SizeOfRawData == 0)
		{
			continue;
		}

		//定义该节在内存中的位置
		VOID* SectionMemoryAddress = (VOID*)((PBYTE)ImageData + m_SectionHeader[i].VirtualAddress);

		//复制段数据到虚拟内存
		memcpy((VOID*)SectionMemoryAddress, (VOID*)((PBYTE)BufferData + m_SectionHeader[i].PointerToRawData),
			m_SectionHeader[i].SizeOfRawData);
	}

	//修正指针，指向新分配的内存
	//新的DOS头
	m_DosHeader = (PIMAGE_DOS_HEADER)ImageData;
	//新的PE头
	m_NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)ImageData + (m_DosHeader->e_lfanew));
	//新的节表地址
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
}

VOID DoRelocation(VOID* ImageData)
{
	//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
	//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)ImageData +
		m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while ((BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock) != 0) //开始扫描重定位表
	{
		WORD *RelocationData = (WORD*)((PBYTE)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		//计算本节需要修正的重定位项(地址)的数目
		int iNumberOfRelocation = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < iNumberOfRelocation; i++)
		{
			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。
			if ((DWORD)(RelocationData[i] & 0xF000) == 0x0000A000)
			{
				//64位Dll重定位，IMAGE_REL_BASED_DIR64
				//对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的
#ifdef _WIN64
				ULONGLONG* Address = (ULONGLONG*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
				ULONGLONG  ulDelta = (ULONGLONG)ImageData - m_NtHeader->OptionalHeader.ImageBase;
				*Address += ulDelta;
#endif
			}
			else if ((DWORD)(RelocationData[i] & 0xF000) == 0x00003000)
			{
				//32位dll重定位，IMAGE_REL_BASED_HIGHLOW
				//对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
#ifndef _WIN64
				DWORD* Address = (DWORD*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
				DWORD  dwDelta = (DWORD)ImageData - m_NtHeader->OptionalHeader.ImageBase;
				*Address += dwDelta;
#endif
			}
		}
		//转移到下一个节进行处理
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
}

BOOL FixImportAddressTable(VOID* ImageData)
{
	ULONG ulOffset = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (ulOffset == 0)
	{
		return TRUE;    //没有导入表
	}

	PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageData + ulOffset);

	while (ImageImportDescriptor->Characteristics != 0)
	{
		PIMAGE_THUNK_DATA FirstThunkData = (PIMAGE_THUNK_DATA)((PBYTE)ImageData + ImageImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA OriginalThunkData = (PIMAGE_THUNK_DATA)((PBYTE)ImageData + ImageImportDescriptor->OriginalFirstThunk);

		//获取Dll的名字
		char szDllName[256] = { 0 };
		BYTE* bName = (BYTE*)((PBYTE)ImageData + ImageImportDescriptor->Name);
		int i = 0;
		for (i = 0; i<256; i++)
		{
			if (bName[i] == 0)
			{
				break;
			}
			szDllName[i] = bName[i];
		}
		if (i > 256)
		{
			return FALSE;
		}
		else
		{
			szDllName[i] = 0;
		}

		HMODULE hDll = GetModuleHandleA(szDllName);
		int a = GetLastError();

		if (hDll == NULL)
		{
			return FALSE;
		}

		for (i = 0;; i++)
		{
			if (OriginalThunkData[i].u1.Function == 0)
			{
				break;
			}

			FARPROC FunctionAddress = NULL;

			if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)  //这里的值给出的是导出序号
			{
				FunctionAddress = GetProcAddress(hDll, (LPCSTR)(OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
			}
			else     //按名字导出
			{
				//获取此IAT项所藐视的函数名称
				PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)ImageData + (OriginalThunkData[i].u1.AddressOfData));
				FunctionAddress = GetProcAddress(hDll, (char*)ImageImportByName->Name);
			}

			if (FunctionAddress != NULL)    //找到了
			{
#ifdef _WIN64
				FirstThunkData[i].u1.Function = (ULONGLONG)FunctionAddress;
#else
				FirstThunkData[i].u1.Function = (DWORD)FunctionAddress;
#endif
			}
			else
			{
				return FALSE;
			}
		}

		//移动到下一个导入模块
		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return TRUE;
}