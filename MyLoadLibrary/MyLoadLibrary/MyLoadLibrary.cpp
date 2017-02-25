// MyLoadLibrary.cpp : �������̨Ӧ�ó������ڵ㡣
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

	//���ļ�����ӳ�䵽�ڴ���
	if (!MapDllFile(szDllPath, (ULONG_PTR*)&ulBaseAddress, &dwFileSize))
	{
		return FALSE;
	}
	
	//���PE�ļ�����Ч��
	if (!CheckDataValidity(ulBaseAddress, dwFileSize))
	{
		return FALSE;
	}

	//��������Ҫ�ļ��ؿռ�
	int iImageLength = CalcTotalImageSize();

	//���������ڴ�   �ú������Զ������뵽���ڴ��ʼ����0
	VOID* ImageData = VirtualAlloc(NULL, iImageLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (ImageData == NULL)
	{
		return FALSE;
	}
	else
	{
		CopyDllDatas(ImageData, ulBaseAddress);      //����DLL���ݣ�������ÿ����

		if (m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			DoRelocation(ImageData);     //�޸��ض����
		}

		if (!FixImportAddressTable(ImageData))    //���������
		{
			VirtualFree(ImageData, 0, MEM_RELEASE);
			return FALSE;
		}

		ULONG ulOld;
		VirtualProtect(ImageData, iImageLength, PAGE_EXECUTE_READWRITE, &ulOld);
	}

	//��������ַ
#ifdef WIN32
	m_NtHeader->OptionalHeader.ImageBase = (UINT32)ImageData;
#else
	m_NtHeader->OptionalHeader.ImageBase = (UINT64)ImageData;
#endif
	m_DllMain = (ProcDllMain)(m_NtHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)ImageData);

	BOOL bInitResult = m_DllMain((HINSTANCE)ImageData, DLL_PROCESS_ATTACH, 0);

	if (!bInitResult)     //��ʼ��ʧ��
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
		szDllPath,   //�ļ���  
		GENERIC_READ | GENERIC_WRITE, //���ļ����ж�д����  
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,  //���Ѵ����ļ�  
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
		PAGE_READWRITE | SEC_COMMIT,  //��ӳ���ļ����ж�д  
		0,
		0,			  //������������64λ������֧�ֵ�����ļ�����Ϊ16EB .������������4KB�ڴ棬Ϊ��д���µĵ�����������������һ�������������������0�Ϳ��ԡ�
		NULL);

	if (hMapFile == INVALID_HANDLE_VALUE)
	{
		printf("Can't create file mapping.Error%d:/n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	//���ļ�����ӳ�䵽���̵ĵ�ַ�ռ�  
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
	//��鳤��
	if (iBufferLength < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	m_DosHeader = (PIMAGE_DOS_HEADER)szBufferData;      //Dosͷ
														//���Dosͷ�ı��
	if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)    //0x5A4D    MZ
	{
		return FALSE;
	}

	//��鳤��
	if ((UINT32)iBufferLength < (m_DosHeader->e_lfanew + sizeof(IMAGE_DOS_HEADER)))
	{
		return FALSE;
	}

	//ȡ��PEͷ
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)szBufferData + m_DosHeader->e_lfanew);    //PEͷ
																					   //���PEͷ�ĺϷ���
	if (m_NtHeader->Signature != IMAGE_NT_SIGNATURE)    //0x00004550   PE00
	{
		return FALSE;
	}

	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)   //0x2000    FIle is a Dll
	{
		return FALSE;
	}

	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)  //0x0002   ָ���ļ���������
	{
		return FALSE;
	}

	if (m_NtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return FALSE;
	}

	//ȡ�ýڱ�(�α�)
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
	//��֤ÿ���ڱ�Ŀռ�
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

	int iMemoryAlign = m_NtHeader->OptionalHeader.SectionAlignment;   //�ζ����ֽ���

																	  //��������ͷ�ĳߴ磬����dos,coff,pe�Ͷα�Ĵ�С
	iLength = GetAlignedSize(m_NtHeader->OptionalHeader.SizeOfHeaders, iMemoryAlign);
	//�������нڵĴ�С
	for (int i = 0; i<m_NtHeader->FileHeader.NumberOfSections; ++i)
	{
		//�õ��ýڵĴ�С
		int iTureCodeSize = m_SectionHeader[i].Misc.VirtualSize;     //û�а����ļ����ڴ����ȶ���
		int iFileAlignCodeSize = m_SectionHeader[i].SizeOfRawData;   //�����ļ����ȶ���
		int iMaxSize = (iFileAlignCodeSize > iTureCodeSize) ? (iFileAlignCodeSize) : (iTureCodeSize);
		int iSectionSize = GetAlignedSize(m_SectionHeader[i].VirtualAddress + iMaxSize, iMemoryAlign);

		if (iLength < iSectionSize)
		{
			iLength = iSectionSize;   //Use the Max
		}
	}

	return iLength;
}

//�������߽�
int GetAlignedSize(int iOriginalData, int iAlignment)
{
	return (iOriginalData + iAlignment - 1) / iAlignment * iAlignment;
}

VOID CopyDllDatas(VOID* ImageData, VOID* BufferData)
{
	//������Ҫ���Ƶ�PEͷ+�α��ֽ���
	int iHeaderLength = m_NtHeader->OptionalHeader.SizeOfHeaders;

	int iCopyLength = iHeaderLength;

	//����ͷ�Ͷ���Ϣ
	memcpy(ImageData, BufferData, iCopyLength);

	//����ÿ����
	for (int i = 0; i<m_NtHeader->FileHeader.NumberOfSections; ++i)
	{
		if (m_SectionHeader[i].VirtualAddress == 0 || m_SectionHeader[i].SizeOfRawData == 0)
		{
			continue;
		}

		//����ý����ڴ��е�λ��
		VOID* SectionMemoryAddress = (VOID*)((PBYTE)ImageData + m_SectionHeader[i].VirtualAddress);

		//���ƶ����ݵ������ڴ�
		memcpy((VOID*)SectionMemoryAddress, (VOID*)((PBYTE)BufferData + m_SectionHeader[i].PointerToRawData),
			m_SectionHeader[i].SizeOfRawData);
	}

	//����ָ�룬ָ���·�����ڴ�
	//�µ�DOSͷ
	m_DosHeader = (PIMAGE_DOS_HEADER)ImageData;
	//�µ�PEͷ
	m_NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)ImageData + (m_DosHeader->e_lfanew));
	//�µĽڱ��ַ
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
}

VOID DoRelocation(VOID* ImageData)
{
	//����NewBase��0x600000,���ļ������õ�ȱʡImageBase��0x400000,������ƫ��������0x200000
	//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)ImageData +
		m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while ((BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
	{
		WORD *RelocationData = (WORD*)((PBYTE)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		//���㱾����Ҫ�������ض�λ��(��ַ)����Ŀ
		int iNumberOfRelocation = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < iNumberOfRelocation; i++)
		{
			// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
			// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�
			if ((DWORD)(RelocationData[i] & 0xF000) == 0x0000A000)
			{
				//64λDll�ض�λ��IMAGE_REL_BASED_DIR64
				//����IA-64�Ŀ�ִ���ļ����ض�λ�ƺ�����IMAGE_REL_BASED_DIR64���͵�
#ifdef _WIN64
				ULONGLONG* Address = (ULONGLONG*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
				ULONGLONG  ulDelta = (ULONGLONG)ImageData - m_NtHeader->OptionalHeader.ImageBase;
				*Address += ulDelta;
#endif
			}
			else if ((DWORD)(RelocationData[i] & 0xF000) == 0x00003000)
			{
				//32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
				//����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�
#ifndef _WIN64
				DWORD* Address = (DWORD*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
				DWORD  dwDelta = (DWORD)ImageData - m_NtHeader->OptionalHeader.ImageBase;
				*Address += dwDelta;
#endif
			}
		}
		//ת�Ƶ���һ���ڽ��д���
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
}

BOOL FixImportAddressTable(VOID* ImageData)
{
	ULONG ulOffset = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (ulOffset == 0)
	{
		return TRUE;    //û�е����
	}

	PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageData + ulOffset);

	while (ImageImportDescriptor->Characteristics != 0)
	{
		PIMAGE_THUNK_DATA FirstThunkData = (PIMAGE_THUNK_DATA)((PBYTE)ImageData + ImageImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA OriginalThunkData = (PIMAGE_THUNK_DATA)((PBYTE)ImageData + ImageImportDescriptor->OriginalFirstThunk);

		//��ȡDll������
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

			if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)  //�����ֵ�������ǵ������
			{
				FunctionAddress = GetProcAddress(hDll, (LPCSTR)(OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
			}
			else     //�����ֵ���
			{
				//��ȡ��IAT�������ӵĺ�������
				PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)ImageData + (OriginalThunkData[i].u1.AddressOfData));
				FunctionAddress = GetProcAddress(hDll, (char*)ImageImportByName->Name);
			}

			if (FunctionAddress != NULL)    //�ҵ���
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

		//�ƶ�����һ������ģ��
		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return TRUE;
}