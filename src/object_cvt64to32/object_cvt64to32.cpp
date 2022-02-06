#include <Windows.h>
#include <stdio.h>


#pragma comment(linker, "/merge:.rdata=.text")

int main()
{
	int nArgs = 0;
	WCHAR** args = CommandLineToArgvW(GetCommandLine(), &nArgs);
	if (nArgs < 2)
	{
		wprintf(L"\nwobj64.exe <filename.obj> [/nofeat]\n\n\n"
			L"Modifies specified x64 OBJ file to make it linkable into x32 libs\n"
			L"and applications.\n\n\n"
			L"Target file shall be compiled without \"link-time code generation\" option.\n\n");
		return -1;
	}
	bool safeseh = true;
	if (nArgs > 2 && _wcsicmp(args[2], L"/nofeat") == 0)
		safeseh = false;

	HANDLE hFile = CreateFile(args[1], GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"%s : error %d: Unable to open file\n", args[1], GetLastError());
		return -1;
	}

	HANDLE hSection = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	CloseHandle(hFile);

	PIMAGE_FILE_HEADER view = PIMAGE_FILE_HEADER(
		MapViewOfFile(hSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
	CloseHandle(hSection);

	if (!view)
	{
		wprintf(L"%s : error : Unable to map file\n", args[1]);
		return -1;
	}

	if (view->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		int rez = 0;
		if (view->Machine == IMAGE_FILE_MACHINE_I386)
			wprintf(L"%s : MachineType of file is already '014C' (x32).\n", args[1]);
		else
		{
			wprintf(L"%s : warning : MachineType of file is '%.4x', expected '8664'.\n", args[1], view->Machine);
			rez = -1;
		}

		UnmapViewOfFile(view);
		return rez;
	}

	int rez = 0;
	UINT nFixups = 0;
	UINT nFixdowns = 0;
	__try
	{
		PIMAGE_SECTION_HEADER section = PIMAGE_SECTION_HEADER(view + 1);
		for (DWORD i = 0, nSections = view->NumberOfSections; i < nSections; ++i)
		{
			if (!memcmp(&section[i].Name, ".pdata\0", 8) ||
				!memcmp(&section[i].Name, ".xdata\0", 8))
			{
				//
				// Functions metadata. Can't use it in x32.
				//
				section[i].PointerToRawData = 0;
				section[i].SizeOfRawData = 0;
				section[i].PointerToRelocations = 0;
				section[i].NumberOfRelocations = 0;
				continue;
			}
			PIMAGE_RELOCATION relocs = PIMAGE_RELOCATION(PCHAR(view) + section[i].PointerToRelocations);
			for (DWORD j = 0, nRelocs = section[i].NumberOfRelocations; j < nRelocs; ++j)
			{
				//
				// Replace link-time fixups for x64 with equivalents for x32
				//
				++nFixups;
				if (relocs[j].Type == IMAGE_REL_AMD64_ADDR32)
				{
					relocs[j].Type = IMAGE_REL_I386_DIR32;
				}
				else if (relocs[j].Type == IMAGE_REL_AMD64_ADDR64)
				{
					relocs[j].Type = IMAGE_REL_I386_DIR32;
				}
				else if (relocs[j].Type == IMAGE_REL_AMD64_ADDR32NB)
				{
					relocs[j].Type = IMAGE_REL_I386_DIR32NB;
				}
				else if (relocs[j].Type == IMAGE_REL_AMD64_REL32)
				{
					relocs[j].Type = IMAGE_REL_I386_REL32;
				}
				else if (
					relocs[j].Type >= IMAGE_REL_AMD64_REL32_1 &&
					relocs[j].Type <= IMAGE_REL_AMD64_REL32_5)
				{
					//wprintf(L"IMAGE_REL_AMD64_REL32_X; type: %04x, va: %x\n", relocs[j].Type, relocs[j].VirtualAddress);
					*PDWORD(PBYTE(view) + section[i].PointerToRawData +
						relocs[j].VirtualAddress) -= relocs[j].Type - IMAGE_REL_AMD64_REL32;
					relocs[j].Type = IMAGE_REL_I386_REL32;
				}
				else
					++nFixdowns;
			}
		}
		view->Machine = IMAGE_FILE_MACHINE_I386;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		wprintf(L"%s : error : Exception processing file. File left in undefined state.\n", args[1]);
		rez = GetExceptionCode();
	}

	// find @feat symbol and set bit0 to indicate this unit has /safeseh
	DWORD featSet = 0;
	__try
	{
		if (!safeseh)
			__leave;
		DWORD symOffset = view->PointerToSymbolTable;
		DWORD symCount = view->NumberOfSymbols;
		PIMAGE_SYMBOL sym = PIMAGE_SYMBOL(PBYTE(view) + symOffset);
		for (DWORD i = 0; i < symCount; ++i, sym = PIMAGE_SYMBOL(PBYTE(sym) + IMAGE_SIZEOF_SYMBOL))
		{
			// we ignore aux symbols; if they present, we just roll them over (expecting no clashes with @feat)
			if (sym->SectionNumber != -1 || sym->Type != 0)
				continue;
			if (sym->StorageClass != IMAGE_SYM_CLASS_STATIC || sym->NumberOfAuxSymbols != 0)
				continue;
			if (strncmp((CHAR*)sym->N.ShortName, "@feat.00", 8) != 0)
				continue;
			sym->Value |= 1;        // set bit0
			featSet += 1;
			break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		wprintf(L"%s : error : Exception processing @feat.00. File left in undefined state.\n", args[1]);
		rez = GetExceptionCode();
	}

	wprintf(L"%s : found %u fixups, fixed %u, skipped %u; @feat.00 set: %u\n",
		args[1], nFixups, nFixups - nFixdowns, nFixdowns, featSet);

	UnmapViewOfFile(view);
	LocalFree(HLOCAL(args));

	return 0;// rez;
}