#include "stdafx.h"
#include "include/plugin.h"

#define DEF_NAME      L"Symbols on Demand"
#define DEF_VERSION   L"1.0"
#define DEF_COPYRIGHT L"Copyright (C) 2015 RaMMicHaeL"

HINSTANCE hInst;
BOOL bDisableAutoLoadSymbols;

BOOL PatchMemory(void *pDest, void *pSrc, size_t nSize)
{
	DWORD dwOldProtect;
	if(VirtualProtect(pDest, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		CopyMemory(pDest, pSrc, nSize);

		DWORD dwOtherProtect;
		if(VirtualProtect(pDest, nSize, dwOldProtect, &dwOtherProtect))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL CheckBytesForPatching()
{
	// 004C9A79 | 75 07         JNZ SHORT ollydbg.004C9A82
	if(*(BYTE *)0x004C9A79 != 0x75 || *(BYTE *)0x004C9A7A != 0x07)
	{
		return FALSE;
	}

	// 004C9CF9 | 74 72         JE SHORT ollydbg.004C9D6D
	if(*(BYTE *)0x004C9CF9 != 0x74 || *(BYTE *)0x004C9CFA != 0x72)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL PatchDisableDebuggingData(BOOL bDisable)
{
	// Check for original bytes.
	if(*(BYTE *)0x004C9A79 != 0x75 || 
		(*(BYTE *)0x004C9A7A != 0x07 && *(BYTE *)0x004C9A7A != 0x00))
	{
		return FALSE;
	}

	if((*(BYTE *)0x004C9CF9 != 0x74 && *(BYTE *)0x004C9CF9 != 0xEB) ||
		*(BYTE *)0x004C9CFA != 0x72)
	{
		return FALSE;
	}

	// 004C9A79 | 75 07         JNZ SHORT ollydbg.004C9A82
	BOOL bPatchByte1 = bDisable ? 0x00 : 0x07;

	if(!PatchMemory((void *)0x004C9A7A, &bPatchByte1, 1))
	{
		return FALSE;
	}

	// 004C9CF9 | 74 72         JE SHORT ollydbg.004C9D6D
	BOOL bPatchByte2 = bDisable ? 0xEB : 0x74;

	if(!PatchMemory((void *)0x004C9CF9, &bPatchByte2, 1))
	{
		return FALSE;
	}

	return TRUE;
}

void LoadCurrentModuleSymbols()
{
	if(run.status == STAT_IDLE)
	{
		WCHAR *pMessage = L"No process is loaded";

		Flash(L"%s", pMessage);
		Addtolist(0, DRAW_NORMAL, DEF_NAME L": %s", pMessage);
		return;
	}

	DWORD dwDisasmSelection = Getcpudisasmselection();

	t_module *pModule = Findmodule(dwDisasmSelection);
	if(!pModule)
	{
		WCHAR szMessage[64];
		wsprintf(szMessage, L"Could not find module on address %08X", dwDisasmSelection);

		Flash(L"%s", szMessage);
		Addtolist(0, 0, DEF_NAME L": %s", szMessage);
		return;
	}

	if(pModule->type & MOD_DBGDATA)
	{
		WCHAR szMessage[64];
		wsprintf(szMessage, L"Symbols were already loaded for %s", pModule->modname);

		Flash(L"%s", szMessage);
		Addtolist(0, 0, DEF_NAME L": %s", szMessage);
		return;
	}

	int result = ((int(__cdecl *)(DWORD, DWORD, WCHAR *, WCHAR *))0x004C9A60)(pModule->base, pModule->size, pModule->path, pModule->modname);
	if(result > 0)
	{
		pModule->type |= MOD_DBGDATA;

		((void(__cdecl *)(t_module *))0x004C9CE8)(pModule);

		Mergequickdata();
	}

	Redrawcpudisasm();

	WCHAR szMessage[64];
	if(result > 0)
	{
		wsprintf(szMessage, L"Symbols were successfully loaded for %s", pModule->modname);
	}
	else
	{
		wsprintf(szMessage, L"No symbols were loaded for %s", pModule->modname);
	}

	Flash(L"%s", szMessage);
	Addtolist(0, 0, DEF_NAME L": %s", szMessage);
}

void ClearCurrentModuleSymbols()
{
	if(run.status == STAT_IDLE)
	{
		WCHAR *pMessage = L"No process is loaded";

		Flash(L"%s", pMessage);
		Addtolist(0, DRAW_NORMAL, DEF_NAME L": %s", pMessage);
		return;
	}

	DWORD dwDisasmSelection = Getcpudisasmselection();

	t_module *pModule = Findmodule(dwDisasmSelection);
	if(!pModule)
	{
		WCHAR szMessage[64];
		wsprintf(szMessage, L"Could not find module on address %08X", dwDisasmSelection);

		Flash(L"%s", szMessage);
		Addtolist(0, 0, DEF_NAME L": %s", szMessage);
		return;
	}

	Deletedatarange(pModule->base, pModule->base + pModule->size, NM_DEBUG, NM_DEDEBUG, DT_NONE);

	if(pModule->type & MOD_DBGDATA)
	{
		Deletesorteddatarange((t_sorted *)0x005D7254, pModule->base, pModule->base + pModule->size);

		((void(__cdecl *)(HANDLE, DWORD))0x004C9C2C)(process, pModule->base);
		pModule->type &= ~MOD_DBGDATA;
	}

	Redrawcpudisasm();

	WCHAR szMessage[64];
	wsprintf(szMessage, L"Symbols were successfully cleared for %s", pModule->modname);

	Flash(L"%s", szMessage);
	Addtolist(0, 0, DEF_NAME L": %s", szMessage);
}

static int __cdecl MainMenuFunc(t_table *pt, wchar_t *name, ulong index, int mode);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		hInst = (HINSTANCE)hModule;
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

// ODBG2_Pluginquery() is a "must" for valid OllyDbg plugin. It must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should fill plugin name and plugin version (as UNICODE strings) and
// return version of expected plugin interface. If OllyDbg decides that this
// plugin is not compatible, it will be unloaded. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, name must
// be descriptive and correlate with the name of DLL. Parameter features is
// reserved for the future. I plan that features[0] will contain the number
// of additional entries in features[]. Attention, this function should not
// call any API functions: they may be incompatible with the version of plugin!
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion, ulong *features,
	wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
	// Check whether OllyDbg has compatible version. This plugin uses only the
	// most basic functions, so this check is done pro forma, just to remind of
	// this option.
	if(ollydbgversion < 201)
		return 0;

	// Report name and version to OllyDbg.
	lstrcpy(pluginname, DEF_NAME); // Name of plugin
	lstrcpy(pluginversion, DEF_VERSION); // Version of plugin

	return PLUGIN_VERSION; // Expected API version
}

// Optional entry, called immediately after ODBG2_Pluginquery(). Plugin should
// make one-time initializations and allocate resources. On error, it must
// clean up and return -1. On success, it must return 0.
extc int __cdecl ODBG2_Plugininit(void)
{
	if(!CheckBytesForPatching())
	{
		Addtolist(0, DRAW_HILITE, DEF_NAME L": OllyDbg assembly code doesn't match (Only OllyDbg v2.01 is supported)");
		return -1;
	}

	if(!Getfromini(NULL, DEF_NAME, L"disable_auto_load_symbols", L"%i", &bDisableAutoLoadSymbols))
	{
		bDisableAutoLoadSymbols = TRUE;
		Writetoini(NULL, DEF_NAME, L"disable_auto_load_symbols", L"%i", bDisableAutoLoadSymbols);
	}

	if(bDisableAutoLoadSymbols)
	{
		PatchDisableDebuggingData(TRUE);
	}

	return 0;
}

// Adds items either to main OllyDbg menu (type=PWM_MAIN) or to popup menu in
// one of the standard OllyDbg windows, like PWM_DISASM or PWM_MEMORY. When
// type matches, plugin should return address of menu. When there is no menu of
// given type, it must return NULL. If menu includes single item, it will
// appear directly in menu, otherwise OllyDbg will create a submenu with the
// name of plugin. Therefore, if there is only one item, make its name as
// descriptive as possible.
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type)
{
	static t_menu mainmenu[] = {
			{ L"&Load current module symbols",
			NULL,
			KK_DIRECT | KK_CTRL | KK_SHIFT | 'D', MainMenuFunc, NULL, 0 },
			{ L"&Clear current module symbols",
			NULL,
			K_NONE, MainMenuFunc, NULL, 1 },
			{ L"|&About",
			NULL,
			K_NONE, MainMenuFunc, NULL, 2 },
			{ NULL, NULL, K_NONE, NULL, NULL, 0 }
	};

	if(lstrcmp(type, PWM_MAIN) == 0)
		return mainmenu;

	return NULL;
}

/*
// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision! Attention, don't make any
// unrecoverable actions for the case that some other plugin will decide that
// OllyDbg should continue running.
extc int __cdecl ODBG2_Pluginclose(void)
{
	return 0;
}
*/

/*
// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory etc.
extc void __cdecl ODBG2_Plugindestroy(void)
{
}
*/

static int __cdecl MainMenuFunc(t_table *pt, wchar_t *name, ulong index, int mode)
{
	switch(mode)
	{
	case MENU_VERIFY:
		return MENU_NORMAL; // Always available

	case MENU_EXECUTE:
		switch(index)
		{
		case 0:
			if(bDisableAutoLoadSymbols)
			{
				PatchDisableDebuggingData(FALSE);
				LoadCurrentModuleSymbols();
				PatchDisableDebuggingData(TRUE);
			}
			else
				LoadCurrentModuleSymbols();
			break;

		case 1:
			ClearCurrentModuleSymbols();
			break;

		case 2:
			// Debuggee should continue execution while message box is displayed.
			Resumeallthreads();

			// Menu item "About", displays plugin info.
			MessageBox(
				hwollymain, 
				DEF_NAME L" plugin v" DEF_VERSION L"\n"
				DEF_COPYRIGHT,
				DEF_NAME,
				MB_ICONASTERISK
			);

			// Suspendallthreads() and Resumeallthreads() must be paired, even if they
			// are called in inverse order!
			Suspendallthreads();
			break;
		}

		return MENU_NOREDRAW;
	}

	return MENU_ABSENT;
}
