#include <windows.h>
#include "ollydbg/plugin.h"

#define DEF_NAME         "Symbol Loader"
#define DEF_VERSION      "1.0"
#define DEF_COPYRIGHT    "Copyright (C) 2015 RaMMicHaeL"

HINSTANCE hInst;
HWND hOllyWnd;
BOOL bAutoLoadSymbols;

BOOL InitPatchProcess()
{
	DWORD dwNumberOfBytesWritten;

	// Skip SymSetSearchPath

	// 004911EC | EB 2E              JMP SHORT OLLYDBG.0049121C
	if(!WriteProcessMemory(GetCurrentProcess(), (void *)0x004911EC, "\xEB", 1, &dwNumberOfBytesWritten) ||
		dwNumberOfBytesWritten != 1)
	{
		return FALSE;
	}

	// SymSetOptions: 0x00001210 -> 0x00000213

	// 00491107 | 81CA 13020000      OR EDX,213
	if(!WriteProcessMemory(GetCurrentProcess(), (void *)0x00491109, "\x13\x02", 2, &dwNumberOfBytesWritten) ||
		dwNumberOfBytesWritten != 2)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL ApplyAutoLoadConfig(BOOL bNewAutoLoadConfig)
{
	char *pPatchData;
	if(bNewAutoLoadConfig)
		pPatchData = "\xE8\x8A\x49\x03\x00";
	else
		pPatchData = "\x90\x90\x90\x90\x90";

	DWORD dwNumberOfBytesWritten;
	if(!WriteProcessMemory(GetCurrentProcess(), (void *)0x0045DC91, pPatchData, 5, &dwNumberOfBytesWritten))
		return FALSE;

	return dwNumberOfBytesWritten == 5;
}

BOOL ReadAutoLoadConfig()
{
	return Pluginreadintfromini(hInst, "auto_load_symbols", FALSE);
}

void ChangeAutoLoadConfig(BOOL bNewAutoLoadConfig)
{
	Pluginwriteinttoini(hInst, "auto_load_symbols", bNewAutoLoadConfig);
}

void LoadCurrentModuleSymbols()
{
	if(Getstatus() == STAT_NONE)
	{
		Flash("No process is loaded");
		return;
	}

	DWORD dwBase, dwSize;
	Getdisassemblerrange(&dwBase, &dwSize);

	t_module *pModule = Findmodule(dwBase);
	if(!pModule)
	{
		Flash("Could not find module on address %p", dwBase);
		Addtolist(0, 0, "Could not find module on address %p", dwBase);
		return;
	}

	// Second argument it the file offset for the Debug directory.
	// I'm not sure what advantages does it provide, though.

	int result = ((int(__cdecl *)(t_module *, size_t, char *))0x00492620)(pModule, 0, pModule->path);
	Redrawdisassembler();

	Flash("Symbols loading completed, result: %d", result);
	Addtolist(0, 0, "Symbols loading completed, result: %d", result);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hInst = (HINSTANCE)hModule;
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

// ODBG_Plugindata() is a "must" for valid OllyDbg plugin. It must fill in
// plugin name and return version of plugin interface. If function is absent,
// or version is not compatible, plugin will be not installed. Short name
// identifies it in the Plugins menu. This name is max. 31 alphanumerical
// characters or spaces + terminating '\0' long. To keep life easy for users,
// this name should be descriptive and correlate with the name of DLL.
extc int _export cdecl ODBG_Plugindata(char shortname[32])
{
	lstrcpy(shortname, DEF_NAME); // Name of plugin
	return PLUGIN_VERSION;
}

// OllyDbg calls this obligatory function once during startup. Place all
// one-time initializations here. If all resources are successfully allocated,
// function must return 0. On error, it must free partially allocated resources
// and return -1, in this case plugin will be removed. Parameter ollydbgversion
// is the version of OllyDbg, use it to assure that it is compatible with your
// plugin; hw is the handle of main OllyDbg window, keep it if necessary.
// Parameter features is reserved for future extentions, do not use it.
extc int _export cdecl ODBG_Plugininit(int ollydbgversion, HWND hWnd, ulong *features)
{
	// This plugin uses all the newest features, check that version of OllyDbg is
	// correct. I will try to keep backward compatibility at least to v1.99.
	if(ollydbgversion < PLUGIN_VERSION)
		return -1;

	// Keep handle of main OllyDbg window. This handle is necessary, for example,
	// to display message box.
	hOllyWnd = hWnd;

	// Plugin successfully initialized. Now is the best time to report this fact
	// to the log window. To conform OllyDbg look and feel, please use two lines.
	// The first, in black, should describe plugin, the second, gray and indented
	// by two characters, bears copyright notice.
	Addtolist(0, 0, DEF_NAME " v" DEF_VERSION);
	Addtolist(0, -1, DEF_COPYRIGHT);

	bAutoLoadSymbols = ReadAutoLoadConfig();

	if(!InitPatchProcess() || !ApplyAutoLoadConfig(bAutoLoadSymbols))
	{
		Addtolist(0, 1, DEF_NAME ": something went wrong!");
	}

	return 0;
}

// Function adds items either to main OllyDbg menu (origin=PM_MAIN) or to popup
// menu in one of standard OllyDbg windows. When plugin wants to add own menu
// items, it gathers menu pattern in data and returns 1, otherwise it must
// return 0. Except for static main menu, plugin must not add inactive items.
// Item indices must range in 0..63. Duplicated indices are explicitly allowed.
extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item)
{
	// Menu creation is very simple. You just fill in data with menu pattern.
	// Some examples:
	// 0 Aaa,2 Bbb|3 Ccc|,,  - linear menu with 3items, relative IDs 0, 2 and 3,
	//                         separator between second and third item, last
	//                         separator and commas are ignored;
	// #A{0Aaa,B{1Bbb|2Ccc}} - unconditional separator, followed by popup menu
	//                         A with two elements, second is popup with two
	//                         elements and separator inbetween.

	switch(origin)
	{
	case PM_MAIN: // Plugin menu in main window
		lstrcpy(data, 
			"0 &Load current module symbols\tCtrl+Shift+D|"
			"1 A&uto load symbols,"
			"2 &Don't auto load symbols|"
			"3 &About");
		// If your plugin is more than trivial, I also recommend to include Help.
		return 1;
	}

	return 0; // Window not supported by plugin
}

// This optional function receives commands from plugin menu in window of type
// origin. Argument action is menu identifier from ODBG_Pluginmenu(). If user
// activates automatically created entry in main menu, action is 0.
extc void _export cdecl ODBG_Pluginaction(int origin, int action, void *item)
{
	if(origin == PM_MAIN) 
	{
		switch(action)
		{
		case 0:
			// Menu item, main plugin functionality
			LoadCurrentModuleSymbols();
			break;

		case 1:
		case 2:
			bAutoLoadSymbols = (action == 1);
			ChangeAutoLoadConfig(bAutoLoadSymbols);

			if(!ApplyAutoLoadConfig(bAutoLoadSymbols))
			{
				Addtolist(0, 1, DEF_NAME ": something went wrong!");
			}
			break;

		case 3:
			// Menu item "About", displays plugin info. If you write your own code,
			// please replace with own copyright!
			MessageBox(
				hOllyWnd, 
				DEF_NAME " plugin v" DEF_VERSION "\n"
				DEF_COPYRIGHT,
				DEF_NAME,
				MB_ICONASTERISK
			);
			break;
		}
	}
}

// This function receives possible keyboard shortcuts from standard OllyDbg
// windows. If it recognizes shortcut, it must process it and return 1,
// otherwise it returns 0.
extc int _export cdecl ODBG_Pluginshortcut(int origin, int ctrl, int alt, int shift, int key, void *item)
{
	if(origin == PM_DISASM)
	{
		if(ctrl && !alt && shift && key == 'D')
		{
			LoadCurrentModuleSymbols();
			return 1;
		}
	}

	return 0;
}

// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to initial state.
/*
extc void _export cdecl ODBG_Pluginreset(void)
{
}
*/

// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision!
/*
extc int _export cdecl ODBG_Pluginclose(void)
{
	return 0;
}
*/

// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory and so on.
/*
extc void _export cdecl ODBG_Plugindestroy(void)
{
}
*/
