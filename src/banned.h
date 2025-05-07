/**
 * @brief Banned C functions list for secure coding enforcement.
 *
 * This file is a compilation of known/unsafe C functions which are banned. 
 * This is to standardised all of our developement enviroment across all coders to ensure we enfore these safe practices.
 * We took guidance from Microsoft SDL and O'reilly security developement lifecycle practices.
 * We will be utilising CITS3007 existing development environment - libbsd to use secure C functions.
 */

 #ifndef BANNED_H
 #define BANNED_H
 
 #ifndef CITS3007_PERMISSIVE
 
 // Reason: unsafe conversion and process control functions
 #pragma GCC poison \
    atof atoi atol atoll system
 
 // Reason: unsafe string copy functions
 #pragma GCC poison \
    strcpy strcpyA strcpyW wcscpy _tcscpy _mbscpy StrCpy StrCpyA StrCpyW \
    lstrcpy lstrcpyA lstrcpyW _tccpy _mbccpy _ftcscpy \
    strncpy wcsncpy _tcsncpy _mbsncpy _mbsnbcpy StrCpyN StrCpyNA StrCpyNW \
    StrNCpy strcpynA StrNCpyA StrNCpyW lstrcpyn lstrcpynA lstrcpynW _fstrncpy

 // Reason: unsafe string concatenation functions
 #pragma GCC poison \
    strcat strcatA strcatW wcscat _tcscat _mbscat StrCat StrCatA StrCatW \
    lstrcat lstrcatA lstrcatW StrCatBuff StrCatBuffA StrCatBuffW StrCatChainW \
    _tccat _mbccat _ftcscat strncat wcsncat _tcsncat _mbsncat _mbsnbcat \
    StrCatN StrCatNA StrCatNW StrNCat StrNCatA StrNCatW lstrncat lstrcatnA lstrcatnW lstrcatn _fstrncat
 
 // Reason: unsafe sprintf-style functions
 #pragma GCC poison \
    sprintfW sprintfA wsprintf wsprintfW wsprintfA sprintf swprintf \
    _stprintf wvsprintf wvsprintfA wvsprintfW vsprintf _vstprintf vswprintf \
 
 // Reason: unsafe string length and memory operations
 #pragma GCC poison \
    memcpy RtlCopyMemory CopyMemory wmemcpy
 
 // Reason: unsafe gets functions
 #pragma GCC poison \
    gets _getts _gettws
 
 // Reason: standard FILE-based I/O
 #pragma GCC poison \
    fopen freopen fclose fflush fgets fputs fread fwrite fgetc fputc \
    getc getchar putc putchar ungetc tmpfile tmpnam FILE
 
 // Reason: Redirect use of standard I/O streams to log-safe alternatives
 #undef stdin
 #undef stdout
 #undef stderr
 #define stdin  DO_NOT_USE_stdin_USE_LOGGING
 #define stdout DO_NOT_USE_stdout_USE_LOGGING
 #define stderr DO_NOT_USE_stderr_USE_LOGGING
 
 #endif 
 
 #endif 
 