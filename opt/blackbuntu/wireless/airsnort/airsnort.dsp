# Microsoft Developer Studio Project File - Name="airsnort" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=airsnort - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "airsnort.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "airsnort.mak" CFG="airsnort - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "airsnort - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "airsnort - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "airsnort - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "bin"
# PROP Intermediate_Dir "build"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I ".\src" /I "c:\gtk\include\gtk-2.0" /I "c:\gtk\include\glib-2.0" /I "c:\gtk\include\pango-1.0" /I "c:\gtk\include\atk-1.0" /I "c:\gtk\lib\glib-2.0\include" /I "c:\gtk\lib\gtk-2.0\include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib shell32.lib gobject-2.0.lib gtk-win32-2.0.lib gdk-win32-2.0.lib glib-2.0.lib atk-1.0.lib gdk_pixbuf-2.0.lib /nologo /subsystem:console /machine:I386 /libpath:"c:\gtk\lib"
# SUBTRACT LINK32 /debug

!ELSEIF  "$(CFG)" == "airsnort - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "bin"
# PROP Intermediate_Dir "build"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I ".\src" /I "c:\gtk\include\gtk-2.0" /I "c:\gtk\include\glib-2.0" /I "c:\gtk\include\pango-1.0" /I "c:\gtk\include\atk-1.0" /I "c:\gtk\lib\glib-2.0\include" /I "c:\gtk\lib\gtk-2.0\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib shell32.lib gobject-2.0.lib gtk-win32-2.0.lib gdk-win32-2.0.lib glib-2.0.lib atk-1.0.lib gdk_pixbuf-2.0.lib /nologo /subsystem:console /machine:I386 /pdbtype:sept /libpath:"c:\gtk\lib"
# SUBTRACT LINK32 /debug

!ENDIF 

# Begin Target

# Name "airsnort - Win32 Release"
# Name "airsnort - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\bssidlist.c
# End Source File
# Begin Source File

SOURCE=.\src\callbacks.c
# End Source File
# Begin Source File

SOURCE=.\src\capture.c
# End Source File
# Begin Source File

SOURCE=.\src\crack.c
# End Source File
# Begin Source File

SOURCE=".\src\crc-32.c"
# End Source File
# Begin Source File

SOURCE=.\src\display.c
# End Source File
# Begin Source File

SOURCE=.\src\interface.c
# End Source File
# Begin Source File

SOURCE=.\src\korek.c
# End Source File
# Begin Source File

SOURCE=.\src\main.c
# End Source File
# Begin Source File

SOURCE=.\src\Packet.c
# End Source File
# Begin Source File

SOURCE=.\src\PacketSource.c
# End Source File
# Begin Source File

SOURCE=.\src\RC4.c
# End Source File
# Begin Source File

SOURCE=.\src\support.c
# End Source File
# Begin Source File

SOURCE=.\src\utils.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\src\bssidlist.h
# End Source File
# Begin Source File

SOURCE=.\src\callbacks.h
# End Source File
# Begin Source File

SOURCE=.\src\capture.h
# End Source File
# Begin Source File

SOURCE=.\src\crack.h
# End Source File
# Begin Source File

SOURCE=".\src\crc-32.h"
# End Source File
# Begin Source File

SOURCE=.\src\display.h
# End Source File
# Begin Source File

SOURCE=.\src\interface.h
# End Source File
# Begin Source File

SOURCE=.\src\iphlp.h
# End Source File
# Begin Source File

SOURCE=.\src\korek.h
# End Source File
# Begin Source File

SOURCE=.\src\Packet.h
# End Source File
# Begin Source File

SOURCE=.\src\PacketSource.h
# End Source File
# Begin Source File

SOURCE=.\src\peek.h
# End Source File
# Begin Source File

SOURCE=.\src\RC4.h
# End Source File
# Begin Source File

SOURCE=.\src\support.h
# End Source File
# Begin Source File

SOURCE=.\src\unistd.h
# End Source File
# Begin Source File

SOURCE=.\src\utils.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
