#    This file is part of AirSnort.

#    AirSnort is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.

#    AirSnort is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with AirSnort; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
    
#    Copyright (c) 2003, Snax

!MESSAGE This is the AirSnort makefile for windows.  Two targets are
!MESSAGE defined, all and clean.  AirSnort for windows requires the
!MESSAGE GTK and GLIB libraries.  Since I have no idea where you may
!MESSAGE have installed the associated library and header files, you
!MESSAGE need to fix all of the paths below to match your installation
!MESSAGE read README.win for recommendations.
!MESSAGE This makefile assumes you have a typical MSVC install with libs
!MESSAGE located at c:\Program Files\Microsoft Visual Studio\VC98\Lib if
!MESSAGE this is not the case, use VC_LIBS= to specify their location.

CPP=cl.exe
RSC=rc.exe
BSC32=bscmake.exe
LINK32=link.exe
LIB=lib.exe

SRCDIR=.\src
OUTDIR=.\bin
INTDIR=.\build
LIBDIR=.\lib

#GTK root install directory
GTKDIR=c:\gtk

#include directories for required gtk/glib components
GTKINCS="$(GTKDIR)\include\gtk-2.0"
GLIBINCS="$(GTKDIR)\include\glib-2.0"
PANGOINCS="$(GTKDIR)\include\pango-1.0"
ATKINCS="$(GTKDIR)\include\atk-1.0"

#lib directories for required gtk/glib components 
GLIBCONFIG="$(GTKDIR)\lib\glib-2.0\include"
GDKCONFIG="$(GTKDIR)\lib\gtk-2.0\include"

GLIBS="$(GTKDIR)\lib"

VC_LIBS=c:\Program Files\Microsoft Visual Studio\VC98\Lib

ALL : "$(OUTDIR)\Airsnort.exe" "$(OUTDIR)\winmonitor.exe"

airsnort : "$(OUTDIR)\Airsnort.exe" 
winmonitor : "$(OUTDIR)\winmonitor.exe"

CLEAN :
	-@erase "$(INTDIR)\bssidlist.obj"
	-@erase "$(INTDIR)\callbacks.obj"
	-@erase "$(INTDIR)\capture.obj"
	-@erase "$(INTDIR)\crack.obj"
	-@erase "$(INTDIR)\crc-32.obj"
	-@erase "$(INTDIR)\display.obj"
	-@erase "$(INTDIR)\interface.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\Packet.obj"
	-@erase "$(INTDIR)\PacketSource.obj"
	-@erase "$(INTDIR)\RC4.obj"
	-@erase "$(INTDIR)\support.obj"
	-@erase "$(INTDIR)\utils.obj"
	-@erase "$(INTDIR)\korek.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\winmonitor.obj"
	-@erase "$(OUTDIR)\Airsnort.pdb"
	-@erase "$(OUTDIR)\Airsnort.exe"
	-@erase "$(OUTDIR)\Airsnort.ilk"
	-@erase "$(OUTDIR)\winmonitor.pdb"
	-@erase "$(OUTDIR)\winmonitor.exe"
	-@erase "$(OUTDIR)\winmonitor.ilk"
	-@erase "$(LIBDIR)\vc60.idb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

"$(LIBDIR)" :
    if not exist "$(LIBDIR)/$(NULL)" mkdir "$(LIBDIR)"

AIRSNORT_CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "$(SRCDIR)" /I "$(PANGOINCS)" /I "$(ATKINCS)" /I "$(GTKINCS)" /I "$(GLIBINCS)" /I "$(GDKCONFIG)" /I "$(GLIBCONFIG)" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

{$(SRCDIR)}.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(AIRSNORT_CPP_PROJ) $< 
<<

AIRSNORT_LINK32_FLAGS=kernel32.lib user32.lib shell32.lib gobject-2.0.lib gtk-win32-2.0.lib gdk-win32-2.0.lib glib-2.0.lib atk-1.0.lib gdk_pixbuf-2.0.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\Airsnort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\Airsnort.exe" /pdbtype:sept /LIBPATH:$(GLIBS) /LIBPATH:"$(VC_LIBS)" 
AIRSNORT_LINK32_OBJS= \
	"$(INTDIR)\bssidlist.obj" \
	"$(INTDIR)\callbacks.obj" \
	"$(INTDIR)\capture.obj" \
	"$(INTDIR)\crack.obj" \
	"$(INTDIR)\crc-32.obj" \
	"$(INTDIR)\display.obj" \
	"$(INTDIR)\interface.obj" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\Packet.obj" \
	"$(INTDIR)\PacketSource.obj" \
	"$(INTDIR)\RC4.obj" \
	"$(INTDIR)\support.obj" \
	"$(INTDIR)\utils.obj" \
	"$(INTDIR)\korek.obj"

"$(OUTDIR)\Airsnort.exe" : "$(OUTDIR)" $(AIRSNORT_LINK32_OBJS)
    $(LINK32) @<<
  $(AIRSNORT_LINK32_FLAGS) $(AIRSNORT_LINK32_OBJS)
<<

WINMONITOR_LINK32_FLAGS=Advapi32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\winmonitor.pdb" /debug /machine:I386 /out:"$(OUTDIR)\winmonitor.exe" /pdbtype:sept /LIBPATH:"$(VC_LIBS)" 
WINMONITOR_LINK32_OBJS= \
	"$(INTDIR)\winmonitor.obj"

"$(OUTDIR)\winmonitor.exe" : "$(OUTDIR)" $(WINMONITOR_LINK32_OBJS)
    $(LINK32) @<<
  $(WINMONITOR_LINK32_FLAGS) $(WINMONITOR_LINK32_OBJS)
<<

SOURCE=$(SRCDIR)\bssidlist.c

"$(INTDIR)\bssidlist.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\callbacks.c"

"$(INTDIR)\callbacks.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\capture.c"

"$(INTDIR)\capture.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\crack.c"

"$(INTDIR)\crack.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\crc-32.c"

"$(INTDIR)\crc-32.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\display.c"

"$(INTDIR)\display.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\interface.c"

"$(INTDIR)\interface.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\main.c"

"$(INTDIR)\main.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\Packet.c"

"$(INTDIR)\Packet.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\PacketSource.c"

"$(INTDIR)\PacketSource.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\RC4.c"

"$(INTDIR)\RC4.obj" : $(SOURCE) "$(INTDIR)"


SOURCE="$(SRCDIR)\support.c"

"$(INTDIR)\support.obj" : $(SOURCE) "$(INTDIR)"

SOURCE="$(SRCDIR)\utils.c"

"$(INTDIR)\utils.obj" : $(SOURCE) "$(INTDIR)"

SOURCE="$(SRCDIR)\korek.c"

"$(INTDIR)\korek.obj" : $(SOURCE) "$(INTDIR)"

SOURCE=$(SRCDIR)\winmonitor.c

"$(INTDIR)\winmonitor.obj" : $(SOURCE) "$(INTDIR)"

