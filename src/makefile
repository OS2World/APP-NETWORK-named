#
# Makefile for nameserver
#
# Bob Eager   August 2000
#
# Product name
#
PRODUCT		= named
#
# Target directory
#
TARGET		= f:\binp
#
# Compiler setup
#
CC		= icc
!IFDEF DEBUG
DBUG		= -DDEBUG
!ELSE
DBUG		=
!ENDIF
!IFDEF	PROD
CFLAGS		= $(DBUG) -Fi -G4 -Gm -Gn -O -Q -Se -Si
!ELSE
CFLAGS		= $(DBUG) -Fi -G4 -Gm -Gn -Q -Se -Si -Ti -Tm -Tx
!ENDIF
#
# Names of library files
#
NETLIB = 	..\netlib\netlib.lib
!IFDEF	PROD
LIBS =		so32dll.lib tcp32dll.lib cppom30o.lib \
		$(NETLIB) os2386.lib
!ELSE
LIBS =		so32dll.lib tcp32dll.lib cppom30.lib \
		$(NETLIB) os2386.lib
!ENDIF
#
# Names of object files
#
OBJ =		named.obj config.obj server.obj refer.obj db.obj log.obj
#
# Other files
#
DEF =		$(PRODUCT).def
LNK =		$(PRODUCT).lnk
#
# Final executable file
#
EXE =		$(PRODUCT).exe
#
# Distribution
#
DIST =		dist.zip
NETLIBDLL =	..\netlib\netlib.dll
#
#-----------------------------------------------------------------------------
#
install:	$(EXE)
		@copy $(EXE) $(TARGET) > nul
#
$(EXE):		$(OBJ) $(NETLIB) $(LNK) $(DEF)
!IFDEF	PROD
		ilink /nodefaultlibrarysearch /nologo /exepack:2 @$(LNK)
!ELSE
		ilink /nodefaultlibrarysearch /debug /nobrowse /nologo @$(LNK)
!ENDIF
#
# Object files
#
named.obj:	named.c named.h log.h
#
config.obj:	config.c named.h log.h cmds.h
#
server.obj:	server.c named.h log.h
#
refer.obj:	refer.c named.h log.h
#
db.obj:		db.c named.h log.h
#
log.obj:	log.c log.h
#
# Linker response file. Rebuild if makefile changes
#
$(LNK):		makefile
		@if exist $(LNK) erase $(LNK)
		@echo /map:$(PRODUCT) >> $(LNK)
		@echo /out:$(PRODUCT) >> $(LNK)
		@echo $(OBJ) >> $(LNK)
		@echo $(LIBS) >> $(LNK)
		@echo $(DEF) >> $(LNK)
#
dist:		$(EXE) $(NETLIBDLL) readme.txt named.doc named.cnf
		zip -9 -j $(DIST) $**
#
clean:		
		-erase $(OBJ) $(LNK) $(PRODUCT).map csetc.pch
#
# End of makefile for nameserver
#
