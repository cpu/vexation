NAME = minijector
OBJS = $(NAME).obj
DEF  = $(NAME).def

#
# Debug build controls
#
!if $d(DEBUG)
!message !! BUILDING WITH DEBUG SYMBOLS !!
TASMDEBUG=/zi
LINKDEBUG=/v
!else
TASMDEBUG=
LINKDEBUG=
!endif

#
# Import dir controls
#
!if $d(MAKEDIR)
IMPORT=$(MAKEDIR)\..\lib\import32
!else
IMPORT=import32
!endif

#
# Linking
# 
$(NAME).exe:: $(OBJS) $(DEF)
  tlink32 /Tpe /ap /c $(LINKDEBUG) $(OBJS),$(NAME),, $(IMPORT), $(DEF)

#
# Assembling
#
.asm.obj:
   tasm32 $(TASMDEBUG) /p /ml /m2 /z $&.asm

clean::
   del $(NAME).exe
   del $(NAME).obj
   del $(NAME).map
   del $(NAME).tr2
   del $(NAME).nms
   del CALC.EXE

run:: $(NAME).EXE
   del CALC.EXE
   copy C:\WINDOWS\CALC.EXE
   td32 $(NAME).EXE
