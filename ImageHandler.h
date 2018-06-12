#ifndef __IMAGE_HANDLER__
#define __IMAGE_HANDLER__

//#include <Windows.h>
#include "pin.H"

#define OPENFILE			"CreateFile"
#define OPENFILEA			OPENFILE"A"
#define OPENFILEW			OPENFILE"W"
#define READFILE			"ReadFile"
#define CREATEFILEMAPPING	"CreateFileMapping"
#define MAPVIEWOFFILE		"MapViewOfFile"
#define UNMAPVIEWOFFILE		"UnmapViewOfFile"
#define MEMSET				"memset"
#define MEMCPY				"memcpy"
#define _VSNWPRINTF			"_vsnwprintf"
#define REPLACETEXTW		"ReplaceTextW"
#define CLOSEHANDLE			"CloseHandle"
#define GETS				"gets"


VOID Image(IMG img, VOID *v);


#endif