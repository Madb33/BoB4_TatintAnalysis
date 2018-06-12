/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2015 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
*  This file contains an ISA-portable PIN tool for tracing memory accesses.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "pin.H"
#include "TaintedObject.h"
#include "ImageHandler.h"
#include "InstructionHandler.h"
#include "others.h"
#include "winapiRelated.h"

// Global variables
BOOL startAnalyse = false;
CHAR fileName[256];
wchar_t fileWName[256];


VOID Fini(INT32 code, VOID *v)
{
	logNPrint("#eof\n");

	printAllTaintedObject();

	Stop();

	logNPrint("Total time : %lfs %lfms\n", GetDurationSecond(), GetDurationMilliSecond());

	deinitTaintedObjectManager();
}

VOID logNPrint(PCHAR _str, ...)
{
	va_list args;

	char str[1024];

	memset(str, 0, 1024);

	va_start(args, _str);
	vsprintf(str, _str, args);
	va_end(args);

	LOG(str);
}

VOID logNExit(PCHAR _str, ...)
{
	va_list args;

	char str[1024] = "";

	va_start(args, _str);
	vsprintf(str, _str, args);
	va_end(args);

	LOG(str);

	Fini(0, NULL);

	exit(-1);
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	PIN_ERROR("This Pintool prints a trace of memory addresses\n"
		+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
	InitStopWatch();
	Start();

	if (PIN_Init(argc, argv)) return Usage();

	//logNPrint("argc %d\n", argc);
	for (int i = 0; i < argc; i++) {
		//logNPrint("argv[%d] %s\n", i, argv[i]);
		if (strncmp(argv[i], "--", 2) == 0) {
			if (argc - 1 == i + 2) {
				strncpy(fileName, argv[i + 2], 256);
				ansiToUtf16(fileName, fileWName, 256);
			}
			break;
		}
	}

	initTaintedObjectManager();

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(Image, 0);

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
