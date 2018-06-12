#include "ImageHandler.h"
#include "TaintedObject.h"
#include "others.h"
#include <unordered_map>
#include <wchar.h>
#include <stdio.h>

unordered_map<UINT, UINT> fileMapping;	// <handle, dwMaxSzLow>
unordered_map<UINT, UINT> fileViewMap;	// <pointer, size>

extern BOOL startAnalyse;
extern CHAR fileName[256];
extern wchar_t fileWName[256];

VOID InsertFileMappingData(UINT handle, UINT size)
{
	fileMapping[handle] = size;
}

VOID EraseFileMappingData(UINT handle)
{
	unordered_map<UINT, UINT>::iterator iter = fileMapping.find(handle);

	if (iter != fileViewMap.end())
		fileMapping.erase(iter);
}

VOID InsertFileViewMapData(UINT ptr, UINT size)
{
	fileViewMap[ptr] = size;
}

UINT PopFileViewMapData(UINT ptr)
{
	unordered_map<UINT, UINT>::iterator iter = fileViewMap.find(ptr);
	UINT size = 0;

	if (iter != fileViewMap.end()) {
		size = iter->second;
		fileViewMap.erase(iter);
	}

	return size;
}

// CreateFileA case for notepad
VOID CreateFileABefore(CHAR * func_name, CHAR *arg0)
{
	if (strcmp(arg0, fileName) == 0)
		startAnalyse = true;

	logNPrint("%s(%ls) startAnalyse %d\n", func_name, arg0, startAnalyse);
}

// CreateFileW case for notepad
VOID CreateFileWBefore(CHAR * func_name, CHAR *arg0)
{
	if (wcscmp((wchar_t*)arg0, fileWName) == 0)
		startAnalyse = true;

	logNPrint("%s(%ls) startAnalyse %d\n", func_name, arg0, startAnalyse);
}

VOID ReadFileAfter(ADDRINT retval, UINT handle, UINT lpBuffer, UINT nNumberOfBytesToRead, UINT lpNumberOfBytesRead)
{
	if (startAnalyse == false)
		return;

	UINT length = MEMORY_ReadUint32(lpNumberOfBytesRead);

	setMemoryTainted(lpBuffer, length);

	logNPrint("ReadFile(0x%x, 0x%x, 0x%x)\n", handle, lpBuffer, nNumberOfBytesToRead);
	logNPrint("\treturn values : 0x%x (%x)\n", retval, length );
}

VOID CreateFileMappingAfter(ADDRINT retval, UINT handle, UINT attribute, UINT protect, UINT dwMaxSzHigh, UINT dwMaxSzLow)
{
	if (startAnalyse == false)
		return;

	InsertFileMappingData(retval, dwMaxSzLow);

	logNPrint("CreateFileMapping\thandle %d dwMaxSzLow %d\n", retval, dwMaxSzLow);
}

VOID MapViewOfFileAfter(ADDRINT retval, UINT handle, UINT access, UINT offsetHigh, UINT offsetLow, UINT numOfBytesToMap)
{
	if (startAnalyse == false)
		return;

	if (numOfBytesToMap == 0)
		InsertFileViewMapData(retval, fileMapping[handle]);
	else
		InsertFileViewMapData(retval, numOfBytesToMap);

	setMemoryTainted(retval, numOfBytesToMap);

	logNPrint("MapViewOfFileAfter\n");
	logNPrint("\treturn values : 0x%x numOfBytesToMap : %#08x\n", retval, numOfBytesToMap);
	//logNPrint("\thandle %d\tsz %d\t\n", handle, fileMapping[handle]);
}

VOID UnmapViewOfFileAfter(ADDRINT retval, UINT lpBaseAddress)
{
	if (startAnalyse == false)
		return;

	UINT size =	PopFileViewMapData(lpBaseAddress);;

	setMemoryUntainted(lpBaseAddress, size);

	logNPrint("UnmapViewOfFileAfter\n");
	logNPrint("\treturn values : 0x%x lpBaseAddress %#08x, size %#08x\n", retval, lpBaseAddress, size);
}

VOID MemsetBefore(CHAR *func_name, UINT ptr, INT val, UINT num)
{
	if (startAnalyse == false)
		return;

	if (isMemoryTainted(ptr, num) == true)
		setMemoryUntainted(ptr, num);

	//logNPrint("%s ptr %#x val %d num %d\n", func_name, ptr, val, num);
}

VOID MemcpyBefore(CHAR *func_name, UINT dst, UINT src, UINT num)
{
	if (startAnalyse == false)
		return;

	if (isMemoryTainted(src, num) == true)
		setMemoryTainted(dst, num);
	else
		setMemoryUntainted(dst, num);

	//logNPrint("%s dst %#x src %#x num %d\n", func_name, dst, src, num);
}

VOID CloseHandleBefore(UINT handle)
{
	EraseFileMappingData(handle);
}

VOID GetsBefore(ADDRINT* ptr)
{
	logNPrint("[GetsBefore] value %#08x\n", *(UINT*)ptr);
}

VOID GetsAfter(ADDRINT retval)
{
	UINT32 val;
	UINT32 size = 0;
	BYTE* ptr = (BYTE*)&val;
	CHAR str[2048];

	while (1) {
		val = MEMORY_ReadUint32(retval);

		for (int i = 0; i < 4; i++, size++) {

			str[size] = ptr[i];

			if (ptr[i] == '\0')
				goto END_LOOP;
		}

		retval += 4;
	}
	
END_LOOP:

	logNPrint("[GetsAfter] retval %#08x val %s\n", retval, str);

	setMemoryTainted(retval, size);

	startAnalyse = true;
}

VOID Image(IMG img, VOID *v)
{
	RTN FuncRtn;

	//logNPrint("Img imported : %s\n", IMG_Name(img).c_str());

	if (IMG_IsMainExecutable(img)) {
		//logNPrint("\timg IMG_IsMainExecutable\n");
		//ADDRINT entry = IMG_Entry(img);
		//logNPrint("\tentry function %s\n", RTN_FindNameByAddress(entry));
	}

	FuncRtn = RTN_FindByName(img, OPENFILEA);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_BEFORE, (AFUNPTR)CreateFileABefore,
			IARG_ADDRINT, OPENFILEA,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, OPENFILEW);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_BEFORE, (AFUNPTR)CreateFileWBefore,
			IARG_ADDRINT, OPENFILEW,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, READFILE);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_AFTER, (AFUNPTR)ReadFileAfter,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, CREATEFILEMAPPING);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_AFTER, (AFUNPTR)CreateFileMappingAfter,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, MAPVIEWOFFILE);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_AFTER, (AFUNPTR)MapViewOfFileAfter,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);

		RTN_Close(FuncRtn);
	}


	FuncRtn = RTN_FindByName(img, UNMAPVIEWOFFILE);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_AFTER, (AFUNPTR)UnmapViewOfFileAfter,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, MEMSET);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_BEFORE, (AFUNPTR)MemsetBefore,
			IARG_ADDRINT, MEMSET,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	FuncRtn = RTN_FindByName(img, MEMCPY);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
			IARG_ADDRINT, MEMCPY,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(FuncRtn);
	}

	/*FuncRtn = RTN_FindByName(img, CLOSEHANDLE);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_BEFORE, (AFUNPTR)CloseHandleBefore,
			IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
			IARG_END);

		RTN_Close(FuncRtn);
	}*/

	FuncRtn = RTN_FindByName(img, GETS);
	if (RTN_Valid(FuncRtn)) {
		RTN_Open(FuncRtn);

		RTN_InsertCall(FuncRtn,
			IPOINT_AFTER, (AFUNPTR)GetsAfter,
			IARG_FUNCRET_EXITPOINT_VALUE,
			//IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
			IARG_END);

		RTN_Close(FuncRtn);
	}
}