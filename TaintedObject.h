#ifndef __TAINTED_OBJECT__
#define __TAINTED_OBJECT__

//#include <Windows.h>
#include <stdint.h>
#include <unordered_map>
#include <map>
#include "pin.H"

using namespace std;

typedef void* PVOID;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

#define TM_BLK_SZ		4194304		// Tainted Memory Block Size - 4KiB


typedef struct TaintedMemory {
	BYTE *dirty;
} TaintedMemory;

typedef struct RegInfo {
	PVOID reg_ptr;	// pointer of register
	BYTE size;		// in byte
} RegInfo;

VOID initTaintedObjectManager();
VOID deinitTaintedObjectManager();
VOID printAllTaintedObject();
BOOL isMemoryTainted(DWORD addr, DWORD size);
BOOL isRegTainted(LEVEL_BASE::REG reg_idx);
VOID setMemoryTainted(DWORD addr, DWORD size);
VOID setMemoryUntainted(DWORD addr, DWORD size);
VOID setRegTainted(ADDRINT addr, LEVEL_BASE::REG reg_idx);
VOID setRegUntainted(REG reg_idx);

#endif