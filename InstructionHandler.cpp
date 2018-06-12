#include "InstructionHandler.h"
#include "TaintedObject.h"
#include "others.h"

extern BOOL startAnalyse;

using namespace std;

VOID printINSInfo(INS ins)
{
	logNPrint("[%#08x] %s\n", (UINT)INS_Address(ins), (PCHAR)INS_Disassemble(ins).c_str());
	logNPrint("\tcount %d\tOpcode %s\tCategory %s\n", INS_OperandCount(ins), 
		OPCODE_StringShort(INS_Opcode(ins)).c_str(), 
		CATEGORY_StringShort(INS_Category(ins)).c_str());
	logNPrint("\tRegR 0 %s\tRegR 1 %s\tRegR 2 %s\tRegR 3 %s\tRegR 4 %s\n",
		REG_StringShort(INS_RegR(ins, 0)).c_str(), REG_StringShort(INS_RegR(ins, 1)).c_str(),
		REG_StringShort(INS_RegR(ins, 2)).c_str(), REG_StringShort(INS_RegR(ins, 3)).c_str(),
		REG_StringShort(INS_RegR(ins, 4)).c_str());
	logNPrint("\tRegW 0 %s\tRegW 1 %s\tRegW 2 %s\tRegW 3 %s\tRegW 4 %s\n",
		REG_StringShort(INS_RegW(ins, 0)).c_str(), REG_StringShort(INS_RegW(ins, 1)).c_str(),
		REG_StringShort(INS_RegW(ins, 2)).c_str(), REG_StringShort(INS_RegW(ins, 3)).c_str(),
		REG_StringShort(INS_RegW(ins, 4)).c_str());
}

VOID ReadMmrBefore(ADDRINT instAddr, ADDRINT addr, UINT32 size, REG reg)
{
	//logNPrint("[ReadMmrBefore]\n");
	//logNPrint("\tIARG_MEMORYREAD_EA %#08x\n", addr);
	//logNPrint("\tWrite register %s\n", REG_StringShort(reg).c_str());

	if (isMemoryTainted(addr, size) == true) {
		if (REG_valid(reg) && !REG_is_seg(reg))
			setRegTainted(instAddr, reg);		
	}
	else {
		if (REG_valid(reg) && !REG_is_seg(reg))
			setRegUntainted(reg);		
	}
}

VOID WriteMmrBefore(ADDRINT addr, UINT32 size, UINT count,
	REG regR0, REG regR1, REG regR2, REG regR3, REG regR4, REG regR5)
{
	//logNPrint("[WriteMmrBefore]\n");
	//logNPrint("\tIARG_MEMORYWRITE_EA  %#08x\n", addr);

	REG arr[6];
	arr[0] = regR0;
	arr[1] = regR1;
	arr[2] = regR2;
	arr[3] = regR3;
	arr[4] = regR4;
	arr[5] = regR5;

	for (UINT i = 0; i < count; i++) {
		if (REG_valid(arr[i]) && !REG_is_seg(arr[i]) && isRegTainted(arr[i]))
			return setMemoryTainted(addr, size);
	}
	
	setMemoryUntainted(addr, size);
}

VOID RegToRegBefore(ADDRINT addr, OPCODE op, REG regW, 
	UINT readCount, REG regR0, REG regR1, REG regR2, REG regR3)
{
	//logNPrint("[RegToRegBefore]\n");

	REG arr[4];
	arr[0] = regR0;
	arr[1] = regR1;
	arr[2] = regR2;
	arr[3] = regR3;

	// xor reg, reg
	if (regW == regR0 && op == XED_ICLASS_XOR)
		return setRegUntainted(regW);		

	for (UINT i = 0; i < readCount; i++) {
		if (REG_valid(arr[i]) && !REG_is_seg(arr[i]) && isRegTainted(arr[i]))
			return setRegTainted(addr, regW);
	}

	setRegUntainted(regW);
}

VOID MmrToMmrBefore(ADDRINT addr, ADDRINT readAddr, 
	UINT32 readSz, ADDRINT writeAddr, UINT32 writeSz)
{
	//logNPrint("[MmrToMmrBefore](%#08x) %#08x %x -> %#08x %x\n", 
	//	addr, readAddr, readSz, writeAddr, writeSz);

	if (isMemoryTainted(readAddr, readSz))
		setMemoryTainted(writeAddr, writeSz);
	else
		setMemoryUntainted(writeAddr, writeSz);
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
	if (startAnalyse == false)
		return;

	BOOL isMemoryWrite = INS_IsMemoryWrite(ins);
	BOOL isMemoryRead = INS_IsMemoryRead(ins);
	BOOL isMemoryRead2 = INS_HasMemoryRead2(ins);

	/*if (isMemoryWrite)
		logNPrint("MemoryWrite\n");
	
	if (isMemoryRead)
		logNPrint("MemoryRead\n");

	if (isMemoryRead2)
		logNPrint("MemoryRead2\n");

	if (!isMemoryWrite && !isMemoryRead)
		logNPrint("RegToReg\n");

	if (isMemoryWrite && isMemoryRead)
		logNPrint("ReadAndWriteMemory\n");

	printINSInfo(ins);*/

	if (isMemoryWrite) {

		INS_InsertPredicatedCall(ins,
			IPOINT_BEFORE, (AFUNPTR)WriteMmrBefore,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE,
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegR(ins, 1),
			IARG_UINT32, INS_RegR(ins, 2),
			IARG_UINT32, INS_RegR(ins, 3),
			IARG_UINT32, INS_RegR(ins, 4),
			IARG_UINT32, INS_RegR(ins, 5),
			IARG_END);
	}
	if (isMemoryRead) {

		INS_InsertPredicatedCall(ins,
			IPOINT_BEFORE, (AFUNPTR)ReadMmrBefore,
			IARG_INST_PTR,
			IARG_MEMORYREAD_EA,
			IARG_MEMORYREAD_SIZE,
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_END);		
	}
	if (!isMemoryWrite && !isMemoryRead) {

		INS_InsertCall(ins,
			IPOINT_BEFORE, (AFUNPTR)RegToRegBefore,
			IARG_INST_PTR,
			IARG_UINT32, INS_Opcode(ins),
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegR(ins, 1),
			IARG_UINT32, INS_RegR(ins, 2),
			IARG_UINT32, INS_RegR(ins, 3),
			IARG_END);
	}
	if (isMemoryWrite && isMemoryRead) {

		INS_InsertCall(ins,
			IPOINT_BEFORE, (AFUNPTR)MmrToMmrBefore,
			IARG_INST_PTR,
			IARG_MEMORYREAD_EA,
			IARG_MEMORYREAD_SIZE,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE,
			IARG_END);
	}
}
