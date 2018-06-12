#include <string.h>
#include "TaintedObject.h"
#include "others.h"

// TO - Tainted Object Prefix
static union {
	struct {
		BYTE TO_AL;
		BYTE TO_AH;
	};
	WORD TO_AX;
	DWORD TO_EAX;
};

static union {
	struct {
		BYTE TO_BL;
		BYTE TO_BH;
	};
	WORD TO_BX;
	DWORD TO_EBX;
};

static union {
	struct {
		BYTE TO_CL;
		BYTE TO_CH;
	};
	WORD TO_CX;
	DWORD TO_ECX;
};

static union {
	struct {
		BYTE TO_DL;
		BYTE TO_DH;
	};
	WORD TO_DX;
	DWORD TO_EDX;
};

// Segment Registers
WORD TO_CS;
WORD TO_DS;
WORD TO_ES;
WORD TO_FS;
WORD TO_GS;
WORD TO_SS;

// Indexes and pointers Registers
static union {
	WORD TO_SI;
	DWORD TO_ESI;
};
static union {
	WORD TO_DI;
	DWORD TO_EDI;
};
static union {
	WORD TO_BP;
	DWORD TO_EBP;
};
static union {
	WORD TO_IP;
	DWORD TO_EIP;
};
static union {
	WORD TO_SP;
	DWORD TO_ESP;
};

// AVX
static union {
	BYTE TO_XMM0[16];
	BYTE TO_YMM0[32];
	BYTE TO_ZMM0[64];
};
static union {
	BYTE TO_XMM1[16];
	BYTE TO_YMM1[32];
	BYTE TO_ZMM1[64];
};
static union {
	BYTE TO_XMM2[16];
	BYTE TO_YMM2[32];
	BYTE TO_ZMM2[64];
};
static union {
	BYTE TO_XMM3[16];
	BYTE TO_YMM3[32];
	BYTE TO_ZMM3[64];
};
static union {
	BYTE TO_XMM4[16];
	BYTE TO_YMM4[32];
	BYTE TO_ZMM4[64];
};
static union {
	BYTE TO_XMM5[16];
	BYTE TO_YMM5[32];
	BYTE TO_ZMM5[64];
};
static union {
	BYTE TO_XMM6[16];
	BYTE TO_YMM6[32];
	BYTE TO_ZMM6[64];
};
static union {
	BYTE TO_XMM7[16];
	BYTE TO_YMM7[32];
	BYTE TO_ZMM7[64];
};
static union {
	BYTE TO_XMM8[16];
	BYTE TO_YMM8[32];
	BYTE TO_ZMM8[64];
};
static union {
	BYTE TO_XMM9[16];
	BYTE TO_YMM9[32];
	BYTE TO_ZMM9[64];
};
static union {
	BYTE TO_XMM10[16];
	BYTE TO_YMM10[32];
	BYTE TO_ZMM10[64];
};
static union {
	BYTE TO_XMM11[16];
	BYTE TO_YMM11[32];
	BYTE TO_ZMM11[64];
};
static union {
	BYTE TO_XMM12[16];
	BYTE TO_YMM12[32];
	BYTE TO_ZMM12[64];
};
static union {
	BYTE TO_XMM13[16];
	BYTE TO_YMM13[32];
	BYTE TO_ZMM13[64];
};
static union {
	BYTE TO_XMM14[16];
	BYTE TO_YMM14[32];
	BYTE TO_ZMM14[64];
};
static union {
	BYTE TO_XMM15[16];
	BYTE TO_YMM15[32];
	BYTE TO_ZMM15[64];
};


typedef unordered_map<REG, RegInfo*> REGMAP;
typedef unordered_map<DWORD, TaintedMemory> MMRMAP;

REGMAP regMap;
MMRMAP mmrUmap;


VOID initTaintedObjectManager()
{
	RegInfo* pri;

	// REG_EAX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EAX;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EAX, pri));

	// REG_AX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_AX;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_AX, pri));

	// REG_AH
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_AH;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_AH, pri));

	// REG_AL
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_AL;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_AL, pri));



	// REG_EBX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EBX;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EBX, pri));

	// REG_BX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_BX;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_BX, pri));

	// REG_BH
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_BH;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_BH, pri));

	// REG_BL
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_BL;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_BL, pri));



	// REG_ECX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ECX;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_ECX, pri));

	// REG_CX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_CX;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_CX, pri));

	// REG_CH
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_CH;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_CH, pri));

	// REG_CL
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_CL;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_CL, pri));



	// REG_EDX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EDX;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EDX, pri));

	// REG_DX
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_DX;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_DX, pri));

	// REG_DH
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_DH;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_DH, pri));

	// REG_DL
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_DL;
	pri->size = 1;
	regMap.insert(REGMAP::value_type(REG_DL, pri));



	// REG_ESI
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ESI;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_ESI, pri));

	// REG_SI
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_SI;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_SI, pri));



	// REG_EDI
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EDI;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EDI, pri));

	// REG_DI
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_DI;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_DI, pri));



	// REG_EBP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EBP;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EBP, pri));

	// REG_BP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_BP;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_BP, pri));



	// REG_EIP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_EIP;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_EIP, pri));

	// REG_IP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_IP;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_IP, pri));
	


	// REG_ESP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ESP;
	pri->size = 4;
	regMap.insert(REGMAP::value_type(REG_ESP, pri));

	// REG_SP
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_SP;
	pri->size = 2;
	regMap.insert(REGMAP::value_type(REG_SP, pri));


	// REG_XMM0
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM0;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM0, pri));

	// REG_YMM0
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM0;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM0, pri));


#if defined(TARGET_MIC)
	// REG_ZMM0
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM0;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM0, pri));
#endif

	// REG_XMM1
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM1;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM1, pri));

	// REG_YMM1
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM1;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM1, pri));


#if defined(TARGET_MIC)
	// REG_ZMM1
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM1;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM1, pri));
#endif

	// REG_XMM2
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM2;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM2, pri));

	// REG_YMM2
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM2;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM2, pri));


#if defined(TARGET_MIC)
	// REG_ZMM2
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM2;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM2, pri));
#endif

	// REG_XMM3
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM3;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM3, pri));

	// REG_YMM3
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM3;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM3, pri));


#if defined(TARGET_MIC)
	// REG_ZMM3
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM3;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM3, pri));
#endif

	// REG_XMM4
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM4;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM4, pri));

	// REG_YMM4
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM4;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM4, pri));


#if defined(TARGET_MIC)
	// REG_ZMM4
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM4;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM4, pri));
#endif

	// REG_XMM5
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM5;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM5, pri));

	// REG_YMM5
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM5;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM5, pri));


#if defined(TARGET_MIC)
	// REG_ZMM5
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM5;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM5, pri));
#endif

	// REG_XMM6
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM6;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM6, pri));

	// REG_YMM6
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM6;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM6, pri));


#if defined(TARGET_MIC)
	// REG_ZMM6
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM6;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM6, pri));
#endif

	// REG_XMM7
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM7;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM7, pri));

	// REG_YMM7
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM7;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM7, pri));


#if defined(TARGET_MIC)
	// REG_ZMM7
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM7;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM7, pri));
#endif

# if defined(TARGET_IA32E)

	// REG_XMM8
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM8;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM8, pri));

	// REG_YMM8
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM8;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM8, pri));


#if defined(TARGET_MIC)
	// REG_ZMM8
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM8;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM8, pri));
#endif

	// REG_XMM9
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM9;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM9, pri));

	// REG_YMM9
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM9;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM9, pri));


#if defined(TARGET_MIC)
	// REG_ZMM9
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM9;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM9, pri));
#endif

	// REG_XMM10
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM10;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM10, pri));

	// REG_YMM10
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM10;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM10, pri));


#if defined(TARGET_MIC)
	// REG_ZMM10
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM10;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM10, pri));
#endif

	// REG_XMM11
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM11;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM11, pri));

	// REG_YMM11
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM11;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM11, pri));


#if defined(TARGET_MIC)
	// REG_ZMM11
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM11;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM11, pri));
#endif

	// REG_XMM12
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM12;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM12, pri));

	// REG_YMM12
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM12;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM12, pri));


#if defined(TARGET_MIC)
	// REG_ZMM12
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM12;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM12, pri));
#endif

	// REG_XMM13
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM13;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM13, pri));

	// REG_YMM13
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM13;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM13, pri));


#if defined(TARGET_MIC)
	// REG_ZMM13
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM13;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM13, pri));
#endif

	// REG_XMM14
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM14;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM14, pri));

	// REG_YMM14
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM14;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM14, pri));


#if defined(TARGET_MIC)
	// REG_ZMM14
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM14;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM14, pri));
#endif

	// REG_XMM15
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_XMM15;
	pri->size = 16;
	regMap.insert(REGMAP::value_type(REG_XMM15, pri));

	// REG_YMM15
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_YMM15;
	pri->size = 32;
	regMap.insert(REGMAP::value_type(REG_YMM15, pri));


#if defined(TARGET_MIC)
	// REG_ZMM15
	pri = (RegInfo*)malloc(sizeof(RegInfo));
	pri->reg_ptr = &TO_ZMM15;
	pri->size = 64;
	regMap.insert(REGMAP::value_type(REG_ZMM15, pri));
#endif
#endif
}

VOID deinitTaintedObjectManager()
{
	MMRMAP::iterator umapIter;
	for (umapIter = mmrUmap.begin(); umapIter != mmrUmap.end(); ++umapIter)
		free(umapIter->second.dirty);
	mmrUmap.clear();

	REGMAP::iterator mapIter;
	for (mapIter = regMap.begin(); mapIter != regMap.end(); ++mapIter)
		free(mapIter->second);
	regMap.clear();
}

VOID printAllTaintedObject()
{
	MMRMAP::iterator umapIter;
	for (umapIter = mmrUmap.begin(); umapIter != mmrUmap.end(); ++umapIter) {

		BYTE *ptr = umapIter->second.dirty;
		while (ptr = (BYTE*)memchr(ptr, 0xff, TM_BLK_SZ - (ptr - umapIter->second.dirty))) {

			logNPrint("[%#08x]\t", umapIter->first + (ptr - umapIter->second.dirty));

			UINT i = 0;
			for (;;i++) {
				logNPrint("%02x ", ptr[i]);
				if (ptr[i] == 0)
					break;
			}
			logNPrint("\n");
			ptr += i;
		}
	}
		logNPrint("[%#08x]\n", umapIter->first);
	
	REGMAP::iterator mapIter;
	for (mapIter = regMap.begin(); mapIter != regMap.end(); ++mapIter)
		logNPrint("[%s] %02x\n", REG_StringShort(mapIter->first).c_str(), *(BYTE*)mapIter->second->reg_ptr);
}

DWORD addrMultipleOfBlkSz(DWORD addr)
{
	return addr - addr % TM_BLK_SZ;
}

BOOL isMemoryTaintedMultipleOfBlkSz(DWORD key, DWORD addr, DWORD size)
{
	MMRMAP::const_iterator iter = mmrUmap.find(key);

	if (iter == mmrUmap.end())
		return false;

	TaintedMemory tm = iter->second;

	void *ptr = tm.dirty + (addr - key);

	if (memchr(ptr, 0xff, size) == NULL)
		return false;

	return true;
}

// Memory range must be in (addr: multiplied of 4, size: 4)
BOOL isMemoryTainted(DWORD addr, DWORD size)
{
	DWORD key = addrMultipleOfBlkSz(addr);

	// If range is small than TM_BLK_SZ
	if (key + TM_BLK_SZ >= addr + size)
		return isMemoryTaintedMultipleOfBlkSz(key, addr, size);

	// Else if range greater than TM_BLK_SZ
	DWORD setAddr, setSize;

	setAddr = addr;
	setSize = key + TM_BLK_SZ - addr;

	while (addr + size >= key) {
		if (isMemoryTaintedMultipleOfBlkSz(key, setAddr, setSize) == true)
			return true;

		key += TM_BLK_SZ;
		setAddr = key;
		setSize = (key + TM_BLK_SZ < addr + size) ? TM_BLK_SZ : addr + size - key;
	}

	return false;
}


BOOL isRegTainted(REG reg_idx)
{
	REGMAP::const_iterator iter = regMap.find(reg_idx);

	if (iter == regMap.end()) {
		//logNPrint("[isRegTainted] failed to find register %s\n", 
		//	REG_StringShort(reg_idx).c_str());
		return false;
	}

	RegInfo *pri = iter->second;

	// If register is zero then not tainted
	if (memchr(pri->reg_ptr, 0xff, pri->size) == NULL)
		return false;

	return true;
}

VOID setMemoryTaintedMultipleOfBlkSz(DWORD key, DWORD addr, DWORD size)
{
	MMRMAP::const_iterator iter = mmrUmap.find(key);

	// Add new map
	if (iter == mmrUmap.end()) {

		TaintedMemory tm;
		tm.dirty = (BYTE*)malloc(TM_BLK_SZ);
		memset(tm.dirty, 0, sizeof(TM_BLK_SZ));

		void *ptr = tm.dirty + (addr - key);
		memset(ptr, 0xff, size);

		mmrUmap[key] = tm;
	}
	// Edit existing map
	else {
		TaintedMemory tm = iter->second;

		void *ptr = tm.dirty + (addr - key);
		memset(ptr, 0xff, size);
	}
}

VOID setMemoryTainted(DWORD addr, DWORD size)
{
	DWORD key = addrMultipleOfBlkSz(addr);

	logNPrint("Memory addr: %#08x size: %#x is tainted\n", addr, size);

	// If range is small than TM_BLK_SZ
	if (key + TM_BLK_SZ >= addr + size)
		return setMemoryTaintedMultipleOfBlkSz(key, addr, size);

	// Else if range greater than TM_BLK_SZ
	DWORD setAddr, setSize;

	setAddr = addr;
	setSize = key + TM_BLK_SZ - addr;
	
	while (addr + size >= key) {
		setMemoryTaintedMultipleOfBlkSz(key, setAddr, setSize);

		key += TM_BLK_SZ;
		setAddr = key;
		setSize = (key + TM_BLK_SZ < addr + size) ? TM_BLK_SZ : addr + size - key;
	}
}

VOID setMemoryUntaintedMultipleOfBlkSz(DWORD key, DWORD addr, DWORD size)
{
	MMRMAP::const_iterator iter = mmrUmap.find(key);

	if (iter != mmrUmap.end()) {

		TaintedMemory tm = iter->second;

		void *ptr = tm.dirty + (addr - key);
		memset(ptr, 0, size);

		if (memchr(tm.dirty, 0xff, TM_BLK_SZ) == NULL) {
			free(iter->second.dirty);
			mmrUmap.erase(iter);
		}
	}
}

VOID setMemoryUntainted(DWORD addr, DWORD size)
{
	DWORD key = addrMultipleOfBlkSz(addr);

	// If range is small than TM_BLK_SZ
	if (key + TM_BLK_SZ >= addr + size)
		return setMemoryUntaintedMultipleOfBlkSz(key, addr, size);

	// Else if range greater than TM_BLK_SZ
	DWORD setAddr, setSize;

	setAddr = addr;
	setSize = key + TM_BLK_SZ - addr;

	while (addr + size >= key) {
		setMemoryUntaintedMultipleOfBlkSz(key, setAddr, setSize);

		key += TM_BLK_SZ;
		setAddr = key;
		setSize = (key + TM_BLK_SZ < addr + size) ? TM_BLK_SZ : addr + size - key;
	}
}

VOID setRegTainted(ADDRINT addr, REG reg_idx)
{
	REGMAP::const_iterator iter = regMap.find(reg_idx);

	if (iter == regMap.end()) {
		//logNPrint("[setRegTainted] failed to find register %s\n", 
		//	REG_StringShort(reg_idx).c_str());
		return;
	}

	logNPrint("Register %s\tis tainted at addr\t%#08x\n", REG_StringShort(reg_idx).c_str(), addr);

	RegInfo *pri = iter->second;

	memset(pri->reg_ptr, 0xff, pri->size);

	if (REG_FullRegName(reg_idx) == REG_EIP)
		logNPrint("[%#08x] Instruction taints EIP\n", addr);
	
}

VOID setRegUntainted(REG reg_idx)
{
	REGMAP::const_iterator iter = regMap.find(reg_idx);

	if (iter == regMap.end()) {
		//logNPrint("[setRegUntainted] failed to find register %s\n", 
		//	REG_StringShort(reg_idx).c_str());
		return;
	}

	RegInfo *pri = iter->second;

	memset(pri->reg_ptr, 0, pri->size);

}
