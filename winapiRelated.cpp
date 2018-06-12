#include <Windows.h>
#include "winapiRelated.h"

void ansiToUtf16(char *ansi_str, wchar_t *utf16_str, unsigned int buf_size)
{
	DWORD utf16_len = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)ansi_str, buf_size, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, (LPCSTR)ansi_str, 256, utf16_str, utf16_len);
}


#define WIN32_LEAN_AND_MEAN

LARGE_INTEGER	mFreq, mStart, mEnd;
float			mTimeforDuration;

void InitStopWatch()
{
	mTimeforDuration = 0;
	mFreq.LowPart = mFreq.HighPart = 0;
	mEnd = mStart = mFreq;
	QueryPerformanceFrequency(&mFreq);
}

void Start()
{ 
	QueryPerformanceCounter(&mStart); 
}

void Stop()
{
	QueryPerformanceCounter(&mEnd);
	mTimeforDuration = (mEnd.QuadPart - mStart.QuadPart) / (float)mFreq.QuadPart;
}

float GetDurationSecond() 
{ 
	return mTimeforDuration; 
}

float GetDurationMilliSecond() 
{ 
	return mTimeforDuration * 1000.f; 
}
