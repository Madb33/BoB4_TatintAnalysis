/**************************************/
/* This module is made to use winapi  */
/*   due to incompatibility between   */
/*   Windows.h and pin.H              */
/**************************************/
#ifndef __WINAPI_RELATED__
#define __WINAPI_RELATED__


void ansiToUtf16(char *ansi_str, wchar_t *utf16_str, unsigned int buf_size);

void InitStopWatch();
void Start();
void Stop();
float GetDurationSecond();
float GetDurationMilliSecond();

#endif