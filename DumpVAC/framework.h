#pragma once

#ifndef _FRAMEWORK_H_
#define _FRAMEWORK_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>

// C++
#include <cstdlib>
#include <cstdio>
#include <ctime>

// General definitions
#define DLL_EXPORT __declspec(dllexport)

#endif // !_FRAMEWORK_H_
