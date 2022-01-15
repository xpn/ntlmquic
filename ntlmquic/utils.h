#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>

uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
    uint8_t* OutBuffer
);