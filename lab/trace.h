#ifndef TRACE_H
#define TRACE_H
#include <stdio.h>
#include <stdlib.h>
#define VMTRACE(PC, OP, SP, I) do { \
    if (getenv("VMTRACE")) { \
        fprintf(stderr, "[pc=0x%02x op=0x%02x sp=%d i=%d]", (PC), (OP), (SP), (I)); \
        fputc(10, stderr); \
    } \
} while (0)
#endif
