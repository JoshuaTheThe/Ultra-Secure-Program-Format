
// PIC only

#ifndef USPF_H
#define USPF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define NAME_LEN  (32)
#define MAGIC_LEN (5) // \x7fUSPF

typedef uint64_t SECTION;
typedef uint64_t SYMBOL;

typedef enum : uint16_t
{
        MACHINE_NONE,
        MACHINE_IA_32,
        MACHINE_AMD64,
        MACHINE_ARM_32,
        MACHINE_ARM_64,
        MACHINE_RV_32,
        MACHINE_RV_64,
} MACHINE;

// Primary Program Header
typedef struct __attribute__((__packed__))
{
        uint8_t         Magic[MAGIC_LEN];
        uint64_t        Version;
        uint8_t         Name[NAME_LEN];
        uint64_t        SectionCount;
        MACHINE         Machine;
        SECTION         RelocationSectionIndex; 
        SECTION         TextSectionIndex;
        SECTION         SymbolSectionIndex;
        SYMBOL          EntrySymbolIndex;
        uint64_t        IntegrityCheck;  // =MAGIC_LEN+Version*1024+SectionCount-Machine+RelocationSectionIndex-TextSectionIndex+SymbolSectionIndex*sizeof_file
        uint8_t         PasswordSHA[32]; // image is protected with this
        uint8_t         SignSHA[64];     // image must have a valid sign
        uint8_t         ImageSHA[32];    // image must be valid
        // Sections then follow
} USPFProgramHeader;

typedef enum : uint8_t
{
        SECTION_TYPE_RELOCATION,
        SECTION_TYPE_SYMBOLTABLE,
        SECTION_TYPE_TEXT,
        SECTION_TYPE_RODATA,
        SECTION_TYPE_RWDATA,
        SECTION_TYPE_BSS, // bss has no data but it has size, set to zero before jumping
} SECTIONTYPE;

typedef struct __attribute__((__packed__))
{
        uint8_t         Name[NAME_LEN];
        SECTIONTYPE     Type;
        uint64_t        DataSize;
        uint8_t         SHA256[32]; // of section
        // encrypted Data would Follow
} USPFSectionHeader;

typedef struct __attribute__((__packed__))
{
        uint8_t         Length;
        uint8_t         Name[];
} USPFSymbol;

typedef struct __attribute__((__packed__))
{
        SECTION         Section;
        SYMBOL          Symbol;
        uint64_t        Offset;
} USPFRelocation;

#endif
