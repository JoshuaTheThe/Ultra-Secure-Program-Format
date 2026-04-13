
// PIC only**

#ifndef USPF_H
#define USPF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#pragma pack(push)
#pragma pack(1)

#define NAME_LEN  (32)
#define MAGIC_LEN (5) // \x7fUSPF

#define VERSION (0x000100000000) // four digits per segment (Major.Minor.Patch)

typedef uint64_t SECTION;
typedef uint64_t SYMBOL;

typedef uint16_t MACHINE;

typedef enum
{
        MACHINE_NONE,
        MACHINE_IA_32,
        MACHINE_AMD64,
        MACHINE_ARM_32,
        MACHINE_ARM_64,
        MACHINE_RV_32,
        MACHINE_RV_64,
} _MACHINE;

// Primary Program Header
typedef struct
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
        uint8_t         PasswordSHA[32]; // image is protected with this
        uint8_t         SignSHA[64];     // image must have a valid sign
        uint8_t         ImageSHA[32];    // image must be valid
        uint8_t         Padding[41];
        // Sections then follow
} USPFProgramHeader;

typedef uint8_t SECTIONTYPE;

typedef enum
{
        SECTION_TYPE_RELOCATION,
        SECTION_TYPE_SYMBOLTABLE,
        SECTION_TYPE_TEXT,
        SECTION_TYPE_RODATA,
        SECTION_TYPE_RWDATA,
        SECTION_TYPE_BSS, // bss has no data but it has size, set to zero before jumping
} _SECTIONTYPE;

typedef struct
{
        uint8_t         Name[NAME_LEN];
        SECTIONTYPE     Type;
        uint64_t        DataSize;
        uint8_t         SHA256[32]; // of section
        // encrypted Data would Follow
} USPFSectionHeader;

typedef struct
{
        uint8_t         Length;
        uint8_t         Name[];
} USPFSymbol;

typedef uint8_t RELOCTYPE;

typedef enum
{
        RELOC_ABS,
        RELOC_REL,
} _RELOCTYPE;

typedef struct
{
        SECTION         Section;
        RELOCTYPE       Type;
        SYMBOL          Symbol;
        uint64_t        OffsetOrAbs;
} USPFRelocation;

#pragma pack(pop)

typedef struct
{
        USPFSectionHeader  Header;
        void              *Data;
} USPFSection;

typedef struct
{
        USPFProgramHeader  Program;
        USPFSection       *Sections;
        void             (*Main)(int argc, char **argv);
        void             (*AfterMain)(void);
} USPFImage;

USPFImage USPFLoadImage(const char *const Path, const char *const Password);

#endif
