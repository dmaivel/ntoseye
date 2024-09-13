#pragma once

#include <stdint.h>
#include <stddef.h>

// #define _In_
// #define _Out_
// #define _In_out_

// typedef int16_t WCHAR;
// typedef char *PSTR, *LPSTR;
// typedef const char *PCSTR, *LPCSTR;
// typedef WCHAR *PWSTR, *LPWSTR;
// typedef const WCHAR *PCWSTR, *LPCWSTR;
// typedef int8_t CHAR, *PCHAR, INT8, *PINT8;
// typedef uint8_t UCHAR, *PUCHAR, UINT8, *PUINT8, BYTE, *PBYTE, BOOLEAN, *PBOOLEAN;
// typedef int16_t SHORT, *PSHORT, INT16, *PINT16;
// typedef uint16_t USHORT, *PUSHORT, UINT16, *PUINT16, WORD, *PWORD;
// typedef int32_t INT, *PINT, INT32, *PINT32, LONG, *PLONG, BOOL, *PBOOL;
// typedef uint32_t UINT, *PUINT, UINT32, *PUINT32, ULONG, *PULONG, ULONG32, *PULONG32, DWORD, *PDWORD, DWORD32, *PDWORD32;
// typedef int64_t LONGLONG, *PLONGLONG, INT64, *PINT64, SSIZE_T, *PSSIZE_T;
// typedef uint64_t ULONGLONG, *PULONGLONG, UINT64, *PUINT64, SIZE_T, *PSIZE_T, ULONG64, *PULONG64, DWORD64, *PDWORD64, QWORD, *PQWORD;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0 /* Export Directory */
#define IMAGE_DOS_SIGNATURE 0x5a4d /* MZ */
#define IMAGE_NT_SIGNATURE 0x4550 /* PE00 */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define _IMAGE_DEBUG_TYPE_CODEVIEW 2

typedef uint32_t WIN32_PROTECTION_MASK;
typedef uint32_t* PWIN32_PROTECTION_MASK;

typedef uint32_t MM_PROTECTION_MASK;
typedef uint32_t* PMM_PROTECTION_MASK;

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   // NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  // bigger than 5 bits!

#define MM_INVALID_PROTECTION ((uint32_t)-1)  // bigger than 5 bits!

#define MM_PROTECTION_WRITE_MASK     4
#define MM_PROTECTION_COPY_MASK      1
#define MM_PROTECTION_OPERATION_MASK 7 // mask off guard page and nocache.
#define MM_PROTECTION_EXECUTE_MASK   2

#define MM_SECURE_DELETE_CHECK 0x55

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define _IMAGE_REL_BASED_DIR64 10

#define PAGE_NOACCESS          0x01     // winnt
#define PAGE_READONLY          0x02     // winnt
#define PAGE_READWRITE         0x04     // winnt
#define PAGE_WRITECOPY         0x08     // winnt
#define PAGE_EXECUTE           0x10     // winnt
#define PAGE_EXECUTE_READ      0x20     // winnt
#define PAGE_EXECUTE_READWRITE 0x40     // winnt
#define PAGE_EXECUTE_WRITECOPY 0x80     // winnt
#define PAGE_GUARD            0x100     // winnt
#define PAGE_NOCACHE          0x200     // winnt
#define PAGE_WRITECOMBINE     0x400     // winnt

#define MI_PTE_LOOKUP_NEEDED ((uint64_t)0xffffffff)

typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS;

#define FIELD_OFFSET offsetof

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((size_t)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS32 {
    uint32_t signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _LIST_ENTRY
{
    uint64_t Flink;
    uint64_t Blink;
} LIST_ENTRY;

typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    uint64_t Buffer;
} UNICODE_STRING;

union _LARGE_INTEGER
{
    struct
    {
        uint32_t LowPart;                                                      //0x0
        int32_t HighPart;                                                      //0x4
    };
    struct
    {
        uint32_t LowPart;                                                      //0x0
        int32_t HighPart;                                                      //0x4
    } u;                                                                    //0x0
    int64_t QuadPart;                                                      //0x0
}; 

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrdermoduleList;
    LIST_ENTRY InMemoryOrdermoduleList;
    LIST_ENTRY InInitializationOrdermoduleList;
    uint64_t BaseAddress;
    uint64_t EntryPoint;
    uint64_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    uint64_t Flags;
    short LoadCount;
    short TlsIndex;
    LIST_ENTRY HashTableEntry;
    uint64_t TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
    uint64_t Length;
    uint8_t Initialized;
    uint64_t SsHandle;
    LIST_ENTRY InLoadOrdermoduleList;
    LIST_ENTRY InMemoryOrdermoduleList;
    LIST_ENTRY InInitializationOrdermoduleList;
    uint64_t EntryInProgress;
} PEB_LDR_DATA;

typedef struct _PEB
{
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    uint8_t Padding0[4];
    uint64_t Mutant;
    uint64_t ImageBaseAddress;
    uint64_t Ldr;
} PEB, PEB64;

typedef struct _LIST_ENTRY32
{
    uint32_t f_link;
    uint32_t b_link;
} LIST_ENTRY32;

typedef struct _UNICODE_STRING32
{
    uint16_t length;
    uint16_t maximum_length;
    uint32_t buffer;
} UNICODE_STRING32;

typedef struct _LDR_MODULE32 {
    LIST_ENTRY32 InLoadOrdermoduleList;
    LIST_ENTRY32 InMemoryOrdermoduleList;
    LIST_ENTRY32 InInitializationOrdermoduleList;
    uint32_t BaseAddress;
    uint32_t EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    uint32_t Flags;
    short LoadCount;
    short TlsIndex;
    LIST_ENTRY32 HashTableEntry;
    uint32_t TimeDateStamp;
} LDR_MODULE32, *PLDR_MODULE32;

typedef struct _PEB_LDR_DATA32
{
    uint32_t Length;
    uint8_t Initialized;
    uint32_t SsHandle;
    LIST_ENTRY32 InLoadOrdermoduleList;
    LIST_ENTRY32 InMemoryOrdermoduleList;
    LIST_ENTRY32 InInitializationOrdermoduleList;
    uint32_t EntryInProgress;
} PEB_LDR_DATA32;

typedef struct _PEB32
{
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    uint32_t Mutant;
    uint32_t ImageBaseAddress;
    uint32_t Ldr;
} PEB32;

typedef struct _IMAGE_BASE_RELOCATION {
    uint32_t   VirtualAddress;
    uint32_t   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION * PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t   Characteristics;            // 0 for terminating null import descriptor
        uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    uint32_t   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    uint32_t   ForwarderChain;                 // -1 if no forwarders
    uint32_t   Name;
    uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual Addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        uint64_t ForwarderString;  // PBYTE 
        uint64_t Function;         // PDWORD
        uint64_t Ordinal;
        uint64_t AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

//@[comment("MVI_tracked")]
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        uint32_t ForwarderString;      // PBYTE 
        uint32_t Function;             // PDWORD
        uint32_t Ordinal;
        uint32_t AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
    uint16_t    Hint;
    char   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _MMPTE_HARDWARE64
{
    uint64_t Valid : 1;
    uint64_t Dirty1 : 1;
    uint64_t Owner : 1;
    uint64_t WriteThrough : 1;
    uint64_t CacheDisable : 1;
    uint64_t Accessed : 1;
    uint64_t Dirty : 1;
    uint64_t LargePage : 1;
    uint64_t Global : 1;
    uint64_t CopyOnWrite : 1;
    uint64_t Unused : 1;
    uint64_t Write : 1;
    uint64_t PageFrameNumber : 36;
    uint64_t reserved1 : 4;
    uint64_t SoftwareWsIndex : 11;
    uint64_t NoExecute : 1;
} MMPTE_HARDWARE64, *PMMPTE_HARDWARE64;

struct _MMPTE_PROTOTYPE
{
    uint64_t Valid:1;                                                      //0x0
    uint64_t DemandFillProto:1;                                            //0x0
    uint64_t HiberVerifyConverted:1;                                       //0x0
    uint64_t ReadOnly:1;                                                   //0x0
    uint64_t SwizzleBit:1;                                                 //0x0
    uint64_t Protection:5;                                                 //0x0
    uint64_t Prototype:1;                                                  //0x0
    uint64_t Combined:1;                                                   //0x0
    uint64_t Unused1:4;                                                    //0x0
    int64_t  ProtoAddress:48;                                               //0x0
}; 

struct _MMPTE_SOFTWARE
{
    uint64_t Valid:1;                                                      //0x0
    uint64_t PageFileReserved:1;                                           //0x0
    uint64_t PageFileAllocated:1;                                          //0x0
    uint64_t ColdPage:1;                                                   //0x0
    uint64_t SwizzleBit:1;                                                 //0x0
    uint64_t Protection:5;                                                 //0x0
    uint64_t Prototype:1;                                                  //0x0
    uint64_t Transition:1;                                                 //0x0
    uint64_t PageFileLow:4;                                                //0x0
    uint64_t UsedPageTableEntries:10;                                      //0x0
    uint64_t ShadowStack:1;                                                //0x0
    uint64_t Unused:5;                                                     //0x0
    uint64_t PageFileHigh:32;                                              //0x0
}; 

typedef struct _MMPTE 
{
    union  
    {
        uint64_t Long;
        MMPTE_HARDWARE64 Hard;
        struct _MMPTE_PROTOTYPE Proto;
        struct _MMPTE_SOFTWARE Soft;
    } u;
} MMPTE;
typedef MMPTE *PMMPTE;

typedef enum _MI_VAD_TYPE {
    VadNone,
    VadDevicePhysicalMemory,
    VadImageMap,
    VadAwe,
    VadWriteWatch,
    VadLargePages,
    VadRotatePhysical,
    VadLargePageSection
} MI_VAD_TYPE, *PMI_VAD_TYPE;

//0x4 bytes (Sizeof)
typedef struct _MMVAD_FLAGS
{
    uint32_t Lock:1;                                                           //0x0
    uint32_t LockContended:1;                                                  //0x0
    uint32_t DeleteInProgress:1;                                               //0x0
    uint32_t NoChange:1;                                                       //0x0
    uint32_t VadType:3;                                                        //0x0
    uint32_t Protection:5;                                                     //0x0
    uint32_t PreferredNode:6;                                                  //0x0
    uint32_t PageSize:2;                                                       //0x0
    uint32_t PrivateMemory:1;                                                  //0x0
} MMVAD_FLAGS; 

struct _MM_PRIVATE_VAD_FLAGS
{
    uint32_t Lock:1;                                                           //0x0
    uint32_t LockContended:1;                                                  //0x0
    uint32_t DeleteInProgress:1;                                               //0x0
    uint32_t NoChange:1;                                                       //0x0
    uint32_t VadType:3;                                                        //0x0
    uint32_t Protection:5;                                                     //0x0
    uint32_t PreferredNode:6;                                                  //0x0
    uint32_t PageSize:2;                                                       //0x0
    uint32_t PrivateMemoryAlwaysSet:1;                                         //0x0
    uint32_t WriteWatch:1;                                                     //0x0
    uint32_t FixedLargePageSize:1;                                             //0x0
    uint32_t ZeroFillPagesOptional:1;                                          //0x0
    uint32_t Graphics:1;                                                       //0x0
    uint32_t Enclave:1;                                                        //0x0
    uint32_t ShadowStack:1;                                                    //0x0
    uint32_t PhysicalMemoryPfnsReferenced:1;                                   //0x0
}; 

typedef struct _MMVAD_FLAGS1
{
    uint32_t CommitCharge:31;                                                  //0x0
    uint32_t MemCommit:1;                                                      //0x0
} MVAD_FLAGS1; 

struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            uint8_t Red:1;                                                    //0x10
            uint8_t Balance:2;                                                //0x10
        };
        uint64_t ParentValue;                                              //0x10
    };
}; 

struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            uint64_t Locked:1;                                             //0x0
            uint64_t Waiting:1;                                            //0x0
            uint64_t Waking:1;                                             //0x0
            uint64_t MultipleShared:1;                                     //0x0
            uint64_t Shared:60;                                            //0x0
        };
        uint64_t Value;                                                    //0x0
        void* Ptr;                                                          //0x0
    };
}; 

//0x40 bytes (Sizeof)
typedef struct _MMVAD_SHORT
{
    union
    {
        struct
        {
            struct _MMVAD_SHORT* NextVad;                                   //0x0
            void* ExtraCreateInfo;                                          //0x8
        };
        struct _RTL_BALANCED_NODE VadNode;                                  //0x0
    };
    uint32_t StartingVpn;                                                      //0x18
    uint32_t EndingVpn;                                                        //0x1c
    uint8_t StartingVpnHigh;                                                  //0x20
    uint8_t EndingVpnHigh;                                                    //0x21
    uint8_t CommitChargeHigh;                                                 //0x22
    uint8_t SpareNT64VadUchar;                                                //0x23
    int32_t ReferenceCount;                                                    //0x24
    struct _EX_PUSH_LOCK PushLock;                                          //0x28
    union
    {
        uint32_t LongFlags;                                                    //0x30
        struct _MMVAD_FLAGS VadFlags;                                       //0x30
        struct _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                       //0x30
        volatile uint32_t VolatileVadLong;                                     //0x30
    } u;                                                                    //0x30
    union
    {
        uint32_t LongFlags1;                                                   //0x34
        struct _MMVAD_FLAGS1 VadFlags1;                                     //0x34
    } u1;                                                                   //0x34
    struct _MI_VAD_EVENT_BLOCK* EventList;                                  //0x38
} MMVAD_SHORT;

struct _MMVAD_FLAGS2
{
    uint32_t FileOffset:24;                                                    //0x0
    uint32_t Large:1;                                                          //0x0
    uint32_t TrimBehind:1;                                                     //0x0
    uint32_t Inherit:1;                                                        //0x0
    uint32_t NoValidationNeeded:1;                                             //0x0
    uint32_t PrivateDemandZero:1;                                              //0x0
    uint32_t Spare:3;                                                          //0x0
};

struct _MMSECTION_FLAGS
{
    uint32_t BeingDeleted:1;                                                   //0x0
    uint32_t BeingCreated:1;                                                   //0x0
    uint32_t BeingPurged:1;                                                    //0x0
    uint32_t NoModifiedWriting:1;                                              //0x0
    uint32_t FailAllIo:1;                                                      //0x0
    uint32_t Image:1;                                                          //0x0
    uint32_t Based:1;                                                          //0x0
    uint32_t File:1;                                                           //0x0
    uint32_t AttemptingDelete:1;                                               //0x0
    uint32_t PrefetchCreated:1;                                                //0x0
    uint32_t PhysicalMemory:1;                                                 //0x0
    uint32_t ImageControlAreaOnRemovableMedia:1;                               //0x0
    uint32_t Reserve:1;                                                        //0x0
    uint32_t Commit:1;                                                         //0x0
    uint32_t NoChange:1;                                                       //0x0
    uint32_t WasPurged:1;                                                      //0x0
    uint32_t UserReference:1;                                                  //0x0
    uint32_t GlobalMemory:1;                                                   //0x0
    uint32_t DeleteOnClose:1;                                                  //0x0
    uint32_t FilePointerNull:1;                                                //0x0
    uint32_t PreferredNode:6;                                                  //0x0
    uint32_t GlobalOnlyPerSession:1;                                           //0x0
    uint32_t Userwritable:1;                                                   //0x0
    uint32_t SystemVaAllocated:1;                                              //0x0
    uint32_t PreferredFsCompressionBoundary:1;                                 //0x0
    uint32_t UsingFileExtents:1;                                               //0x0
    uint32_t PageSize64K:1;                                                    //0x0
}; 

struct _MMSECTION_FLAGS2
{
    uint16_t PartitionId:10;                                                  //0x0
    uint8_t NoCrossPartitionAccess:1;                                         //0x2
    uint8_t SubsectionCrossPartitionReferenceOverflow:1;                      //0x2
}; 

struct _EX_FAST_REF
{
    union
    {
        void* Object;                                                       //0x0
        uint64_t RefCnt:4;                                                 //0x0
        uint64_t Value;                                                    //0x0
    };
}; 

struct _CONTROL_AREA
{
    struct _SEGMENT* Segment;                                               //0x0
    union
    {
        struct _LIST_ENTRY ListHead;                                        //0x8
        void* AweContext;                                                   //0x8
    };
    uint64_t NumberOfSectionReferences;                                    //0x18
    uint64_t NumberOfPfnReferences;                                        //0x20
    uint64_t NumberOfMappedViews;                                          //0x28
    uint64_t NumberOfUserReferences;                                       //0x30
    union
    {
        uint32_t LongFlags;                                                    //0x38
        struct _MMSECTION_FLAGS Flags;                                      //0x38
    } u;                                                                    //0x38
    union
    {
        uint32_t LongFlags;                                                    //0x3c
        struct _MMSECTION_FLAGS2 Flags;                                     //0x3c
    } u1;                                                                   //0x3c
    struct _EX_FAST_REF FilePointer;                                        //0x40
    volatile int32_t ControlAreaLock;                                          //0x48
    uint32_t ModifiedWriteCount;                                               //0x4c
    struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;                           //0x50
    union
    {
        struct
        {
            union
            {
                uint32_t NumberOfSystemCacheViews;                             //0x58
                uint32_t ImageRelocationStartBit;                              //0x58
            };
            union
            {
                volatile int32_t writableUserReferences;                       //0x5c
                struct
                {
                    uint32_t ImageRelocationSizeIn64k:16;                      //0x5c
                    uint32_t SystemImage:1;                                    //0x5c
                    uint32_t CantMove:1;                                       //0x5c
                    uint32_t StrongCode:2;                                     //0x5c
                    uint32_t BitMap:2;                                         //0x5c
                    uint32_t ImageActive:1;                                    //0x5c
                    uint32_t ImageBaseOkToReuse:1;                             //0x5c
                };
            };
            union
            {
                uint32_t FlushInProgressCount;                                 //0x60
                uint32_t NumberOfSubsections;                                  //0x60
                struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;           //0x60
            };
        } e2;                                                               //0x58
    } u2;                                                                   //0x58
    struct _EX_PUSH_LOCK FileObjectLock;                                    //0x68
    volatile uint64_t LockedPages;                                         //0x70
    union
    {
        uint64_t IoAttributionContext:61;                                  //0x78
        uint64_t Spare:3;                                                  //0x78
        uint64_t ImageCrossPartitionCharge;                                //0x78
        uint64_t CommittedPageCount:36;                                    //0x78
    } u3;                                                                   //0x78
}; 

struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
}; 

struct _MMSUBSECTION_FLAGS
{
    uint16_t SubsectionAccessed:1;                                            //0x0
    uint16_t Protection:5;                                                    //0x0
    uint16_t StartingSector4132:10;                                           //0x0
    uint16_t SubsectionStatic:1;                                              //0x2
    uint16_t GlobalMemory:1;                                                  //0x2
    uint16_t Spare:1;                                                         //0x2
    uint16_t OnDereferenceList:1;                                             //0x2
    uint16_t SectorEndOffset:12;                                              //0x2
}; 

struct _MI_SUBSECTION_ENTRY1
{
    uint32_t CrossPartitionReferences:30;                                      //0x0
    uint32_t SubsectionMappedLarge:2;                                          //0x0
}; 

struct _SUBSECTION
{
    struct _CONTROL_AREA* ControlArea;                                      //0x0
    struct _MMPTE* SubsectionBase;                                          //0x8
    struct _SUBSECTION* NextSubsection;                                     //0x10
    union
    {
        struct _RTL_AVL_TREE GlobalPerSessionHead;                          //0x18
        struct _MI_CONTROL_AREA_WAIT_BLOCK* CreationWaitList;               //0x18
        struct _MI_PER_SESSION_PROTOS* SessionDriverProtos;                 //0x18
    };
    union
    {
        uint32_t LongFlags;                                                    //0x20
        struct _MMSUBSECTION_FLAGS SubsectionFlags;                         //0x20
    } u;                                                                    //0x20
    uint32_t StartingSector;                                                   //0x24
    uint32_t NumberOfFullSectors;                                              //0x28
    uint32_t PtesInSubsection;                                                 //0x2c
    union
    {
        struct _MI_SUBSECTION_ENTRY1 e1;                                    //0x30
        uint32_t EntireField;                                                  //0x30
    } u1;                                                                   //0x30
    uint32_t UnusedPtes:30;                                                    //0x34
    uint32_t ExtentQueryNeeded:1;                                              //0x34
    uint32_t DirtyPages:1;                                                     //0x34
}; 

struct _MI_VAD_SEQUENTIAL_INFO
{
    uint64_t Length:12;                                                    //0x0
    uint64_t Vpn:52;                                                       //0x0
}; 

struct _MMEXTEND_INFO
{
    uint64_t CommittedSize;                                                //0x0
    uint32_t ReferenceCount;                                                   //0x8
}; 

struct _DISPATCHER_HEADER
{
    union
    {
        volatile int32_t Lock;                                                 //0x0
        int32_t LockNV;                                                        //0x0
        struct
        {
            uint8_t Type;                                                     //0x0
            uint8_t Signalling;                                               //0x1
            uint8_t Size;                                                     //0x2
            uint8_t Reserved1;                                                //0x3
        };
        struct
        {
            uint8_t TimerType;                                                //0x0
            union
            {
                uint8_t TimerControlFlags;                                    //0x1
                struct
                {
                    uint8_t Absolute:1;                                       //0x1
                    uint8_t Wake:1;                                           //0x1
                    uint8_t EncodedTolerableDelay:6;                          //0x1
                };
            };
            uint8_t Hand;                                                     //0x2
            union
            {
                uint8_t TimerMiscFlags;                                       //0x3
                struct
                {
                    uint8_t Index:6;                                          //0x3
                    uint8_t Inserted:1;                                       //0x3
                    volatile uint8_t Expired:1;                               //0x3
                };
            };
        };
        struct
        {
            uint8_t Timer2Type;                                               //0x0
            union
            {
                uint8_t Timer2Flags;                                          //0x1
                struct
                {
                    uint8_t Timer2Inserted:1;                                 //0x1
                    uint8_t Timer2Expiring:1;                                 //0x1
                    uint8_t Timer2CancelPending:1;                            //0x1
                    uint8_t Timer2SetPending:1;                               //0x1
                    uint8_t Timer2Running:1;                                  //0x1
                    uint8_t Timer2Disabled:1;                                 //0x1
                    uint8_t Timer2ReservedFlags:2;                            //0x1
                };
            };
            uint8_t Timer2ComponentId;                                        //0x2
            uint8_t Timer2RelativeId;                                         //0x3
        };
        struct
        {
            uint8_t QueueType;                                                //0x0
            union
            {
                uint8_t QueueControlFlags;                                    //0x1
                struct
                {
                    uint8_t Abandoned:1;                                      //0x1
                    uint8_t DisableIncrement:1;                               //0x1
                    uint8_t QueueReservedControlFlags:6;                      //0x1
                };
            };
            uint8_t QueueSize;                                                //0x2
            uint8_t QueueReserved;                                            //0x3
        };
        struct
        {
            uint8_t ThReadType;                                               //0x0
            uint8_t ThReadReserved;                                           //0x1
            union
            {
                uint8_t ThReadControlFlags;                                   //0x2
                struct
                {
                    uint8_t CycleProfiling:1;                                 //0x2
                    uint8_t CounterProfiling:1;                               //0x2
                    uint8_t GroupScheduling:1;                                //0x2
                    uint8_t AffinitySet:1;                                    //0x2
                    uint8_t Tagged:1;                                         //0x2
                    uint8_t EnergyProfiling:1;                                //0x2
                    uint8_t SchedulerAssist:1;                                //0x2
                    uint8_t ThReadReservedControlFlags:1;                     //0x2
                };
            };
            union
            {
                uint8_t DebugActive;                                          //0x3
                struct
                {
                    uint8_t ActiveDR7:1;                                      //0x3
                    uint8_t Instrumented:1;                                   //0x3
                    uint8_t Minimal:1;                                        //0x3
                    uint8_t Reserved4:2;                                      //0x3
                    uint8_t AltSyscall:1;                                     //0x3
                    uint8_t UmsScheduled:1;                                   //0x3
                    uint8_t UmsPrimary:1;                                     //0x3
                };
            };
        };
        struct
        {
            uint8_t MutantType;                                               //0x0
            uint8_t MutantSize;                                               //0x1
            uint8_t DpcActive;                                                //0x2
            uint8_t MutantReserved;                                           //0x3
        };
    };
    int32_t SignalState;                                                       //0x4
    struct _LIST_ENTRY WaitListHead;                                        //0x8
}; 

struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
}; 

struct _FILE_OBJECT
{
    short Type;                                                             //0x0
    short Size;                                                             //0x2
    struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
    struct _VPB* Vpb;                                                       //0x10
    void* FsContext;                                                        //0x18
    void* FsContext2;                                                       //0x20
    struct _SECTION_OBJECT_POINTERS* SectionObjectPointer;                  //0x28
    void* PrivateCacheMap;                                                  //0x30
    int32_t FinalStatus;                                                       //0x38
    struct _FILE_OBJECT* RelatedFileObject;                                 //0x40
    unsigned char LockOperation;                                                    //0x48
    unsigned char DeletePending;                                                    //0x49
    unsigned char ReadAccess;                                                       //0x4a
    unsigned char WriteAccess;                                                      //0x4b
    unsigned char DeleteAccess;                                                     //0x4c
    unsigned char SharedRead;                                                       //0x4d
    unsigned char SharedWrite;                                                      //0x4e
    unsigned char SharedDelete;                                                     //0x4f
    uint32_t Flags;                                                            //0x50
    struct _UNICODE_STRING FileName;                                        //0x58
    union _LARGE_INTEGER CurrentByteOffset;                                 //0x68
    uint32_t Waiters;                                                          //0x70
    uint32_t Busy;                                                             //0x74
    void* LastLock;                                                         //0x78
    struct _KEVENT Lock;                                                    //0x80
    struct _KEVENT Event;                                                   //0x98
    struct _IO_COMPLETION_CONTEXT* CompletionContext;                       //0xb0
    uint64_t IrpListLock;                                                  //0xb8
    struct _LIST_ENTRY IrpList;                                             //0xc0
    void* FileObjectExtension;                                              //0xd0
}; 

typedef struct _MMVAD
{
    struct _MMVAD_SHORT Core;                                               //0x0
    union
    {
        uint32_t LongFlags2;                                                   //0x40
        struct _MMVAD_FLAGS2 VadFlags2;                            //0x40
    } u2;                                                                   //0x40
    struct _SUBSECTION* Subsection;                                         //0x48
    struct _MMPTE* FirstPrototypePte;                                       //0x50
    struct _MMPTE* LastContiguousPte;                                       //0x58
    struct _LIST_ENTRY ViewLinks;                                           //0x60
    struct _EPROCESS* Vadsprocess;                                          //0x70
    union
    {
        struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;                        //0x78
        struct _MMEXTEND_INFO* ExtendedInfo;                                //0x78
    } u4;                                                                   //0x78
    struct _FILE_OBJECT* FileObject;                                        //0x80
} MMVAD; 