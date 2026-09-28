#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD InlineProbeUnload;

static volatile LONG g_Counter;

__forceinline static ULONG
InlineProbeScale(ULONG value, ULONG factor)
{
    ULONG scaled = value * factor;

    InterlockedAdd(&g_Counter, (LONG)scaled);
    return scaled;
}

__forceinline static ULONG
InlineProbeAccumulate(ULONG value)
{
    ULONG doubled = InlineProbeScale(value, 2);
    ULONG tripled = InlineProbeScale(doubled, 3);

    return doubled ^ tripled;
}

_Use_decl_annotations_
VOID
InlineProbeUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    g_Counter = 0;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONG seed = RegistryPath->Length;
    ULONG total = InlineProbeAccumulate(seed);

    DriverObject->DriverUnload = InlineProbeUnload;
    return total == 0xFFFFFFFFu ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
