`../msvc_inline.pdb` is the PDB of `InlineProbe.c`, which MSVC built as a
KMDF-less WDM driver with this configuration:

- Visual Studio 18 with the WDK 10.0.28000 kernel-mode driver toolset.
- The command `MSBuild <project>.vcxproj /p:Configuration=Release /p:Platform=x64`.
- The options `/O2`, `/Zi`, and `/Zo`.

MSVC compiled the source as `PdbProbe.c`.

The `DriverEntry` function is at RVA 0x1000 and is 0x2a bytes long. It inlines
`InlineProbeAccumulate`, which inlines `InlineProbeScale` twice, and each
`InlineProbeScale` inlines `_InlineInterlockedAdd` from the WDK. The parameters
also have the classic MSVC `S_REGREL32` records for home slots.
