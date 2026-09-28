`../msvc_inline.pdb` is the PDB of `InlineProbe.c` built as a KMDF-less WDM
driver by MSVC: Visual Studio 18 with the WDK 10.0.28000 kernel-mode driver
toolset, `MSBuild <project>.vcxproj /p:Configuration=Release /p:Platform=x64`
(`/O2`, `/Zi`, `/Zo`), the source compiled as `PdbProbe.c`. Its `DriverEntry`
(RVA 0x1000, 0x2a bytes) inlines `InlineProbeAccumulate`, which inlines
`InlineProbeScale` twice, each inlining the WDK's `_InlineInterlockedAdd`;
the parameters also have MSVC's classic `S_REGREL32` home-slot records.
