# Choosing a backend

`ntoseye` can talk to a live target four ways. Pick with `--backend kd` (default), `--backend kdnet`, `--backend gdb`, or `--backend memory`. Crash-dump mode is a separate offline attach mode selected with `--dump <file>`.

| Capability | `kd` (default) | `kdnet` | `gdb` | `memory` | `--dump` |
| --- | --- | --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe (KDCOM) | Windows KD over encrypted UDP | Hypervisor GDB stub | Direct VM-process memory | Offline crash-dump file |
| Guest configuration | Kernel debugging enabled | Kernel network debugging enabled | None | None | None |
| Host VM configuration | Serial socket | Reachable virtual NIC | Listening GDB stub | None | None |
| Execution control | Yes | Yes | Yes | No | No |
| Registers | Yes | Yes | Yes | No | Yes (crash context) |
| Memory reads | Yes | Yes | Yes | Yes | Yes |
| Kernel breakpoints | Yes | Yes | Yes | No | No |
| Usermode breakpoints | Yes | Yes | No | No | No |
| Hardware watchpoints | Yes | Yes | Yes | No | No |
| Model-specific registers | Yes | Yes | No | No | No |
| Reboot / forced crash | Yes | Yes | No | No | No |
| Bugcheck stops | Reported by the target | Reported by the target | Trapped at `nt!KeBugCheckEx` | No | Read from the dump |
| [VTL1 inspection](usage.md#secure-kernel-vtl1) (AMD64) | Host memory source only | Host memory source only | Yes | Yes | No |

## Hypervisor setup

Host-side configuration is specific to the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)

## Supported live environments

Any Windows 10/11 target reachable over the network is debuggable with `kdnet` (see the [KDNET guide](kdnet.md)); that path has nothing hypervisor-specific in it. The combinations below are where `ntoseye` additionally reads VM memory directly, sets the VM up with `ntoseye configure`, and offers the `gdb` and `memory` backends:

| Host OS | Hypervisor | Guest architecture | `kd` | `kdnet` | `gdb` | `memory` |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | KVM/QEMU | AMD64 | Yes | Yes | Yes | Yes |
| Linux | VMware Workstation | AMD64 | Yes | Yes | Yes | Yes |
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | Yes | Yes (see below) | Yes |

Other hypervisors are untested with these integrations. Crash-dump analysis supports AMD64 and ARM64 dumps.

Under UTM the `gdb` backend needs "Use Hypervisor" turned off, because QEMU aborts the VM when a debugger enables guest debugging on HVF; the [UTM guide](utm.md) has the details. The other backends are unaffected, since none of them asks the hypervisor for debug traps.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## KDNET

Guest, host, and per-hypervisor setup for the `kdnet` backend is in the [KDNET guide](kdnet.md). In the guest, `kdnet.exe <host-ip> 50000` does the whole configuration and prints the key; on the host, `ntoseye --backend kdnet --kdnet-key <key>`.

## KD and KDNET memory sources

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) reads direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces target-mediated reads: kernel-space addresses under any process context, and user-space addresses of the process the current processor is running (AMD64), go through `DbgKdReadVirtualMemory`; user space of any other process goes through `DbgKdReadPhysicalMemory` behind a host page walk whose translations are cached until the target next runs. Session space resolves in the halted processor's session, as in WinDbg.

The source controls reads. Where the target can service virtual writes, all sources use `DbgKdWriteVirtualMemory`; other addresses use a page walk and `DbgKdWritePhysicalMemory`. A virtual write resolves through the target's own page tables and refuses a page it will not write; a physical or host-memory write reaches whatever frame is mapped, reports nothing, and follows that frame if the guest remaps it.

Neither preserves write protection or copy-on-write. The kernel services a debugger write with `MMDBG_COPY_UNSAFE`, which makes the PTE writable for the duration instead of taking the fault that would copy a shared page; the copy-on-write path beside it requires IRQL <= APC_LEVEL, which a debugger holding every other processor frozen can never reach. A breakpoint written into a shared image page is therefore visible to every process mapping that page, however it was written. See [breakpoints](#user-mode-breakpoints-in-shared-pages).

The host mapping's identity is re-checked after a guest reboot rebuilds debugger state, not just at attach.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory. Every read is a request/reply round trip. Over KDCOM on an emulated UART the request alone costs about 2 ms before the target sees it: QEMU's 16550 hands the guest one byte per main-loop iteration at the FIFO trigger level KDCOM programs, and a KD request plus its ACK is ~90 bytes host-to-guest. The reply then costs about 5 µs per byte (a 2 KiB read is ~12 ms), and KDNET has neither floor. Prefer `--memory-source host` (the `auto` default) whenever the VM is local; otherwise the session is shaped to need few, short reads:

- Virtual reads through the target are served from a cache of 512-byte lines for as long as the target stays halted. A miss fetches from its line to the end of the request, so the fields of one structure cost a single request between them while a large read still costs the same 2 KiB requests it always did (a KDNET datagram carries 1 KiB of data, and fills adapt to that after the first short reply). The cache is dropped when the target runs and whenever the debugger writes memory or installs or removes a breakpoint.
- The host page walk (user space of a process other than the halted processor's) reads page-table entries in the same 512-byte lines, so adjacent pages share their upper-level entries and their run of PTEs; other physical reads get no read-ahead, since they may touch a device. A process's loader list is walked once per halt, however many of its threads are unwound.
- Module images are never copied whole. Attach reads each module's headers with one probe; the unwinder fetches 2 KiB blocks of `.pdata`/`.rdata` as its lookups touch them and keeps them for the session, and a stack walk reads the stack a page at a time.
- A module's PDB is remembered by the image identity the symbol server uses (`~/.ntoseye/symbols/identities`, keyed by file name, `TimeDateStamp`, and `SizeOfImage`, all of which the loader's module list already carries). A module seen in an earlier session is identified with no reads from the target; `lm` shows such modules' symbol source as `cached`. A remembered PDB that fails to load is forgotten and the module rediscovered from the target.

Process, kernel-module, and driver-object lists are walked only when something needs them (a listing command, a tab completion, a break context in a user-mode process) and the first walk per halt serves every later use until the target runs again. The process walk reads one span per `_EPROCESS` and consults the PEB only for names the kernel's 15-byte `ImageFileName` may have truncated, so the prompt after attach and each stop no longer waits on a full process walk.

## User-mode breakpoints in shared pages

A software breakpoint is an `int3` written into a physical frame, and an image page is shared by every process mapping it. `bu /p <pid> user32!PeekMessageW` puts the byte in the single frame backing `user32.dll` for the whole machine, so every process calling that function traps. Scoping is a host-side filter: `ntoseye` compares the trapping process against the breakpoint's scope and *absorbs* a hit belonging to anyone else, removing the byte, single-stepping the instruction, writing the byte back and resuming without reporting anything.

No view shows the injected byte. A site is masked out of any read reaching the frame it was written into, so the original instruction appears under every process mapping a shared page, while a process that merely has its own memory at the same address is left alone. Only the debugger's views hide the `int3`; the guest still executes it.

The target's own breakpoint table knows nothing of these bytes, so `ntoseye` records each one in `~/.ntoseye/sites/` before writing it: the frame, the kernel base of the boot, and the original bytes. Exiting, detaching, or a terminating signal removes the byte and the record. A session that dies without that cleanup (killed, crashed) leaves both behind, and the next attach to the same target in the same boot writes the original bytes back and says how many it restored. It restores a site only while the frame still holds the breakpoint followed by the recorded bytes; a frame the guest has since restored or reused is left alone.

An absorb halts every vCPU, so a breakpoint on a busy shared symbol costs the absorb rate times the absorb cost whether or not the scoped process ever runs. Measured on a 4-vCPU Windows 11 guest, breakpoint on `nt!NtCreateFile`, file-enumeration loop running:

| Transport | Host service per absorb | Absorbs/s sustained | Guest speed |
| --- | --- | --- | --- |
| KDCOM (emulated UART) | ~30 ms | 16 | ~5% |
| KDNET | ~1 ms | 125 | ~50% |

Use KDNET for breakpoint-heavy work. Each absorb is a handful of KD request/reply round trips, and KDCOM's ~2 ms per request over an emulated UART dominates everything else. Over KDNET what remains is the guest freezing and thawing its own processors, which no debugger-side change can remove.

Three other ways to cut the cost: scope to a symbol the rest of the system does not call, since a breakpoint in the target's own image traps only that image's processes; use `ba e1`, which needs no byte in the page and so writes nothing to a shared frame, though AMD64 debug registers are per-processor here so it still traps for every process and there are only four slots; or prefer a cheap condition over a pass count, since both absorb but a false condition stops sooner.

## Paged-out memory

A page the guest has trimmed out of a working set is usually still in RAM on the standby or modified list, with its PTE left in the *transition* state. Both the host page walk and the target read those, so trimmed memory keeps reading normally. Writes to such a page are refused: the kernel is free to repurpose the frame or re-read it from disk, so the edit would be lost or land somewhere unrelated.

A page that has genuinely gone to disk reads as unavailable, and `.pagein` asks the guest to fetch it:

```
.pagein /p 5280 0x1048000
```

The guest's own debugger worker thread does the work, so the target is resumed and comes back halted at `nt!DbgBreakPointWithStatus` rather than wherever it was. Nothing can fault a page in while every processor is frozen, so that resume is inherent rather than an implementation choice. `/p` attaches the worker to a process first, which user-space addresses need.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.

## Secure kernel (VTL1)

`.vtl 1` and `!trustlets` inspect the VBS secure kernel and its trustlets on AMD64 guests (see [REPL usage](usage.md#secure-kernel-vtl1)). The NT kernel's debugger interface cannot read VTL1 memory, so this needs direct host memory: the `memory` and `gdb` backends, or `kd`/`kdnet` while reads come from host memory. KD sessions can inspect VTL1 but not control its execution. `--memory-source kd` and crash dumps are unsupported.

On AMD64 QEMU/KVM, `gdb` additionally supports nonpatching hardware execution breakpoints (`ba e1`) in secure-kernel modules, real VTL1 register/stack inspection at those stops, and continue. Explicit `.vtl` memory selection alone supplies no register context. Software breakpoints, secure writes, and single-stepping remain unsupported; see the linked usage section for the tested HVCI configuration and limits.
