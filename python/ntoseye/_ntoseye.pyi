"""
The native module of the ntoseye SDK. Import from `ntoseye`, which
re-exports all of it.
"""

from collections.abc import Callable, Sequence
from ntoseye import Diagnostic
from typing import Any, Final, Literal, final

__version__: Final[str]
"""
The ntoseye release version of this extension.
"""

build: Final[str]
"""
The git commit of this extension build (`<commit>`, `<commit>-dirty`, or
`unknown`). Use it to find a stale extension in a long-lived
interpreter.
"""

@final
class Ace(BaseRecord):
    """
    An ACE in an ACL. ntoseye reads the mask and the SID separately, so a
    damaged body does not hide the type and flags of the header.
    """
    @property
    def access_mask(self, /) -> Diagnostic[int]: ...
    @property
    def flag_names(self, /) -> str: ...
    @property
    def flags(self, /) -> int:
        """
        The inheritance flags.
        """
    @property
    def index(self, /) -> int:
        """
        The position of the ACE in the ACL.
        """
    @property
    def sid(self, /) -> Diagnostic[Sid]: ...
    @property
    def type(self, /) -> int: ...
    @property
    def type_name(self, /) -> str: ...

@final
class Acl(BaseRecord):
    """
    A decoded ACL header and its ACEs (`!acl`).
    """
    @property
    def ace_count(self, /) -> int: ...
    @property
    def aces(self, /) -> list[Ace]: ...
    @property
    def address(self, /) -> int: ...
    @property
    def bounded(self, /) -> bool:
        """
        Whether `ace_count` is more than the decoder limit, in which case
        `aces` contains only the first ACEs.
        """
    @property
    def revision(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """
    @property
    def unknown_revision(self, /) -> bool:
        """
        Whether the decoder does not recognize `revision`, in which case
        `aces` is empty.
        """

@final
class AddressDescription(BaseRecord):
    """
    What an address belongs to: a loaded module (and section), a process VAD
    region, a kernel region, or nothing that ntoseye recognizes.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int:
        """
        The address space of the lookup.
        """
    @property
    def kind(self, /) -> str:
        """
        `kernel-module`, `user-image`, `kernel-region`, `private`,
        `mapped`, or `unknown`.
        """
    @property
    def module(self, /) -> AddressModule |None:
        """
        The module containing the address, if any.
        """
    @property
    def region(self, /) -> MemoryRegion |None:
        """
        The region containing the address, if any.
        """
    @property
    def section(self, /) -> str |None:
        """
        The module section containing the address, if any.
        """
    @property
    def va_type(self, /) -> str |None:
        """
        The `_MI_SYSTEM_VA_TYPE` name, for a kernel region.
        """

@final
class AddressModule(BaseRecord):
    """
    The loaded module that contains an address.
    """
    @property
    def base(self, /) -> int:
        """
        The module's base address.
        """
    @property
    def name(self, /) -> str:
        """
        The module's image name.
        """
    @property
    def offset(self, /) -> int:
        """
        The offset of the address from `base`.
        """
    @property
    def size(self, /) -> int:
        """
        The module's image size.
        """

@final
class AddressTranslation(BaseRecord):
    """
    A virtual address translated through the page tables of a DTB (`!vtop`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int: ...
    @property
    def large(self, /) -> bool:
        """
        Whether a large page maps it.
        """
    @property
    def levels(self, /) -> list[PageTableEntry]:
        """
        The levels read, top down.
        """
    @property
    def physical(self, /) -> int |None:
        """
        The physical address; `None` when the address is not mapped.
        """
    @property
    def section(self, /) -> bool:
        """
        Whether nothing maps the page here. If true, `physical` is the frame
        that the page's section PTE holds, for a page of a shared image or
        file view that is not touched yet.
        """
    @property
    def transition(self, /) -> bool:
        """
        Whether the leaf is a transition PTE. If true, `physical` is a frame
        that the guest still holds, but nothing maps it here and it cannot be
        written.
        """

@final
class AlpcClientPort(BaseRecord):
    """
    A client communication port that a process holds, and the ports that it
    is connected to.
    """
    @property
    def connection_name(self, /) -> str |None: ...
    @property
    def connection_port(self, /) -> int: ...
    @property
    def handle(self, /) -> int: ...
    @property
    def port(self, /) -> int: ...
    @property
    def queued(self, /) -> int |None:
        """
        The number of messages queued on the port. None if ntoseye cannot read it.
        """
    @property
    def server_owner(self, /) -> int |None:
        """
        The `_EPROCESS` of the server. None if ntoseye cannot read it.
        """
    @property
    def server_owner_name(self, /) -> str |None: ...
    @property
    def server_port(self, /) -> int: ...
    @property
    def server_queued(self, /) -> int |None:
        """
        The number of messages queued on the server port. None if ntoseye cannot
        read it.
        """

@final
class AlpcConnection(BaseRecord):
    """
    A connection to an ALPC connection port, with its communication info
    and the two ports that it connects.
    """
    @property
    def client_owner(self, /) -> int:
        """
        The `_EPROCESS` of the client.
        """
    @property
    def client_owner_name(self, /) -> str |None: ...
    @property
    def client_port(self, /) -> int: ...
    @property
    def client_queued(self, /) -> int |None:
        """
        The number of messages queued on the client port. None if ntoseye cannot
        read it.
        """
    @property
    def communication_info(self, /) -> int: ...
    @property
    def server_port(self, /) -> int: ...
    @property
    def server_queued(self, /) -> int |None:
        """
        The number of messages queued on the server port (main, large, and
        pending). None if ntoseye cannot read it.
        """

@final
class AlpcMessage(BaseRecord):
    """
    A `_KALPC_MESSAGE` (`!alpc /m`). A field is None if this Windows build
    does not have it, or if ntoseye cannot read it.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def attributes(self, /) -> Record:
        """
        The `_KALPC_MESSAGE_ATTRIBUTES` fields in this build, by snake_case
        name.
        """
    @property
    def callback_id(self, /) -> int |None: ...
    @property
    def cancel_sequence_no(self, /) -> int |None: ...
    @property
    def client_process_id(self, /) -> int |None:
        """
        `PortMessage.ClientId`, the sender.
        """
    @property
    def client_thread_id(self, /) -> int |None: ...
    @property
    def data_length(self, /) -> int |None: ...
    @property
    def extension_buffer_size(self, /) -> int |None: ...
    @property
    def message_id(self, /) -> int |None: ...
    @property
    def message_type(self, /) -> int |None:
        """
        `PortMessage.u2.s2.Type`.
        """
    @property
    def message_type_name(self, /) -> str |None:
        """
        The `LPC_*` name of the low byte of the message type.
        """
    @property
    def owner_port(self, /) -> int: ...
    @property
    def owner_port_kind(self, /) -> str |None:
        """
        The WinDbg port type name of the owner port.
        """
    @property
    def pointers(self, /) -> Record:
        """
        The pointer fields of the message in this build, by snake_case name.
        """
    @property
    def port_queue(self, /) -> int:
        """
        The port whose queue holds the message.
        """
    @property
    def port_queue_kind(self, /) -> str |None: ...
    @property
    def port_queue_owner(self, /) -> int |None:
        """
        The `_EPROCESS` that owns the queue port.
        """
    @property
    def port_queue_owner_name(self, /) -> str |None: ...
    @property
    def queue_port_type(self, /) -> int |None:
        """
        The `QueuePortType` bits of `u1.State`.
        """
    @property
    def queue_type(self, /) -> int |None:
        """
        The `QueueType` bits of `u1.State`.
        """
    @property
    def sequence_no(self, /) -> int |None: ...
    @property
    def state(self, /) -> int |None:
        """
        `u1.State`.
        """
    @property
    def state_flags(self, /) -> list[str]:
        """
        The PDB names of the one-bit `u1.s1` state flags that are set.
        """
    @property
    def total_length(self, /) -> int |None: ...

@final
class AlpcOwnedPort(BaseRecord):
    """
    A connection port that a process owns, and its connections.
    """
    @property
    def connections(self, /) -> list[AlpcConnection]: ...
    @property
    def handle(self, /) -> int: ...
    @property
    def name(self, /) -> str |None: ...
    @property
    def port(self, /) -> int: ...
    @property
    def termination(self, /) -> ListEnd: ...

@final
class AlpcPort(BaseRecord):
    """
    An `_ALPC_PORT` (`!alpc /p`). A field is None if this Windows build does
    not have it, or if ntoseye cannot read it.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def attribute_flags(self, /) -> int |None:
        """
        `PortAttributes.Flags`.
        """
    @property
    def client_port(self, /) -> int |None: ...
    @property
    def communication_info(self, /) -> int: ...
    @property
    def completion_list(self, /) -> int |None: ...
    @property
    def completion_port(self, /) -> int |None: ...
    @property
    def connection_port(self, /) -> int |None: ...
    @property
    def connection_termination(self, /) -> ListEnd |None:
        """
        How the walk of the connection list ended. None if there was no walk.
        """
    @property
    def connections(self, /) -> list[AlpcConnection]:
        """
        The connections of a connection port.
        """
    @property
    def direct_queue_length(self, /) -> int |None: ...
    @property
    def handle_count(self, /) -> int: ...
    @property
    def kind(self, /) -> str |None:
        """
        The WinDbg port type name (`ALPC_CONNECTION_PORT`, ...).
        """
    @property
    def max_message_length(self, /) -> int |None:
        """
        `PortAttributes.MaxMessageLength`.
        """
    @property
    def name(self, /) -> str |None: ...
    @property
    def owner(self, /) -> int:
        """
        The `_EPROCESS` that owns the port.
        """
    @property
    def owner_name(self, /) -> str |None: ...
    @property
    def pointer_count(self, /) -> int: ...
    @property
    def port_context(self, /) -> int |None: ...
    @property
    def port_type(self, /) -> int |None:
        """
        The `Type` bits of `u1.State`.
        """
    @property
    def queues(self, /) -> list[AlpcQueue]: ...
    @property
    def sequence_no(self, /) -> int |None: ...
    @property
    def server_port(self, /) -> int |None: ...
    @property
    def state(self, /) -> int |None:
        """
        `u1.State`.
        """
    @property
    def state_flags(self, /) -> list[str]:
        """
        The PDB names of the one-bit `u1.s1` state flags that are set.
        """

@final
class AlpcProcessPorts(BaseRecord):
    """
    The ALPC ports that a process holds handles to (`!alpc /lpp`).
    """
    @property
    def advertised_handles(self, /) -> int:
        """
        The handle count that the table reports.
        """
    @property
    def connected(self, /) -> list[AlpcClientPort]:
        """
        The client ports that the process holds.
        """
    @property
    def created(self, /) -> list[AlpcOwnedPort]:
        """
        The connection ports that the process owns.
        """
    @property
    def process(self, /) -> ProcessIdentity: ...
    @property
    def scanned_handles(self, /) -> int: ...
    @property
    def server_ports(self, /) -> int:
        """
        The number of server communication ports that the process holds,
        which are its ends of connections to its own ports.
        """
    @property
    def skipped_entries(self, /) -> int:
        """
        The number of handle-table entries that ntoseye could not read.
        """

@final
class AlpcQueue(BaseRecord):
    """
    One message queue of an ALPC port, or its wait queue.
    """
    @property
    def entries(self, /) -> list[int]:
        """
        The queued `_KALPC_MESSAGE`s. For the wait queue, the waiting
        `_ETHREAD`s.
        """
    @property
    def field(self, /) -> str:
        """
        The `_ALPC_PORT` list head, for example `PendingQueue`.
        """
    @property
    def key(self, /) -> str:
        """
        The snake_case name of the queue.
        """
    @property
    def length(self, /) -> int |None:
        """
        The count that the port keeps for the queue. None if the port keeps no
        count.
        """
    @property
    def termination(self, /) -> ListEnd: ...

@final
class Amd64TrapFrame(BaseRecord):
    """
    The x64 registers that a `_KTRAP_FRAME` saved. A register is `None` if
    the entry that built the frame does not write it. The nonvolatile
    registers r12-r15 are in the `_KEXCEPTION_FRAME`, so this type does
    not include them.
    """
    @property
    def cs(self, /) -> int: ...
    @property
    def eflags(self, /) -> int: ...
    @property
    def error_code(self, /) -> int |None:
        """
        The exception error code, which is stale for a vector that has no
        error code.
        """
    @property
    def kind(self, /) -> str |None:
        """
        The entry that built the frame: `interrupt`, `exception`,
        `system call`, or `Zw call`. `None` if the entry is unknown, and
        then only the machine frame and rbp are reliable.
        """
    @property
    def previous_irql(self, /) -> int |None:
        """
        The IRQL before the trap, which only interrupts record.
        """
    @property
    def previous_mode(self, /) -> int:
        """
        The mode that the trap came from: 0 for kernel, 1 for user.
        """
    @property
    def r10(self, /) -> int |None: ...
    @property
    def r11(self, /) -> int |None: ...
    @property
    def r8(self, /) -> int |None: ...
    @property
    def r9(self, /) -> int |None: ...
    @property
    def rax(self, /) -> int |None: ...
    @property
    def rbp(self, /) -> int: ...
    @property
    def rbx(self, /) -> int |None: ...
    @property
    def rcx(self, /) -> int |None: ...
    @property
    def rdi(self, /) -> int |None: ...
    @property
    def rdx(self, /) -> int |None: ...
    @property
    def rip(self, /) -> int: ...
    @property
    def rsi(self, /) -> int |None: ...
    @property
    def rsp(self, /) -> int: ...
    @property
    def ss(self, /) -> int |None: ...

@final
class Amd64UnwindCode(BaseRecord):
    """
    One AMD64 unwind code.
    """
    @property
    def code_offset(self, /) -> int:
        """
        The prolog offset of the end of the instruction that the code
        undoes.
        """
    @property
    def description(self, /) -> str:
        """
        The operation and its operands, for example
        `UWOP_SAVE_NONVOL rbx at +0x30`.
        """
    @property
    def op(self, /) -> int:
        """
        The `UWOP_*` operation.
        """
    @property
    def op_info(self, /) -> int:
        """
        The info nibble of the operation.
        """
    @property
    def slot(self, /) -> int:
        """
        The index of the first slot of the code.
        """

@final
class Amd64UnwindInfo(BaseRecord):
    """
    AMD64 `UNWIND_INFO`.
    """
    @property
    def code_count(self, /) -> int:
        """
        The number of unwind-code slots.
        """
    @property
    def codes(self, /) -> list[Amd64UnwindCode]: ...
    @property
    def flags(self, /) -> int:
        """
        `UNW_FLAG_*` bits.
        """
    @property
    def form(self, /) -> str:
        """
        `amd64`.
        """
    @property
    def frame_offset(self, /) -> int:
        """
        The frame pointer's offset from the stack pointer, in bytes.
        """
    @property
    def frame_register(self, /) -> str |None:
        """
        The frame pointer register, if the function sets one up.
        """
    @property
    def handler(self, /) -> UnwindHandler |None:
        """
        The exception or termination handler, for `UNW_FLAG_EHANDLER` or
        `UNW_FLAG_UHANDLER`.
        """
    @property
    def prolog_size(self, /) -> int:
        """
        The size of the prolog, in bytes.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the structure in bytes, covering the header, the codes,
        and the handler RVA or the chained entry, but not the handler's
        data.
        """
    @property
    def version(self, /) -> int: ...

@final
class Apc(BaseRecord):
    """
    A queued `_KAPC`.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def kernel_routine(self, /) -> Diagnostic[int |None]:
        """
        `KernelRoutine`.
        """
    @property
    def kernel_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `kernel_routine` as a symbol, if it resolves to one.
        """
    @property
    def normal_routine(self, /) -> Diagnostic[int |None]:
        """
        `NormalRoutine`. The value inside is `None` for a special kernel APC.
        """
    @property
    def normal_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `normal_routine` as a symbol, if it resolves to one.
        """

@final
class ApcQueues(BaseRecord):
    """
    The APC queues of all threads, of one process, or of one thread
    (`!apc`).
    """
    @property
    def layout_error(self, /) -> str |None:
        """
        The error, if ntoseye could not resolve the APC layout.
        """
    @property
    def selector(self, /) -> str |ApcSelection:
        """
        `all`, `current_thread`, or the selected thread or process.
        """
    @property
    def threads(self, /) -> list[ApcThread]: ...
    @property
    def total(self, /) -> int:
        """
        The total number of APCs in `threads`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry limit.
        """

@final
class ApcSelection(BaseRecord):
    """
    The thread or process that `!apc` inspects.
    """
    @property
    def kind(self, /) -> str:
        """
        `thread`, `process`, or `number`. A `number` is not yet resolved to
        a thread or a process.
        """
    @property
    def value(self, /) -> int:
        """
        The given value: an ETHREAD, KTHREAD, or TID, or a PID or EPROCESS.
        """

@final
class ApcThread(BaseRecord):
    """
    The kernel-mode and user-mode APC queues of a thread.
    """
    @property
    def kernel(self, /) -> list[Apc]: ...
    @property
    def kernel_termination(self, /) -> ListEnd:
        """
        How the kernel-mode list walk ended.
        """
    @property
    def state_error(self, /) -> str |None:
        """
        The error, if ntoseye could not read the APC state of the thread.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...
    @property
    def user(self, /) -> list[Apc]: ...
    @property
    def user_termination(self, /) -> ListEnd:
        """
        How the user-mode list walk ended.
        """

@final
class Arm64EpilogScope(BaseRecord):
    """
    One ARM64 epilog scope.
    """
    @property
    def first_code(self, /) -> int:
        """
        The index of the first unwind code of the epilog.
        """
    @property
    def start_offset(self, /) -> int:
        """
        The start of the epilog, in bytes from the start of the function.
        """

@final
class Arm64PackedUnwind(BaseRecord):
    """
    ARM64 unwind data that is packed into the `.pdata` entry (flag 1 or 2).
    It describes a canonical prolog, and ntoseye lists it as the codes that
    it represents.
    """
    @property
    def codes(self, /) -> list[Arm64UnwindCode]: ...
    @property
    def cr(self, /) -> int:
        """
        The `CR` field: whether and how the prolog saves the frame chain
        and the link register.
        """
    @property
    def flag(self, /) -> int:
        """
        1, or 2 for a function fragment without a prolog.
        """
    @property
    def form(self, /) -> str:
        """
        `packed`.
        """
    @property
    def frame_size(self, /) -> int:
        """
        The size of the frame, in bytes.
        """
    @property
    def homes_arguments(self, /) -> bool:
        """
        Whether the prolog stores the argument registers in their home
        locations.
        """
    @property
    def reg_f(self, /) -> int:
        """
        The `RegF` field: the saved non-volatile floating-point registers.
        """
    @property
    def reg_i(self, /) -> int:
        """
        The `RegI` field: the saved non-volatile integer registers.
        """

@final
class Arm64TrapFrame(BaseRecord):
    """
    The ARM64 registers that a `_KTRAP_FRAME` saved. The frame holds
    x0-x18, fp (x29), and lr (x30), so x19-x28 are `None`.
    """
    @property
    def bcr(self, /) -> list[int |None]:
        """
        Breakpoint control registers.
        """
    @property
    def bvr(self, /) -> list[int |None]:
        """
        Breakpoint value registers.
        """
    @property
    def cpsr(self, /) -> int |None: ...
    @property
    def esr(self, /) -> int |None: ...
    @property
    def fault_address(self, /) -> int |None:
        """
        The faulting data address (FAR).
        """
    @property
    def fp(self, /) -> int: ...
    @property
    def lr(self, /) -> int: ...
    @property
    def pc(self, /) -> int: ...
    @property
    def previous_irql(self, /) -> int |None:
        """
        The IRQL before the trap.
        """
    @property
    def previous_mode(self, /) -> int |None:
        """
        The mode that the trap came from: 0 for kernel, 1 for user.
        """
    @property
    def sp(self, /) -> int: ...
    @property
    def wcr(self, /) -> list[int |None]:
        """
        Watchpoint control registers.
        """
    @property
    def wvr(self, /) -> list[int |None]:
        """
        Watchpoint value registers.
        """
    @property
    def x0(self, /) -> int |None: ...
    @property
    def x1(self, /) -> int |None: ...
    @property
    def x10(self, /) -> int |None: ...
    @property
    def x11(self, /) -> int |None: ...
    @property
    def x12(self, /) -> int |None: ...
    @property
    def x13(self, /) -> int |None: ...
    @property
    def x14(self, /) -> int |None: ...
    @property
    def x15(self, /) -> int |None: ...
    @property
    def x16(self, /) -> int |None: ...
    @property
    def x17(self, /) -> int |None: ...
    @property
    def x18(self, /) -> int |None: ...
    @property
    def x19(self, /) -> int |None: ...
    @property
    def x2(self, /) -> int |None: ...
    @property
    def x20(self, /) -> int |None: ...
    @property
    def x21(self, /) -> int |None: ...
    @property
    def x22(self, /) -> int |None: ...
    @property
    def x23(self, /) -> int |None: ...
    @property
    def x24(self, /) -> int |None: ...
    @property
    def x25(self, /) -> int |None: ...
    @property
    def x26(self, /) -> int |None: ...
    @property
    def x27(self, /) -> int |None: ...
    @property
    def x28(self, /) -> int |None: ...
    @property
    def x29(self, /) -> int |None: ...
    @property
    def x3(self, /) -> int |None: ...
    @property
    def x30(self, /) -> int |None: ...
    @property
    def x4(self, /) -> int |None: ...
    @property
    def x5(self, /) -> int |None: ...
    @property
    def x6(self, /) -> int |None: ...
    @property
    def x7(self, /) -> int |None: ...
    @property
    def x8(self, /) -> int |None: ...
    @property
    def x9(self, /) -> int |None: ...

@final
class Arm64UnwindCode(BaseRecord):
    """
    One ARM64 unwind code.
    """
    @property
    def bytes(self, /) -> list[int]: ...
    @property
    def description(self, /) -> str:
        """
        Its name and the prolog instruction that it represents.
        """
    @property
    def index(self, /) -> int:
        """
        The index of its first byte in the code bytes.
        """

@final
class Arm64XdataUnwind(BaseRecord):
    """
    An ARM64 `.xdata` unwind record.
    """
    @property
    def code_words(self, /) -> int:
        """
        The number of 32-bit words of unwind codes.
        """
    @property
    def codes(self, /) -> list[Arm64UnwindCode]: ...
    @property
    def epilog_count(self, /) -> int: ...
    @property
    def epilog_in_header(self, /) -> bool:
        """
        The `E` bit: the header describes a single epilog.
        """
    @property
    def epilog_scopes(self, /) -> list[Arm64EpilogScope]: ...
    @property
    def exception_data(self, /) -> bool:
        """
        The `X` bit: exception data (a handler) follows.
        """
    @property
    def form(self, /) -> str:
        """
        `xdata`.
        """
    @property
    def handler(self, /) -> UnwindHandler |None: ...
    @property
    def size(self, /) -> int:
        """
        The size of the record in bytes, including the RVA of the handler.
        """
    @property
    def version(self, /) -> int: ...

@final
class AttachedDevice(BaseRecord):
    """
    A device on the `AttachedDevice` stack of a device.
    """
    @property
    def device(self, /) -> int: ...
    @property
    def device_type(self, /) -> int: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...

@final
class BackendCapability(BaseRecord):
    """
    A row of the capability matrix of the backend.
    """
    @property
    def capability(self, /) -> str:
        """
        Stable identifier (`memory_introspection`, ...).
        """
    @property
    def label(self, /) -> str:
        """
        Human-readable name.
        """
    @property
    def supported(self, /) -> bool: ...

class BaseRecord:
    """
    An immutable, ordered set of named fields with dict access. It is the base
    of `Record` and of all typed result classes (`PciFunction`, ...), whose
    properties give the type of each field.
    """
    def __contains__(self, key: str, /) -> bool: ...
    def __dir__(self, /) -> list[str]: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, key: str, /) -> Any: ...
    def __iter__(self, /) -> NameIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, key: str, default: Any |None = None) -> Any:
        """
        The field, or `default` if the record has no field with that name.
        """
    def items(self, /) -> list[tuple[str, Any]]:
        """
        `(name, value)` pairs, in order.
        """
    def keys(self, /) -> list[str]:
        """
        The field names, in order.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        A plain nested `dict`, with all records and diagnostics converted, in
        the shape that the MCP `format=json` surface returns.
        """
    def values(self, /) -> list[Any]:
        """
        The field values, in order.
        """

@final
class BigPoolAllocation(BaseRecord):
    """
    A large allocation from `PoolBigPageTable`.
    """
    @property
    def address(self, /) -> int:
        """
        The allocation's address.
        """
    @property
    def entry(self, /) -> int:
        """
        The address of the `PoolBigPageTable` entry.
        """
    @property
    def index(self, /) -> int:
        """
        The entry's index in `PoolBigPageTable`.
        """
    @property
    def nonpaged(self, /) -> bool: ...
    @property
    def offset(self, /) -> int:
        """
        The offset of the requested address in the allocation.
        """
    @property
    def pattern(self, /) -> int: ...
    @property
    def pool_flags(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The allocation size in bytes.
        """
    @property
    def slush_size(self, /) -> int: ...
    @property
    def tag(self, /) -> int: ...
    @property
    def tag_name(self, /) -> str:
        """
        The tag as its four characters.
        """
    @property
    def target(self, /) -> int:
        """
        The requested address.
        """

@final
class BlackboxStream(BaseRecord):
    """
    A blackbox stream (pnp, ntfs, bsd, winlogon) of a crash dump, whose
    payload ntoseye does not parse.
    """
    @property
    def available(self, /) -> bool:
        """
        `True` if the payload is available. Always `False`.
        """
    @property
    def kind(self, /) -> str:
        """
        `pnp`, `ntfs`, `bsd`, or `winlogon`.
        """
    @property
    def name(self, /) -> str:
        """
        The stream's recorded name.
        """
    @property
    def parsed(self, /) -> bool:
        """
        `True` if ntoseye parsed the payload. Always `False`.
        """
    @property
    def present(self, /) -> bool |None:
        """
        `True` if the dump records the stream. `None` if the dump has no
        stream directory that shows this.
        """
    @property
    def reason(self, /) -> str:
        """
        The reason that the payload is not available.
        """
    @property
    def size(self, /) -> int |None:
        """
        The stream's size in bytes, when recorded.
        """

class Breakpoint:
    """
    A breakpoint handle. Because a breakpoint stays when ntoseye builds the
    target again, and a symbolic breakpoint resolves again after a reboot, the
    handle has no generation stamp and becomes invalid only when the breakpoint
    is deleted.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def action(self, /) -> str |None:
        """
        The optional command action (`do` in WinDbg).
        """
    @property
    def address(self, /) -> int:
        """
        The address from the most recent resolution.
        """
    @property
    def condition(self, /) -> str |None:
        """
        The optional expression condition.
        """
    @condition.setter
    def condition(self, /, condition: str |None) -> None:
        """
        Assigning an expression raises `ValueError` while a `when=` callback is
        attached, and `add()` also raises it if you give both.
        """
    def delete(self, /) -> None:
        """
        Remove this breakpoint. A breakpoint that is already gone, such as a
        one-shot breakpoint after its hit, is left as it is.
        """
    @property
    def enabled(self, /) -> bool:
        """
        True if this breakpoint is enabled.
        """
    @enabled.setter
    def enabled(self, /, enabled: bool) -> None: ...
    @property
    def hit_count(self, /) -> int:
        """
        The number of physical hits.
        """
    @property
    def hypercall(self, /) -> HypercallFilter |None:
        """
        What a hypercall breakpoint stops on: its call code and the caller's
        partition and VP, if restricted. `None` for any other breakpoint.
        """
    @property
    def id(self, /) -> int:
        """
        The breakpoint ID, which does not change.
        """
    @property
    def one_shot(self, /) -> bool:
        """
        True if ntoseye removes the breakpoint after the first hit that stops
        the target.
        """
    @one_shot.setter
    def one_shot(self, /, one_shot: bool) -> None: ...
    @property
    def pass_count(self, /) -> int:
        """
        The requested number of hits before the breakpoint stops the target.
        """
    @pass_count.setter
    def pass_count(self, /, pass_count: int) -> None: ...
    @property
    def process(self, /) -> Process |None:
        """
        The process restriction, if the breakpoint has a process scope.
        """
    @property
    def processor(self, /) -> int |None:
        """
        The processor filter, if any.
        """
    @property
    def remaining_pass_count(self, /) -> int:
        """
        The number of hits that remain before this breakpoint stops the target.
        """
    @property
    def resolved(self, /) -> bool:
        """
        True if the site is set at an address. A symbolic breakpoint whose
        module is not loaded yet stays unresolved until the module loads.
        """
    @property
    def specification(self, /) -> str |None:
        """
        The symbol or source identity that you used to make this breakpoint.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The resolved display symbol, if known.
        """
    @property
    def temporary(self, /) -> bool:
        """
        True if this is a temporary run-to breakpoint.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread restriction, if any.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Get the breakpoint state as a plain `dict`, in the shape that MCP shows.
        """
    @property
    def valid(self, /) -> bool:
        """
        True if the breakpoint still exists in this session.
        """
    @property
    def vm_exit(self, /) -> ExitFilter |None:
        """
        What a VM-exit breakpoint stops on: its exit reason and the caller's
        partition and VP, if restricted. `None` for any other breakpoint.
        """

@final
class BreakpointIterator:
    """
    Iterator over `dbg.breakpoints`.
    """
    def __iter__(self, /) -> BreakpointIterator: ...
    def __next__(self, /) -> Breakpoint: ...

@final
class BreakpointStatus(BaseRecord):
    """
    A code breakpoint or data watchpoint (`bl`).
    """
    @property
    def action(self, /) -> str |None:
        """
        The commands that run when the breakpoint breaks.
        """
    @property
    def address(self, /) -> int |None:
        """
        None while a symbolic or source breakpoint is deferred.
        """
    @property
    def condition(self, /) -> str |None:
        """
        The condition expression that a hit must satisfy.
        """
    @property
    def deferred(self, /) -> bool:
        """
        Whether a symbolic or source specification waits for resolution.
        """
    @property
    def enabled(self, /) -> bool: ...
    @property
    def hit_count(self, /) -> int: ...
    @property
    def hypercall(self, /) -> HypercallFilter |None:
        """
        The hypercall a hit must be handling, and from which caller, for a
        hypercall breakpoint (`!hvbp`). None for any other breakpoint.
        """
    @property
    def id(self, /) -> int: ...
    @property
    def one_shot(self, /) -> bool:
        """
        Whether ntoseye removes the breakpoint after its first break.
        """
    @property
    def pass_count(self, /) -> int:
        """
        The requested hit number. Both 0 and 1 break on the first hit.
        """
    @property
    def processor(self, /) -> int |None:
        """
        The only processor that can report a hit (`/c`). None if there is no
        processor restriction.
        """
    @property
    def remaining_pass_count(self, /) -> int:
        """
        The number of hits that remain before the breakpoint breaks.
        """
    @property
    def resolved(self, /) -> bool:
        """
        Whether the breakpoint resolved to an address. Use it to tell a
        deferred breakpoint from a disabled one.
        """
    @property
    def scope(self, /) -> str:
        """
        `global`, or the process that the breakpoint is limited to
        (`name (pid)`).
        """
    @property
    def specification(self, /) -> str |None:
        """
        The symbolic or source specification (`bu`/`bm`), which ntoseye
        keeps when it resolves the breakpoint again.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The display name of the current resolution.
        """
    @property
    def temporary(self, /) -> bool: ...
    @property
    def thread(self, /) -> str |None:
        """
        The only thread that can report a hit (`/t`: `tid N` or
        `ethread 0x...`). None if there is no thread restriction.
        """
    @property
    def vm_exit(self, /) -> ExitFilter |None:
        """
        The VM exit a hit must be handling, and from which caller, for a
        VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
        """
    @property
    def watch_access(self, /) -> str |None:
        """
        `write` or `read_write` for a data watchpoint. None for a code
        breakpoint.
        """
    @property
    def watch_length(self, /) -> int |None:
        """
        The watched width in bytes. None for a code breakpoint.
        """

@final
class Breakpoints:
    """
    The code breakpoints and data watchpoints, with their IDs as keys
    (`dbg.breakpoints`).
    """
    def __contains__(self, id: int, /) -> bool: ...
    def __getitem__(self, id: int, /) -> Breakpoint:
        """
        Get a breakpoint by ID, or raise `KeyError` if the ID does not exist.
        """
    def __iter__(self, /) -> BreakpointIterator:
        """
        Iterate over a new snapshot of the breakpoint handles.
        """
    def __len__(self, /) -> int:
        """
        The number of live breakpoints.
        """
    def add(self, /, target: int |str, condition: str |None = None, *, hardware: bool = False, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a code breakpoint at an address or a symbolic spec.
        
        `hardware=True` sets a debug-register execute breakpoint instead of
        patching code. The target resolves to an address once, when you call
        this method, and does not resolve again after a module reload or a
        reboot. The secure kernel (VTL1) accepts only this kind of breakpoint,
        for example `add(dbg.secure_kernel.symbols["securekernel!Func"],
        hardware=True)`.
        """
    def add_exit(self, /, reason: int |str, partition: int |None = None, vp: int |None = None, *, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a VM-exit breakpoint, as `!hvexit` does: a debug-register execute
        breakpoint on the Windows hypervisor's VM-exit entry point that stops
        only for an exit with basic exit `reason` (Intel SDM Appendix C), a
        number or a name (`"cpuid"`, `"rdmsr"`, `"ept_violation"`), and, with
        `partition` and `vp`, only from that partition or VP. Every exit
        enters there, so the guest runs far slower while it is set; ntoseye
        resumes the other exits without a stop, before any `when=` callback
        runs. A hit whose caller or exit ntoseye cannot tell stops. A
        `condition` sees the caller's registers at its exit and reads its
        memory, as for `add_hypercall()`. Needs the gdb backend and the VM's
        hv-evmcs enlightenment. This feature is experimental.
        """
    def add_hypercall(self, /, call: int |str, partition: int |None = None, vp: int |None = None, *, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a hypercall breakpoint, as `!hvbp` does: a debug-register execute
        breakpoint on the Windows hypervisor's handler of `call`, a call code
        or a name (`"HvCallPostMessage"`, or `"HvCall0004"` as `x hv!*` names
        a code the TLFS does not), that stops only when the caller made that
        call, and, with `partition` (a partition ID) and `vp` (a VP index in
        it), only when the caller is that partition or VP. ntoseye resumes
        the other hits without a stop, before any `when=` callback runs. A
        hit whose caller ntoseye cannot tell stops. A `condition` sees the
        caller's registers at its VMCALL (`"rdx == 0xfb"`), not the
        hypervisor's at the handler, and reads the caller's memory: the `$p`
        operators its guest physical memory (`"$pqwo(rdx+8) == 1"` tests a
        slow call's input), the others its virtual memory. Needs the gdb
        backend and the VM's hv-evmcs enlightenment. This feature is
        experimental.
        """
    def add_pattern(self, /, pattern: str, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None, limit: int = 256) -> list[Breakpoint]:
        """
        Add symbol-identity breakpoints for the names that match a glob (`bm`).
        """
    def add_source(self, /, file: str, line: int, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> list[Breakpoint]:
        """
        Add a source breakpoint at each address that matches `file:line`.
        """
    def get(self, /, id: int) -> Breakpoint |None:
        """
        Get a breakpoint by ID, or `None` if the ID does not exist.
        """
    def watch(self, /, target: int |str, *, access: Literal["write", "read_write"] = ..., length: int = 1, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Watchpoint:
        """
        Add a hardware data watchpoint.
        """

@final
class Bugcheck(BaseRecord):
    """
    A decoded bugcheck (BSOD) with the code, the four parameters, and the
    faulting instruction if ntoseye identified it.
    """
    @property
    def args(self, /) -> list[BugcheckArgument]:
        """
        The four bugcheck parameters, each with its meaning for this code.
        """
    @property
    def code(self, /) -> int:
        """
        The bugcheck code.
        """
    @property
    def code_hex(self, /) -> str:
        """
        The code as zero-padded hex text (`0x0000000a`).
        """
    @property
    def description(self, /) -> str |None:
        """
        What the bugcheck means. `None` if the code has no description.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The responsible driver, from the dump record or from the fault site.
        """
    @property
    def fault(self, /) -> BugcheckFault |None:
        """
        The faulting instruction. `None` if ntoseye did not identify one.
        """
    @property
    def name(self, /) -> str:
        """
        The symbolic name (`IRQL_NOT_LESS_OR_EQUAL`).
        """
    @property
    def source(self, /) -> str |None:
        """
        Where ntoseye found the data if it was not in its usual place (a
        pointer in `nt!KiBugCheckData` to the real slots). Usually `None`.
        """
    @property
    def trap_frames(self, /) -> list[BugcheckTrapFrame]:
        """
        The trap frames that the parameters point to.
        """

@final
class BugcheckArgument(BaseRecord):
    """
    One bugcheck parameter and what it means for the code.
    """
    @property
    def description(self, /) -> str:
        """
        What this parameter holds for the bugcheck code. Empty if the code
        has no documented meaning for this parameter.
        """
    @property
    def index(self, /) -> int:
        """
        The parameter's position, 1 to 4.
        """
    @property
    def value(self, /) -> int: ...

@final
class BugcheckFault(BaseRecord):
    """
    The instruction a bugcheck faulted at.
    """
    @property
    def driver(self, /) -> str |None:
        """
        The driver that contains `ip`. `None` if `ip` is not in a loaded
        driver.
        """
    @property
    def ip(self, /) -> int:
        """
        The faulting instruction pointer.
        """
    @property
    def symbol(self, /) -> str:
        """
        The symbol at `ip`.
        """

@final
class BugcheckTrapFrame(BaseRecord):
    """
    A trap frame that a bugcheck parameter points to, with its decoded
    registers or the reason that decoding failed.
    """
    @property
    def address(self, /) -> int:
        """
        The address that ntoseye read the frame from.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that decoding failed. `None` if decoding succeeded.
        """
    @property
    def frame(self, /) -> Amd64TrapFrame |Arm64TrapFrame |None:
        """
        The saved registers. `None` if decoding failed.
        """
    @property
    def rip_symbol(self, /) -> str |None:
        """
        The symbol at the interrupted instruction.
        """

@final
class CacheAttribute(BaseRecord):
    """
    The `CacheAttribute` of a PFN.
    """
    @property
    def name(self, /) -> str:
        """
        The `_MI_PFN_CACHE_ATTRIBUTE` name (`MmCached`, ...).
        """
    @property
    def value(self, /) -> int: ...

@final
class CachedFile(BaseRecord):
    """
    A file that the cache manager maps a view of.
    """
    @property
    def dirty_pages(self, /) -> Diagnostic[int]: ...
    @property
    def file_name(self, /) -> Diagnostic[str]: ...
    @property
    def file_object(self, /) -> int: ...
    @property
    def file_size(self, /) -> Diagnostic[int]:
        """
        Bytes.
        """
    @property
    def mapped_vacbs(self, /) -> int: ...
    @property
    def open_count(self, /) -> Diagnostic[int]: ...
    @property
    def shared_cache_map(self, /) -> int: ...
    @property
    def valid_bytes(self, /) -> int:
        """
        The bytes in the mapped views that are present in memory.
        """
    @property
    def valid_data_length(self, /) -> Diagnostic[int]:
        """
        Bytes.
        """

@final
class CallTrace(BaseRecord):
    """
    A `wt` call trace: why it stopped, the instructions that it stepped,
    and the call tree.
    """
    @property
    def end(self, /) -> str:
        """
        `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
        `failed`. `diverted` means that an interrupt diverted a step and the
        traced thread is not known. Any value other than `returned` means
        that the tree is partial.
        """
    @property
    def error(self, /) -> str |None:
        """
        A description of the failure, for `failed`.
        """
    @property
    def instructions(self, /) -> int:
        """
        The number of single-stepped instructions.
        """
    @property
    def root(self, /) -> CallTraceFrame: ...

@final
class CallTraceFrame(BaseRecord):
    """
    One call-tree node of a `wt` trace.
    """
    @property
    def children(self, /) -> list[CallTraceFrame]:
        """
        The calls that the function made.
        """
    @property
    def instructions(self, /) -> int:
        """
        The number of instructions stepped in the function itself.
        """
    @property
    def name(self, /) -> str:
        """
        The called function.
        """

@final
class CodeViewRecord(BaseRecord):
    """
    A CodeView debug record, which identifies the PDB that the image was built with.
    """
    @property
    def age(self, /) -> int: ...
    @property
    def format(self, /) -> str:
        """
        `RSDS` (PDB 7.0) or `NB10` (PDB 2.0).
        """
    @property
    def guid(self, /) -> str |None:
        """
        The PDB GUID, for `RSDS`.
        """
    @property
    def pdb(self, /) -> str:
        """
        The PDB path that the linker recorded.
        """
    @property
    def signature(self, /) -> int |None:
        """
        The PDB timestamp signature, for `NB10`.
        """

@final
class ControlArea(BaseRecord):
    """
    The `_CONTROL_AREA` of a section, with its segment and subsections
    (`!ca`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def file_name(self, /) -> Diagnostic[str]: ...
    @property
    def file_object(self, /) -> int: ...
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `_MMSECTION_FLAGS` bits set in `flags`.
        """
    @property
    def flags(self, /) -> int:
        """
        `u.LongFlags`.
        """
    @property
    def mapped_views(self, /) -> int: ...
    @property
    def pfn_references(self, /) -> int: ...
    @property
    def section_references(self, /) -> int: ...
    @property
    def segment(self, /) -> int: ...
    @property
    def segment_detail(self, /) -> Diagnostic[ControlAreaSegment]: ...
    @property
    def subsections(self, /) -> list[Subsection]: ...
    @property
    def subsections_stopped(self, /) -> str |None:
        """
        Why the subsection walk stopped before a null `NextSubsection`.
        `None` if the walk got to a null `NextSubsection`.
        """
    @property
    def user_references(self, /) -> int: ...

@final
class ControlAreaSegment(BaseRecord):
    """
    A control area's `_SEGMENT`.
    """
    @property
    def committed_pages(self, /) -> int: ...
    @property
    def prototype_ptes(self, /) -> int |None:
        """
        `None` for the segment of a data file, whose prototype PTEs are in
        its subsections.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes.
        """
    @property
    def total_ptes(self, /) -> int: ...

@final
class Cpu:
    """
    One processor, identified by its backend vCPU ID (for example, `"p1.1"`).
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def gdt(self, /) -> Gdt:
        """
        Decode the GDT of this processor (`!gdt`).
        """
    def hypercall_caller(self, /) -> HypercallCaller |None:
        """
        The virtual processor whose hypercall this processor handles, for a
        vCPU halted in the Windows hypervisor, as `!hvcall` finds it: the
        guest partition's VP that it serves, else the root partition's VP on
        this processor. A `when=` callback of `breakpoints.add_hypercall()`
        reads the caller's registers and memory through it
        (`stop.cpu.hypercall_caller()`), as the breakpoint's condition does.
        `None` when the vCPU is not halted in the hypervisor, or the caller is
        unknown: the partitions cannot be walked, or no saved state of a VP
        that the processor runs is current.
        """
    @property
    def id(self, /) -> str:
        """
        The backend vCPU ID.
        """
    def idt(self, /, vector: int |None = None) -> Idt:
        """
        Decode one IDT vector, or the full table up to a limit (`!idt`).
        """
    def info(self, /) -> CpuInfo:
        """
        Read the processor vendor, family, model, speed, and feature bits (`!cpuinfo`).
        """
    def irql(self, /) -> Irql:
        """
        Read the current IRQL of this processor (`!irql`).
        """
    @property
    def memory(self, /) -> Memory:
        """
        Memory through the page tables that this processor has loaded (its CR3)
        at the time of the read. These are the kernel's or a process's tables, a
        VTL1 root (read-only), or a root outside NT (read-only), such as the
        hypervisor's root on a vCPU halted in the Windows hypervisor.
        """
    @property
    def msr(self, /) -> Msrs:
        """
        Model-specific registers: `cpu.msr[0xC0000082]`, `cpu.msr["IA32_LSTAR"]`.
        """
    def pcr(self, /) -> Pcr:
        """
        Decode the essential KPCR and KPRCB fields of this processor (`!pcr`).
        """
    def prcb(self, /) -> Prcb:
        """
        Decode the `_KPRCB` of this processor (`!prcb`).
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process whose page tables are loaded on this processor.
        """
    @property
    def registers(self, /) -> Registers:
        """
        The live register file of this processor. It is writable while the
        processor is halted in NT, and read-only at a recognized VTL1 stop.
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer, which needs a halted target.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        The VTL states that the hypervisor saved for this virtual processor
        (`.vtlcxr`), for a vCPU halted in the Windows hypervisor (VBS). VTL0
        comes first, and each state has the point where the VTL stopped, its
        control and segment registers, and the last exit that it took. This
        needs `hv-evmcs` on the VM, and the list is empty without it or if the
        saved state does not pass validation.
        """
    @property
    def serving(self, /) -> ServedVp |None:
        """
        The guest partition's virtual processor that this processor serves,
        for a vCPU halted in the Windows hypervisor: the VP whose exit it
        handles or that it is about to enter, with its partition ID, VP index,
        VTL, where it left off, its last exit, and the hypercall it made.
        None when the processor runs one of the root partition's VPs, or the
        hypervisor's partitions cannot be walked (no `hv-evmcs`).
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `rip`, if it resolves to one.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread that runs on this processor.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The processor as a plain `dict`, in the shape that MCP shows.
        """

@final
class CpuFeatureBits(BaseRecord):
    """
    One `_KPRCB` feature-bit field.
    """
    @property
    def name(self, /) -> str:
        """
        The `_KPRCB` field.
        """
    @property
    def value(self, /) -> Diagnostic[int]: ...

@final
class CpuInfo(BaseRecord):
    """
    The vendor, family, model, speed, and feature bits of a processor
    (`!cpuinfo`).
    """
    @property
    def family(self, /) -> Diagnostic[int]: ...
    @property
    def feature_bits(self, /) -> list[CpuFeatureBits]: ...
    @property
    def kprcb(self, /) -> Diagnostic[int]:
        """
        The `_KPRCB` address.
        """
    @property
    def mhz(self, /) -> Diagnostic[int]:
        """
        The processor speed, in MHz.
        """
    @property
    def model(self, /) -> Diagnostic[int]: ...
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def source(self, /) -> str:
        """
        The source of the values: `_KPRCB` or `triage-dump PRCB metadata`.
        """
    @property
    def stepping(self, /) -> Diagnostic[int]: ...
    @property
    def triage_fallback(self, /) -> CpuTriageFallback |None:
        """
        The triage metadata, present if ntoseye could not find the KPRCB.
        """
    @property
    def vendor(self, /) -> Diagnostic[str]:
        """
        The vendor string (`GenuineIntel`, ...).
        """
    @property
    def vendor_id(self, /) -> Diagnostic[int]:
        """
        `_KPRCB.CpuVendor`.
        """

@final
class CpuIterator:
    """
    Iterator over `dbg.cpus`.
    """
    def __iter__(self, /) -> CpuIterator: ...
    def __next__(self, /) -> Cpu: ...

@final
class CpuTriageFallback(BaseRecord):
    """
    The triage PRCB metadata of the dump, which ntoseye uses when it
    cannot read the KPRCB.
    """
    @property
    def family(self, /) -> int: ...
    @property
    def mhz(self, /) -> int:
        """
        The processor speed, in MHz.
        """
    @property
    def processor_number(self, /) -> int: ...
    @property
    def vendor(self, /) -> str: ...

@final
class Cpus:
    """
    The processors of the target, in backend vCPU order (`dbg.cpus`). The target
    must be halted to list them.
    """
    def __getitem__(self, index: int, /) -> Cpu: ...
    def __iter__(self, /) -> CpuIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, index: int) -> Cpu |None: ...

@final
class CrashContext(BaseRecord):
    """
    The process and thread that crashed, as a triage dump recorded them.
    A field is `None` if the dump does not record it.
    """
    @property
    def create_time(self, /) -> str |None:
        """
        The time when the process was created (ISO 8601 UTC). Also `None` if
        ntoseye cannot convert the recorded time.
        """
    @property
    def exit_status(self, /) -> int |None:
        """
        The process's exit status (NTSTATUS).
        """
    @property
    def parent_process_id(self, /) -> int |None: ...
    @property
    def process_id(self, /) -> int |None: ...
    @property
    def process_name(self, /) -> str |None: ...
    @property
    def thread_exit_status(self, /) -> int |None:
        """
        The thread's exit status (NTSTATUS).
        """
    @property
    def thread_id(self, /) -> int |None: ...

@final
class Culprit(BaseRecord):
    """
    The module that the available evidence identifies as the cause of the
    crash.
    """
    @property
    def confidence(self, /) -> str:
        """
        `low`, `medium`, or `high`.
        """
    @property
    def evidence(self, /) -> list[CulpritEvidence]:
        """
        The evidence that points to the module.
        """
    @property
    def module(self, /) -> str: ...

@final
class CulpritEvidence(BaseRecord):
    """
    One item of evidence for a culprit attribution.
    """
    @property
    def address(self, /) -> int |None:
        """
        The address that the evidence uses, if the evidence is an address.
        """
    @property
    def detail(self, /) -> str: ...
    @property
    def kind(self, /) -> str:
        """
        `recorded_broken_driver`, `recorded_bugcheck_driver`,
        `bugcheck_fault_address`, `exception_address`,
        `current_instruction`, or `top_frame`.
        """

@final
class DebugLog(BaseRecord):
    """
    A page of captured guest debug output.
    """
    @property
    def dropped(self, /) -> bool:
        """
        Whether the bounded ring removed lines that the caller did not read.
        """
    @property
    def lines(self, /) -> list[DebugLogLine]: ...
    @property
    def next_seq(self, /) -> int:
        """
        The cursor to give on the next call to continue after the last line.
        """

@final
class DebugLogLine(BaseRecord):
    """
    A captured line of guest debug output (DbgPrint, kernel printf).
    """
    @property
    def seq(self, /) -> int:
        """
        A monotonic sequence number that serves as the read cursor.
        """
    @property
    def text(self, /) -> str: ...
    @property
    def timestamp_ms(self, /) -> int:
        """
        The host wall-clock time when the line was complete, in milliseconds
        since the Unix epoch.
        """

@final
class Debugger:
    """
    A live debugging session. You can use it as a context manager: when the
    `with` block ends, the debugger closes (`close()`), which removes all
    breakpoints, resumes the target, and ends the session.
    
    You can use it from any Python thread, and the session thread runs the calls
    one at a time. A call that waits (`run()`, `wait()`) releases the GIL.
    Ctrl+C (`KeyboardInterrupt`) during a call stops a wait, step, or trace
    early and raises the exception, and during a `command()` that resumes the
    target it breaks in, as in the REPL. Between calls the session continues to
    service the guest, resuming breakpoint hits in the wrong process and hits
    with a false condition so the guest does not stay frozen. A debugger that
    ntoseye gives to a REPL custom command is valid only on the REPL thread, and
    only for that command.
    """
    def __enter__(self, /) -> Debugger: ...
    def __exit__(self, /, _exc_type: Any, _exc_value: Any, _traceback: Any) -> bool: ...
    def __repr__(self, /) -> str: ...
    @property
    def breakpoints(self, /) -> Breakpoints:
        """
        Code breakpoints and data watchpoints: `.add(...)`, `.watch(...)`,
        iteration, `[id]`.
        """
    @property
    def capabilities(self, /) -> list[BackendCapability]:
        """
        The capability matrix of the backend, which shows the operations that
        the transport supports.
        """
    def close(self, /) -> None:
        """
        Remove all breakpoints, let the target run, and end the session. This
        releases the connection and the single-instance lock of the target, so
        you can attach to the target again. After this call, this debugger and
        its handles raise an exception, and a second call does nothing. If
        closing fails, the target stays halted, the session stays open, and the
        error is raised. A borrowed debugger (from a REPL command) does not own
        the session and leaves it unchanged.
        """
    @property
    def coherent(self, /) -> bool:
        """
        False after a reboot until the module list of the kernel exists. During
        that period kernel symbols and breakpoints work, but process and module
        enumeration do not work yet.
        """
    def command(self, /, line: str, timeout: float |None = None) -> str:
        """
        Run a REPL command line and return its text output without styling. If a
        command resumes the target, this waits up to `timeout` seconds for the
        next stop, which then becomes `dbg.stop`. Command loops and `.sleep`
        also end when `timeout` elapses.
        """
    def cont(self, /, disposition: Literal["handled", "not_handled"] = ...) -> None:
        """
        Resume the target without a wait, and acknowledge the current exception
        as `handled` or `not_handled` (KD only).
        """
    @property
    def cpus(self, /) -> Cpus:
        """
        The processors (vCPUs) of the target: `cpus[0].registers.rip`.
        """
    def crash(self, /) -> None:
        """
        Crash the target on purpose (`.crash`), which causes a bugcheck stop.
        """
    def debug_log(self, /, since: int = 0) -> DebugLog:
        """
        Captured guest debug output (DbgPrint) since sequence `since`. To poll
        only for new lines, pass the previous `next_seq`.
        """
    @property
    def drivers(self, /) -> Drivers:
        """
        Driver objects from the `Driver` directory of the object manager:
        `drivers["Disk"]`, `.at(addr)`.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger (MASM) expression in kernel scope to an integer,
        using the registers of the stopped vCPU.
        """
    @property
    def exceptions(self, /) -> Exceptions:
        """
        Exception stop policies (`sx*`): `.set(code, mode)`, iteration, `.reset()`.
        """
    @property
    def generation(self, /) -> int:
        """
        The number of times ntoseye has rebuilt its view of the guest, for
        example after a reboot. Handles from an older generation raise
        `StaleHandleError`, so keep this value with raw addresses to know when
        they become stale.
        """
    def hypercalls(self, /) -> list[Hypercall]:
        """
        The Windows hypervisor's hypercall table, one entry per call code, as
        `!hvcalls -a` lists it. Needs the VM's `hv-evmcs` enlightenment or a
        vCPU stopped in the hypervisor. This feature is experimental.
        """
    def hypervisor_partitions(self, /) -> list[HypervisorPartition]:
        """
        The partitions of the Windows hypervisor, root first, with their
        virtual processors, as `!hvpartitions` and `!hvvps` list them. Each
        call walks them again. This needs the VM's `hv-evmcs` enlightenment or
        a vCPU stopped in the hypervisor, and an Intel host. Raises
        `NtoseyeError` if ntoseye does not recognize the layout of this
        hypervisor build. This feature is experimental.
        """
    @property
    def inspect(self, /) -> Inspect:
        """
        System-wide reports and helpers that decode an object at an address
        (`!vm`, `!pool`, ...).
        """
    def interrupt(self, /) -> Stop:
        """
        Break into the running target and return the stop that results.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Kernel virtual memory, read through the page tables of the kernel. User
        addresses are not mapped here, so read them through `process.memory`.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Loaded kernel modules: `modules["nt"]`, iteration, `.at(addr)`.
        """
    def notices(self, /) -> list[str]:
        """
        Remove and return the diagnostics that the debugger raised since the
        last call, such as a breakpoint that failed to re-arm, a breakpoint slot
        that was reclaimed, or host memory that no longer matched after a
        reload.
        """
    @property
    def physical(self, /) -> Memory:
        """
        Guest-physical memory, without address translation.
        """
    @property
    def processes(self, /) -> Processes:
        """
        Running processes, keyed by PID: `processes[4]`, `.find(name)`.
        """
    def reboot(self, /) -> None:
        """
        Reboot the target (`.reboot`). The next stop is a `Stop.Reboot`.
        """
    def reload(self, /) -> None:
        """
        Rebuild the guest state now (find the kernel again). Stops already do
        this when the backend reports a reload, and this function forces a
        rebuild.
        """
    def run(self, /, timeout: float |None = None, *, disposition: Literal["handled", "not_handled"] = ...) -> Stop |None:
        """
        Resume and wait for the next stop, resuming again automatically after a
        hit in the wrong process or a hit with a false condition. Returns the
        `Stop`, or `None` if the target is still running after `timeout`
        seconds.
        """
    def run_to(self, /, target: int |str, timeout: float |None = None, *, step: Literal["over", "into"] |None = None) -> Stop |None:
        """
        Run until execution reaches `target` (`g <addr>`), which is an address
        or a symbolic `module!name[+off]`. With `step="over"`/`"into"`,
        single-step to it (`pa`/`ta`). Other stops on the way are returned as
        they are. With `timeout`, if execution does not reach `target` in time,
        the target is interrupted where it is, and the stop is a
        `Stop.Interrupt`.
        """
    @property
    def secure_kernel(self, /) -> SecureKernel:
        """
        The VBS secure kernel (VTL1), with read-only `memory`, `symbols`,
        `types`, `modules`, and `trustlets`. ntoseye finds it in host memory on
        first use and raises `NtoseyeError` if VBS is not running or the backend
        cannot read host memory. This feature is experimental.
        """
    def step(self, /, until: Literal["call", "ret", "branch"] |None = None, timeout: float |None = None) -> Stop:
        """
        Single-step one instruction. With `until` ("call", "ret", "branch"),
        step into instructions until the next instruction of that kind
        (`tc`/`tt`/`th`). With `timeout` (seconds), an `until` walk that does
        not end in time is interrupted where it is, and the stop is a
        `Stop.Interrupt`: a `Stop.Step` always ends a walk where it was going.
        Under VBS on the gdb backend, the other vCPUs can run while the step's
        vCPU waits on them; a watchpoint hit one of them makes meanwhile ends
        the step, and is returned instead.
        """
    def step_out(self, /, timeout: float |None = None) -> Stop:
        """
        Run until the stepping thread returns from the current function (`gu`).
        With `timeout` (seconds), the thread is interrupted where it is if it
        does not return in time, and the stop is a `Stop.Interrupt`.
        """
    def step_over(self, /, until: Literal["call", "ret", "branch"] |None = None, timeout: float |None = None) -> Stop:
        """
        Step over the current instruction. With `until`, step over instructions
        until the next call, ret, or branch (`pc`/`pt`/`ph`). Stepping over a
        call runs the target until the stepping thread returns from it. With
        `timeout` (seconds), a run or walk that does not end in time is
        interrupted where it is, and the stop is a `Stop.Interrupt`.
        """
    @property
    def stop(self, /) -> Stop |None:
        """
        The current stop when the target is halted. `None` when the target runs.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
        `search(query)`, and the symbol and source paths.
        """
    @property
    def threads(self, /) -> Threads:
        """
        All Windows threads, keyed by TID: `threads[tid]`, `.at(ethread)`.
        """
    def trace_calls(self, /, limit: int = 10000) -> CallTrace:
        """
        Trace calls until the current function returns (`wt`), single-stepping
        at most `limit` instructions. Returns `{end, error, instructions,
        root}`, where `root` is the call tree and `end` gives the reason that
        tracing stopped.
        """
    @property
    def types(self, /) -> Types:
        """
        Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`.
        """
    def wait(self, /, timeout: float |None = None) -> Stop |None:
        """
        Wait for the next stop without resuming. If the target is already
        halted, return the current stop immediately, and return `None` if the
        target is still running after `timeout`.
        """
    def write_dump(self, /, path: str) -> int:
        """
        Write a full `PAGEDU64` kernel dump of the halted target to `path`
        (`.dump /f`). Returns the number of unreadable pages that were filled
        with zeros.
        """

@final
class DecodedHypercall(BaseRecord):
    """
    The hypercall of a VMCALL exit, with its input decoded as the Hyper-V
    TLFS lays it out (`!hvcall`).
    """
    @property
    def code(self, /) -> int: ...
    @property
    def decoded(self, /) -> bool:
        """
        Whether ntoseye knows the layout of the call's input. When it does
        not, `fields` holds the input as raw qwords: RDX and R8 for a fast
        call, else the first 8 qwords of the input.
        """
    @property
    def elements(self, /) -> list[HypercallElement]:
        """
        A rep call's input list, each element up to the rep count.
        """
    @property
    def fast(self, /) -> bool:
        """
        Whether the input is in registers (RDX, R8, and XMM0 to XMM5)
        rather than in memory.
        """
    @property
    def fields(self, /) -> list[HypercallField]: ...
    @property
    def input_gpa(self, /) -> int |None:
        """
        The guest physical address of the input (RDX), for a call whose
        input is in memory.
        """
    @property
    def input_value(self, /) -> int:
        """
        The hypercall input value (RCX).
        """
    @property
    def name(self, /) -> str |None:
        """
        The TLFS name, or None for a code that the TLFS does not list.
        """
    @property
    def nested(self, /) -> bool:
        """
        Whether the call is for the L0 hypervisor of a nested environment.
        """
    @property
    def output_gpa(self, /) -> int |None:
        """
        The guest physical address of the output (R8), for a call whose
        input is in memory.
        """
    @property
    def rep_count(self, /) -> int: ...
    @property
    def rep_start(self, /) -> int:
        """
        The first rep element still to process; those before it are done.
        """
    @property
    def summary(self, /) -> str:
        """
        The call on one line, as the stop header shows it.
        """
    @property
    def unavailable(self, /) -> str |None:
        """
        Why some of the input is missing: an unreadable input page, input
        in XMM registers, or input past the end of its page.
        """
    @property
    def variable_header_size(self, /) -> int:
        """
        The size of the variable input header, in qwords.
        """

@final
class DescriptorRegister(BaseRecord):
    """
    A descriptor-table register (IDTR/GDTR).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def limit(self, /) -> int:
        """
        The table limit: the table size in bytes, minus one.
        """

@final
class DevNode(BaseRecord):
    """
    A decoded `_DEVICE_NODE` and, if requested, its flat subtree
    (`!devnode`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def child(self, /) -> int: ...
    @property
    def completion_status(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def instance_path(self, /) -> str: ...
    @property
    def parent(self, /) -> int: ...
    @property
    def pdo(self, /) -> int:
        """
        Its physical device object.
        """
    @property
    def pending_irp(self, /) -> int:
        """
        The IRP that PnP waits on. 0 for none.
        """
    @property
    def previous_state(self, /) -> int: ...
    @property
    def previous_state_name(self, /) -> str: ...
    @property
    def problem(self, /) -> int:
        """
        The `CM_PROB_*` problem code. 0 for none.
        """
    @property
    def problem_name(self, /) -> str |None:
        """
        The problem code's name, when it is a known one.
        """
    @property
    def problem_status(self, /) -> int: ...
    @property
    def service_name(self, /) -> str: ...
    @property
    def sibling(self, /) -> int: ...
    @property
    def state(self, /) -> int:
        """
        `PNP_DEVNODE_STATE`.
        """
    @property
    def state_history(self, /) -> list[DevNodeHistoryState]: ...
    @property
    def state_history_entry(self, /) -> int:
        """
        `StateHistoryEntry`, the next slot in the ring.
        """
    @property
    def state_name(self, /) -> str: ...
    @property
    def subtree(self, /) -> list[DevNodeSummary]:
        """
        The nodes below this node, in depth-first order. Empty if the
        request was not recursive.
        """
    @property
    def subtree_truncated(self, /) -> bool:
        """
        Whether the walk of the subtree stopped at its limit.
        """
    @property
    def user_flags(self, /) -> int: ...

@final
class DevNodeHistoryState(BaseRecord):
    """
    A nonzero entry in the `StateHistory` ring of a device node.
    """
    @property
    def index(self, /) -> int:
        """
        Its slot in the ring.
        """
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str: ...

@final
class DevNodeSummary(BaseRecord):
    """
    The identity and state of a device node, as the subtree and triage
    lists show them.
    """
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_NODE`.
        """
    @property
    def depth(self, /) -> int:
        """
        `Level`, the depth of the node in the device tree.
        """
    @property
    def instance_path(self, /) -> str: ...
    @property
    def pdo(self, /) -> int:
        """
        Its physical device object.
        """
    @property
    def pending_irp(self, /) -> int:
        """
        The IRP that PnP waits on. 0 for none.
        """
    @property
    def problem(self, /) -> int:
        """
        The `CM_PROB_*` problem code. 0 for none.
        """
    @property
    def problem_name(self, /) -> str |None:
        """
        The problem code's name, when it is a known one.
        """
    @property
    def problem_status(self, /) -> int: ...
    @property
    def service_name(self, /) -> str: ...
    @property
    def state(self, /) -> int:
        """
        `PNP_DEVNODE_STATE`.
        """
    @property
    def state_name(self, /) -> str: ...

@final
class Device:
    """
    One `_DEVICE_OBJECT`.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_OBJECT` address.
        """
    def inspect(self, /) -> DeviceObject:
        """
        Inspect this `_DEVICE_OBJECT` and its attachment stack.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class DeviceObject(BaseRecord):
    """
    A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
    """
    @property
    def attached_device(self, /) -> int:
        """
        The device layered directly above this device. 0 if there is none.
        """
    @property
    def attached_stack(self, /) -> list[AttachedDevice]:
        """
        The `AttachedDevice` chain, from the bottom up.
        """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def current_irp(self, /) -> int: ...
    @property
    def device_extension(self, /) -> int: ...
    @property
    def device_type(self, /) -> int: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def next_device(self, /) -> int:
        """
        The next device of the driver. 0 at the end of the chain.
        """
    @property
    def object(self, /) -> int: ...
    @property
    def via_pointer(self, /) -> bool:
        """
        Whether the argument pointed to a pointer to the device object.
        """

@final
class DeviceStack(BaseRecord):
    """
    A device stack from the top filter to the PDO, and the device node of
    the PDO (`!devstack`).
    """
    @property
    def argument(self, /) -> int:
        """
        The address that you gave: a device object, a pointer to a device
        object, or a device node.
        """
    @property
    def entries(self, /) -> list[DeviceStackLayer]:
        """
        The stack, top filter first.
        """
    @property
    def pdo_devnode(self, /) -> DevNodeSummary |None:
        """
        `None` if the PDO has no device node, or if ntoseye cannot read it.
        `pdo_devnode_error` gives the reason.
        """
    @property
    def pdo_devnode_error(self, /) -> str |None: ...
    @property
    def requested_device(self, /) -> int:
        """
        The device object where the stack walk started.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the stack walk stopped at its limit.
        """

@final
class DeviceStackLayer(BaseRecord):
    """
    A device object in a device stack.
    """
    @property
    def device_extension(self, /) -> int: ...
    @property
    def device_object(self, /) -> int: ...
    @property
    def driver_name(self, /) -> str: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def is_argument(self, /) -> bool:
        """
        Whether this is the device that the stack was requested for.
        """
    @property
    def object_name(self, /) -> str: ...

@final
class DisassembledInstruction(BaseRecord):
    """
    One decoded instruction.
    """
    @property
    def asm(self, /) -> str:
        """
        The instruction text.
        """
    @property
    def comment(self, /) -> str |None:
        """
        The resolved branch or rip-relative target, if there is one.
        """
    @property
    def hex(self, /) -> str:
        """
        The bytes of the instruction, in hex.
        """
    @property
    def ip(self, /) -> int: ...
    @property
    def length(self, /) -> int:
        """
        The instruction length in bytes.
        """
    @property
    def mnemonic(self, /) -> str:
        """
        The lowercase mnemonic, without prefixes (`mov`, `ldr`). `.inst`
        for an ARM64 word that encodes no instruction.
        """
    @property
    def operands(self, /) -> list[Operand]:
        """
        The explicit operands, in instruction order.
        """

@final
class Dpc(BaseRecord):
    """
    A queued `_KDPC`.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def context(self, /) -> Diagnostic[int |None]:
        """
        `DeferredContext`.
        """
    @property
    def deferred_routine(self, /) -> Diagnostic[int |None]:
        """
        `DeferredRoutine`.
        """
    @property
    def deferred_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `deferred_routine` as a symbol, if it resolves to one.
        """
    @property
    def importance(self, /) -> Diagnostic[int]:
        """
        `Importance`.
        """

@final
class DpcQueue(BaseRecord):
    """
    One of a processor's DPC queues.
    """
    @property
    def entries(self, /) -> list[Dpc]: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def queue(self, /) -> int:
        """
        0 for the normal queue, 1 for the threaded queue.
        """
    @property
    def termination(self, /) -> ListEnd:
        """
        How the list walk ended.
        """

@final
class DpcQueues(BaseRecord):
    """
    The queued DPCs of all processors (`!dpcs`).
    """
    @property
    def errors(self, /) -> list[SchedulerError]: ...
    @property
    def queues(self, /) -> list[DpcQueue]:
        """
        The queues that are not empty.
        """
    @property
    def total(self, /) -> int:
        """
        The total number of DPCs in `queues`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry limit.
        """

@final
class Driver:
    """
    One `_DRIVER_OBJECT` and the device objects that it created.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def devices(self, /) -> list[Device]:
        """
        The device objects that this driver created.
        """
    def inspect(self, /) -> DriverObject:
        """
        Inspect the `_DRIVER_OBJECT`, its devices, and its dispatch table.
        """
    @property
    def name(self, /) -> str:
        """
        The name of the driver object.
        """
    @property
    def object(self, /) -> int:
        """
        The `_DRIVER_OBJECT` address.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the driver image.
        """
    @property
    def start(self, /) -> int:
        """
        The base address of the driver image.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The driver object as a plain `dict`, in the shape that MCP renders.
        """

@final
class DriverDeviceLink(BaseRecord):
    """
    A device on the `DeviceObject`/`NextDevice` chain of a driver.
    """
    @property
    def attached(self, /) -> int:
        """
        `AttachedDevice`, the device layered above this device. 0 if there is none.
        """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def device(self, /) -> int: ...
    @property
    def device_type(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def next(self, /) -> int:
        """
        `NextDevice`, the next device of the driver. 0 at the end of the chain.
        """

@final
class DriverIterator:
    """
    Iterator over `dbg.drivers`.
    """
    def __iter__(self, /) -> DriverIterator: ...
    def __next__(self, /) -> Driver: ...

@final
class DriverObject(BaseRecord):
    """
    A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
    """
    @property
    def devices(self, /) -> list[DriverDeviceLink]: ...
    @property
    def dispatch(self, /) -> list[IrpDispatchRoutine]:
        """
        The 28 `IRP_MJ_*` dispatch routines, in `IRP_MJ_*` code order.
        """
    @property
    def driver_section(self, /) -> int: ...
    @property
    def driver_size(self, /) -> int:
        """
        The size of the driver image in bytes.
        """
    @property
    def driver_start(self, /) -> int: ...
    @property
    def driver_unload(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        `DriverName`. None if ntoseye cannot read it.
        """
    @property
    def object(self, /) -> int: ...
    @property
    def via_pointer(self, /) -> bool:
        """
        Whether the argument pointed to a pointer to the driver object.
        """

@final
class DriverObjectSummary(BaseRecord):
    """
    A `_DRIVER_OBJECT` from the Driver and FileSystem directories of the
    object manager (`drivers`).
    """
    @property
    def device_object(self, /) -> int:
        """
        The first device on the chain of the driver. 0 if there is none.
        """
    @property
    def driver_size(self, /) -> int:
        """
        The size of the driver image in bytes.
        """
    @property
    def driver_start(self, /) -> int: ...
    @property
    def driver_unload(self, /) -> int: ...
    @property
    def name(self, /) -> str: ...
    @property
    def object(self, /) -> int: ...

@final
class Drivers:
    """
    The driver objects in the `Driver` directory of the object manager, keyed
    by name (`dbg.drivers`).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Driver: ...
    def __iter__(self, /) -> DriverIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Driver |None:
        """
        Find the driver object or image that contains `addr`.
        """
    def get(self, /, name: str) -> Driver |None:
        """
        Find a driver object by name, with or without its directory prefix.
        """

@final
class DumpException(BaseRecord):
    """
    The exception a crash dump recorded.
    """
    @property
    def address(self, /) -> int:
        """
        Where the exception occurred.
        """
    @property
    def code(self, /) -> int:
        """
        The exception code (NTSTATUS).
        """
    @property
    def code_hex(self, /) -> int:
        """
        The same code in hex.
        """
    @property
    def code_name(self, /) -> str:
        """
        The code's symbolic name.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def parameters(self, /) -> list[int]:
        """
        The exception's `ExceptionInformation` parameters.
        """

@final
class DumpSystemInfo(BaseRecord):
    """
    The system that a crash dump comes from, as the system-info stream of
    the dump records it.
    """
    @property
    def build(self, /) -> int:
        """
        The build number (the stream's minor version).
        """
    @property
    def machine(self, /) -> str:
        """
        `I386`, `AMD64`, `ARM64`, or `Unknown`.
        """
    @property
    def machine_image_type(self, /) -> int:
        """
        The machine type (`IMAGE_FILE_MACHINE_*`).
        """
    @property
    def major_version(self, /) -> int: ...
    @property
    def product_type(self, /) -> str:
        """
        `Workstation`, `DomainController`, `Server`, or `Unknown`.
        """
    @property
    def service_pack_build(self, /) -> int: ...
    @property
    def suite_mask(self, /) -> int:
        """
        The product suite (`VER_SUITE_*`) bits.
        """
    @property
    def system_time(self, /) -> str |None:
        """
        The time when the dump was taken (ISO 8601 UTC). `None` if the dump
        does not record it.
        """
    @property
    def system_up_time_secs(self, /) -> int |None:
        """
        The system uptime in seconds. `None` if the dump does not record
        it.
        """

@final
class EptDifference(BaseRecord):
    """
    A guest physical range that VTL0's and VTL1's EPTs map differently.
    """
    @property
    def end(self, /) -> int:
        """
        The end of the range (exclusive).
        """
    @property
    def start(self, /) -> int: ...
    @property
    def vtl0(self, /) -> str |None:
        """
        VTL0's access as `r-x`-style text, with `u` for user-mode execute
        under mode-based execute control, or None where VTL0 maps nothing.
        """
    @property
    def vtl1(self, /) -> str |None:
        """
        VTL1's access, as `vtl0` gives VTL0's.
        """

@final
class EptMapping(BaseRecord):
    """
    Where a guest physical address goes through one VTL's EPT, and the
    access that every level of the walk allows.
    """
    @property
    def entries(self, /) -> list[int]:
        """
        The entry of each level of the walk, from the PML4 down.
        """
    @property
    def execute(self, /) -> bool:
        """
        Execute access: supervisor-mode only when `user_execute` is not
        None.
        """
    @property
    def host_physical(self, /) -> int: ...
    @property
    def memory_type(self, /) -> int:
        """
        The EPT memory type (0 UC, 1 WC, 4 WT, 5 WP, 6 WB).
        """
    @property
    def page_size(self, /) -> int:
        """
        The size of the mapping page: 4 KiB, 2 MiB, or 1 GiB.
        """
    @property
    def read(self, /) -> bool: ...
    @property
    def user_execute(self, /) -> bool |None:
        """
        User-mode execute access when the VTL uses mode-based execute
        control, else None.
        """
    @property
    def write(self, /) -> bool: ...

@final
class ErrorCode(BaseRecord):
    """
    A decoded NTSTATUS, Win32, or HRESULT code (`!error`).
    """
    @property
    def code(self, /) -> int: ...
    @property
    def customer(self, /) -> bool |None:
        """
        Whether the code is customer-defined (its C bit).
        """
    @property
    def description(self, /) -> str: ...
    @property
    def facility(self, /) -> int |None:
        """
        The facility that the code encodes.
        """
    @property
    def kind(self, /) -> str:
        """
        `NTSTATUS`, `HRESULT`, `Win32`, or `unknown`.
        """
    @property
    def name(self, /) -> str:
        """
        The symbolic name of the code.
        """
    @property
    def severity(self, /) -> str |None:
        """
        `success`, `informational`, `warning`, or `error`. `None` for a
        Win32 code.
        """
    @property
    def win32_code(self, /) -> int |None:
        """
        The Win32 error: the code itself, or the Win32 error that a
        `HRESULT_FROM_WIN32` code wraps.
        """
    @property
    def win32_name(self, /) -> str |None:
        """
        The name of that Win32 error.
        """

@final
class EtwBuffer(BaseRecord):
    """
    A trace buffer of a logger (`_WMI_BUFFER_HEADER`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def current_offset(self, /) -> int: ...
    @property
    def data_end(self, /) -> int:
        """
        The number of bytes in the buffer that hold the header and complete
        events.
        """
    @property
    def processor(self, /) -> int: ...
    @property
    def reference_count(self, /) -> int: ...
    @property
    def saved_offset(self, /) -> int: ...
    @property
    def sequence_number(self, /) -> int: ...
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str: ...
    @property
    def timestamp(self, /) -> int:
        """
        The raw timestamp in the clock of the logger.
        """

@final
class EtwEvent(BaseRecord):
    """
    An event record that ntoseye decoded from a trace buffer. A field is
    `None` if the header kind of the event does not have it.
    """
    @property
    def activity_id(self, /) -> str |None: ...
    @property
    def buffer(self, /) -> int:
        """
        The buffer that the event came from.
        """
    @property
    def descriptor(self, /) -> EtwEventDescriptor |None: ...
    @property
    def event_class(self, /) -> EtwEventClass |None:
        """
        The class of a classic event. The JSON key is `class`.
        """
    @property
    def event_flags(self, /) -> int |None:
        """
        `EVENT_HEADER.Flags`.
        """
    @property
    def extended(self, /) -> list[EtwExtendedData]: ...
    @property
    def group(self, /) -> str |None:
        """
        The `EVENT_TRACE_GROUP_*` name of the hook id, if it is known.
        """
    @property
    def guid(self, /) -> str |None:
        """
        The provider GUID (`EVENT_HEADER`), event class GUID
        (`EVENT_TRACE_HEADER`), or message GUID (`MESSAGE_TRACE_HEADER`).
        """
    @property
    def header(self, /) -> str:
        """
        The trace header at the start of the record (`EVENT_HEADER`, ...).
        """
    @property
    def header_type(self, /) -> int: ...
    @property
    def hook_id(self, /) -> int |None:
        """
        The kernel hook id (group << 8 | type) of system and perfinfo events.
        """
    @property
    def message(self, /) -> EtwEventMessage |None: ...
    @property
    def offset(self, /) -> int:
        """
        The offset of the record in its buffer.
        """
    @property
    def payload(self, /) -> str:
        """
        The user data of the event, as hex.
        """
    @property
    def process_id(self, /) -> int |None: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The record size, with the header included (unaligned).
        """
    @property
    def system_time(self, /) -> int |None:
        """
        The FILETIME, if the clock of the logger converts to one.
        """
    @property
    def system_time_utc(self, /) -> str |None:
        """
        `system_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        """
    @property
    def thread_id(self, /) -> int |None: ...
    @property
    def timestamp(self, /) -> int |None:
        """
        The raw timestamp in the clock of the logger. A WPP message without
        `TRACE_MESSAGE_TIMESTAMP` has no timestamp.
        """

@final
class EtwEventClass(BaseRecord):
    """
    `Class.Type`/`Level`/`Version` of a classic event.
    """
    @property
    def level(self, /) -> int: ...
    @property
    def type(self, /) -> int: ...
    @property
    def version(self, /) -> int: ...

@final
class EtwEventDescriptor(BaseRecord):
    """
    The `EVENT_DESCRIPTOR` of an `EVENT_HEADER` event.
    """
    @property
    def channel(self, /) -> int: ...
    @property
    def id(self, /) -> int: ...
    @property
    def keyword(self, /) -> int: ...
    @property
    def level(self, /) -> int: ...
    @property
    def opcode(self, /) -> int: ...
    @property
    def task(self, /) -> int: ...
    @property
    def version(self, /) -> int: ...

@final
class EtwEventDump(BaseRecord):
    """
    The in-memory events of a logger, oldest first (`!wmitrace.logdump`).
    """
    @property
    def buffers_walked(self, /) -> int: ...
    @property
    def cpu_mhz(self, /) -> int |None:
        """
        Processor speed used for CpuCycle timestamps.
        """
    @property
    def events(self, /) -> list[EtwEvent]: ...
    @property
    def issues(self, /) -> list[EtwEventIssue]:
        """
        The buffers that ntoseye skipped fully (compressed), and the walks that
        stopped early.
        """
    @property
    def list_stop(self, /) -> str |None:
        """
        Why the walk of the `GlobalList` stopped before it came back to the
        list head. `None` if the walk completed.
        """
    @property
    def logger(self, /) -> EtwLogger: ...
    @property
    def message_format_note(self, /) -> str |None:
        """
        Why some WPP messages have no `text`. `None` if all messages have
        `text`.
        """
    @property
    def qpc_frequency(self, /) -> int |None:
        """
        QPC frequency used for PerfCounter timestamps.
        """
    @property
    def total_events(self, /) -> int:
        """
        The number of events found before a count kept the most recent.
        """

@final
class EtwEventIssue(BaseRecord):
    """
    A buffer in which ntoseye could not decode all events.
    """
    @property
    def buffer(self, /) -> int: ...
    @property
    def offset(self, /) -> int:
        """
        The position in the buffer where the walk stopped.
        """
    @property
    def reason(self, /) -> str: ...

@final
class EtwEventMessage(BaseRecord):
    """
    The fields that follow a `MESSAGE_TRACE_HEADER`, as the
    `TRACE_MESSAGE_*` option flags of the header select them. A field is
    `None` if the flags do not select it, and the TMF fields are `None` if
    no loaded PDB declares the trace message format (TMF) of the message.
    """
    @property
    def component_id(self, /) -> int |None: ...
    @property
    def flags(self, /) -> str |None:
        """
        The trace flag name from the TMF.
        """
    @property
    def format_error(self, /) -> str |None:
        """
        Why the payload does not fit the argument types of the TMF.
        """
    @property
    def function(self, /) -> str |None:
        """
        The function that traced the message.
        """
    @property
    def guid(self, /) -> str |None: ...
    @property
    def level(self, /) -> str |None:
        """
        The trace level from the TMF (`TRACE_LEVEL_ERROR`, or a number).
        """
    @property
    def number(self, /) -> int:
        """
        The message number.
        """
    @property
    def option_flags(self, /) -> int: ...
    @property
    def provider(self, /) -> str |None:
        """
        The provider (component) name from the TMF.
        """
    @property
    def sequence(self, /) -> int |None: ...
    @property
    def text(self, /) -> str |None:
        """
        The message text, rendered from its TMF and the payload.
        """

@final
class EtwExtendedData(BaseRecord):
    """
    An `EVENT_HEADER` extended data item.
    """
    @property
    def data(self, /) -> str:
        """
        The bytes of the item, as hex.
        """
    @property
    def type(self, /) -> int:
        """
        `EVENT_HEADER_EXT_TYPE_*`.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The name of the type, if it is known.
        """

@final
class EtwLogger(BaseRecord):
    """
    An active ETW trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
    """
    @property
    def address(self, /) -> int:
        """
        The `_WMI_LOGGER_CONTEXT`.
        """
    @property
    def buffer_size(self, /) -> int:
        """
        Bytes per buffer.
        """
    @property
    def buffers_available(self, /) -> int: ...
    @property
    def buffers_in_use(self, /) -> int:
        """
        The buffers taken from the free pool (`number_of_buffers -
        buffers_available`). Each of these buffers is current on a processor,
        full, or in a flush.
        """
    @property
    def buffers_written(self, /) -> int: ...
    @property
    def clock(self, /) -> str:
        """
        The name of what the event timestamps count.
        """
    @property
    def clock_type(self, /) -> int:
        """
        `ClockType` (`EVENT_TRACE_CLOCK_*`).
        """
    @property
    def collection_on(self, /) -> bool: ...
    @property
    def consumers(self, /) -> int: ...
    @property
    def events_lost(self, /) -> int: ...
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `Flags` bitfields that are set, from the PDB.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def flush_threshold(self, /) -> int: ...
    @property
    def flush_timer(self, /) -> int: ...
    @property
    def instance_guid(self, /) -> str: ...
    @property
    def log_buffers_lost(self, /) -> int: ...
    @property
    def log_file_name(self, /) -> str |None:
        """
        `LogFileName`. `None` if ntoseye cannot read its buffer.
        """
    @property
    def logger_id(self, /) -> int: ...
    @property
    def logger_mode(self, /) -> int: ...
    @property
    def logger_mode_names(self, /) -> list[str]:
        """
        The `EVENT_TRACE_*_MODE` bits that are set in `logger_mode`.
        """
    @property
    def logger_status(self, /) -> int: ...
    @property
    def logger_thread(self, /) -> int: ...
    @property
    def maximum_buffers(self, /) -> int: ...
    @property
    def maximum_event_size(self, /) -> int: ...
    @property
    def maximum_file_size(self, /) -> int: ...
    @property
    def minimum_buffers(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        `LoggerName`. `None` if ntoseye cannot read its buffer, which can
        happen when the pool is freed or paged out while a session stops.
        """
    @property
    def number_of_buffers(self, /) -> int: ...
    @property
    def peak_buffers(self, /) -> int: ...
    @property
    def real_time_buffers_delivered(self, /) -> int: ...
    @property
    def real_time_buffers_lost(self, /) -> int: ...
    @property
    def start_time(self, /) -> int:
        """
        `StartTime`, a FILETIME.
        """
    @property
    def start_time_utc(self, /) -> str |None:
        """
        `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`). `None` if it is
        out of range.
        """

@final
class EtwLoggerBuffers(BaseRecord):
    """
    A logger and the buffers on its `GlobalList`
    (`!wmitrace.strdump <logger>`).
    """
    @property
    def buffers(self, /) -> list[EtwBuffer]: ...
    @property
    def list_stop(self, /) -> str |None:
        """
        Why the walk of the `GlobalList` stopped before it came back to the
        list head. `None` if the walk completed.
        """
    @property
    def logger(self, /) -> EtwLogger: ...

@final
class EtwLoggerTable(BaseRecord):
    """
    All active ETW loggers of the host silo (`!wmitrace.strdump`).
    """
    @property
    def context_array(self, /) -> int:
        """
        `EtwpLoggerContext`: the array of `max_loggers` context pointers.
        """
    @property
    def loggers(self, /) -> list[EtwLogger]: ...
    @property
    def max_loggers(self, /) -> int: ...
    @property
    def silo_state(self, /) -> int: ...

@final
class ExceptionPolicy(BaseRecord):
    """
    One exception stop policy (`sx`).
    """
    @property
    def alias(self, /) -> str |None:
        """
        The WinDbg alias of the code (`av`, `bp`, ...), if it has one.
        """
    @property
    def code(self, /) -> int:
        """
        The exception code.
        """
    @property
    def command(self, /) -> str |None:
        """
        The commands that run when the exception occurs.
        """
    @property
    def disposition(self, /) -> str |None:
        """
        An explicit final action: `break`, or continue as `handled` or
        `not_handled`. None for the default action of the mode.
        """
    @property
    def mode(self, /) -> str:
        """
        `break`, `second_chance`, `notify`, or `ignore`.
        """

@final
class ExceptionPolicyIterator:
    """
    Iterator over `dbg.exceptions`.
    """
    def __iter__(self, /) -> ExceptionPolicyIterator: ...
    def __next__(self, /) -> ExceptionPolicy: ...

@final
class ExceptionRecord(BaseRecord):
    """
    A decoded `EXCEPTION_RECORD64` (`.exr`).
    """
    @property
    def code(self, /) -> int:
        """
        The exception code (NTSTATUS).
        """
    @property
    def code_name(self, /) -> str:
        """
        The code's symbolic name.
        """
    @property
    def exception_address(self, /) -> int:
        """
        Where the exception occurred.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def nested(self, /) -> int:
        """
        The address of a nested `EXCEPTION_RECORD`, or 0.
        """
    @property
    def parameters(self, /) -> list[int]:
        """
        The exception's `ExceptionInformation` parameters.
        """
    @property
    def record_address(self, /) -> int |None:
        """
        The address that ntoseye read the record from. `None` for the
        record of the current event, which ntoseye builds from the stop
        without reading it from memory.
        """

@final
class Exceptions:
    """
    The stop policy for each exception (`dbg.exceptions`, `sx*`).
    """
    def __iter__(self, /) -> ExceptionPolicyIterator:
        """
        Iterate over the configured exception-policy records.
        """
    def __len__(self, /) -> int:
        """
        The number of configured policies.
        """
    def __repr__(self, /) -> str: ...
    @property
    def module_events(self, /) -> list[ModuleEventPolicy]:
        """
        The module load and unload filters (`sx* ld[:<module>]` and
        `sx* ud[:<module>]`), in the order that you set them. Iterating over
        `dbg.exceptions` gives only the exception policies.
        """
    def reset(self, /) -> None:
        """
        Remove all configured policies and module load and unload filters, so
        ordinary exceptions break by default and module loads and unloads do
        not stop.
        """
    def set(self, /, code: int |str, mode: Literal["break", "second_chance", "notify", "ignore"], *, disposition: Literal["handled", "not_handled"] |None = None) -> None:
        """
        Set the stop policy for an exception (`sxe`/`sxd`/`sxn`/`sxi`), or set a
        module filter: `"ld"` or `"ld:<module>"` for loads, `"ud"` or
        `"ud:<module>"` for unloads. The module name is not case-sensitive, the
        extension is optional, and `*`/`?` globs work. A `"break"` load filter
        stops as `Stop.ModuleLoad` before the module entry point runs, and a
        `"break"` unload filter stops as `Stop.ModuleUnload` after the driver's
        unload routine, while the module is still listed. A `"notify"` filter
        adds a `ModLoad:` or `Unload module` line to the queue in
        `dbg.notices()`. `disposition` does not apply to `ld` or `ud`.
        """

@final
class ExecutiveObject(BaseRecord):
    """
    An executive object with its `_OBJECT_HEADER`, type, and name, and the
    entries of a directory (`!object`).
    """
    @property
    def body(self, /) -> int: ...
    @property
    def entries(self, /) -> list[ObjectDirectoryEntry] |None:
        """
        The entries of a directory. None for all other objects.
        """
    @property
    def handle_count(self, /) -> int: ...
    @property
    def header(self, /) -> int: ...
    @property
    def info_mask(self, /) -> int |None:
        """
        The `InfoMask` of the header, which shows which optional headers
        come before it.
        """
    @property
    def input(self, /) -> int:
        """
        The address that you gave.
        """
    @property
    def mode(self, /) -> str:
        """
        `body` if the input pointed to the object body, or `header` if it
        pointed to the object header.
        """
    @property
    def name(self, /) -> str |None:
        """
        None for an unnamed object.
        """
    @property
    def name_info(self, /) -> int |None:
        """
        The `_OBJECT_HEADER_NAME_INFO`. None if the object has none.
        """
    @property
    def pointer_count(self, /) -> int: ...
    @property
    def type_index(self, /) -> int |None:
        """
        The decoded `TypeIndex` of the header. None if ntoseye cannot read it.
        """
    @property
    def type_name(self, /) -> str |None: ...
    @property
    def type_object(self, /) -> int |None:
        """
        The `_OBJECT_TYPE`. None if ntoseye cannot resolve it.
        """

@final
class ExecutiveResource(BaseRecord):
    """
    An `_ERESOURCE` (`!locks <address>`).
    """
    @property
    def active_count(self, /) -> Diagnostic[int]: ...
    @property
    def address(self, /) -> int: ...
    @property
    def contention_count(self, /) -> Diagnostic[int]: ...
    @property
    def exclusive_waiters(self, /) -> Diagnostic[int]:
        """
        The number of threads that wait for exclusive access.
        """
    @property
    def flags(self, /) -> Diagnostic[int]: ...
    @property
    def owners(self, /) -> Diagnostic[list[ResourceOwner]]:
        """
        The threads that own the resource.
        """
    @property
    def shared_waiters(self, /) -> Diagnostic[int]:
        """
        The number of threads that wait for shared access.
        """

@final
class ExitFilter(BaseRecord):
    """
    What a VM-exit breakpoint (`!hvexit`) stops on: one basic exit
    reason, from any VP or from one partition or VP of the Windows
    hypervisor.
    """
    @property
    def name(self, /) -> str |None:
        """
        Its name, or None for a reason ntoseye does not name.
        """
    @property
    def partition(self, /) -> int |None:
        """
        The caller's partition ID. None for any caller.
        """
    @property
    def reason(self, /) -> int:
        """
        The basic exit reason (Intel SDM Appendix C).
        """
    @property
    def vp(self, /) -> int |None:
        """
        The caller's VP index in `partition`. None for any VP.
        """

@final
class Export(BaseRecord):
    """
    One PE export (`Module.exports`, `!dh -e`). An export has a name or
    only an ordinal, and a forwarder has no address.
    """
    @property
    def address(self, /) -> int |None:
        """
        The mapped address. `None` for a forwarder.
        """
    @property
    def forwarder(self, /) -> str |None:
        """
        The target of a forwarder (`OTHER.Function`).
        """
    @property
    def name(self, /) -> str |None:
        """
        `None` for an ordinal-only export.
        """
    @property
    def ordinal(self, /) -> int: ...
    @property
    def rva(self, /) -> int |None:
        """
        `None` for a forwarder.
        """

@final
class ExpressionValue(BaseRecord):
    """
    An evaluated debugger expression (`?`).
    """
    @property
    def expression(self, /) -> str: ...
    @property
    def value(self, /) -> int: ...

@final
class FailureSignature(BaseRecord):
    """
    A deterministic identity for a failure that does not depend on
    addresses, so you can use it to compare failures.
    """
    @property
    def bucket(self, /) -> str:
        """
        The failure bucket.
        """
    @property
    def code(self, /) -> int:
        """
        The bugcheck or exception code.
        """
    @property
    def code_kind(self, /) -> str:
        """
        `bugcheck` or `exception`.
        """
    @property
    def components(self, /) -> list[str]:
        """
        The ordered parts that make `bucket`.
        """
    @property
    def module(self, /) -> str |None:
        """
        The module at the failing location.
        """
    @property
    def source(self, /) -> str:
        """
        The source of the failing location: `bugcheck_fault`,
        `exception_address`, `current_instruction`, `top_frame`, or
        `code_only`.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at the failing location.
        """

@final
class Field(BaseRecord):
    """
    The PDB layout of a field, with its name, byte offset, byte size, and type spelling.
    """
    @property
    def name(self, /) -> str: ...
    @property
    def offset(self, /) -> int:
        """
        The byte offset in the containing type.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """
    @property
    def type(self, /) -> str:
        """
        The PDB type spelling.
        """

@final
class FileCache(BaseRecord):
    """
    The mapped views of the cache manager, from its VACB arrays
    (`!filecache`).
    """
    @property
    def active_vacbs(self, /) -> int:
        """
        The VACBs that map a view.
        """
    @property
    def file_count(self, /) -> int:
        """
        The number of shared cache maps that have a mapped view, including
        the maps that `files` does not list.
        """
    @property
    def files(self, /) -> list[CachedFile]:
        """
        One entry for each shared cache map that has a mapped view, most
        valid bytes first, up to 1,024 entries.
        """
    @property
    def free_vacbs(self, /) -> Diagnostic[int]:
        """
        `CcNumberOfFreeVacbs`.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt request stopped the walk early.
        """
    @property
    def mapped_bytes(self, /) -> int: ...
    @property
    def vacb_arrays(self, /) -> int: ...
    @property
    def valid_bytes(self, /) -> int:
        """
        The bytes in the mapped views that are present in memory.
        """

@final
class FileObject(BaseRecord):
    """
    A `_FILE_OBJECT` (`!fileobj`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def current_byte_offset(self, /) -> Diagnostic[int]: ...
    @property
    def delete_access(self, /) -> Diagnostic[bool]: ...
    @property
    def delete_pending(self, /) -> Diagnostic[bool]: ...
    @property
    def device_name(self, /) -> Diagnostic[str |None]:
        """
        The object name of the device, or None for an unnamed device.
        """
    @property
    def device_object(self, /) -> Diagnostic[int]: ...
    @property
    def device_type(self, /) -> Diagnostic[int]: ...
    @property
    def file_name(self, /) -> Diagnostic[str]: ...
    @property
    def file_type(self, /) -> Diagnostic[int]:
        """
        `Type`, which is `IO_TYPE_FILE` (5) for a valid file object.
        """
    @property
    def final_status(self, /) -> Diagnostic[int]:
        """
        The NTSTATUS that the file object completed with.
        """
    @property
    def flags(self, /) -> Diagnostic[int]: ...
    @property
    def fs_context(self, /) -> Diagnostic[int]:
        """
        The `FsContext` of the file system (its FCB).
        """
    @property
    def fs_context2(self, /) -> Diagnostic[int]:
        """
        The `FsContext2` of the file system (its CCB).
        """
    @property
    def lock_operation(self, /) -> Diagnostic[bool]: ...
    @property
    def private_cache_map(self, /) -> Diagnostic[int]: ...
    @property
    def read_access(self, /) -> Diagnostic[bool]: ...
    @property
    def related_file_object(self, /) -> Diagnostic[int]: ...
    @property
    def section_object_pointer(self, /) -> Diagnostic[int]: ...
    @property
    def shared_delete(self, /) -> Diagnostic[bool]: ...
    @property
    def shared_read(self, /) -> Diagnostic[bool]: ...
    @property
    def shared_write(self, /) -> Diagnostic[bool]: ...
    @property
    def size(self, /) -> Diagnostic[int]: ...
    @property
    def write_access(self, /) -> Diagnostic[bool]: ...

@final
class FindStack(BaseRecord):
    """
    Threads with a stack frame that matches a symbol or module
    (`!findstack`).
    """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt stopped the walk before it finished.
        """
    @property
    def level(self, /) -> int:
        """
        The detail level. 0 counts the matches, 1 lists them, and 2 adds the
        whole stacks.
        """
    @property
    def pattern(self, /) -> str: ...
    @property
    def scanned_threads(self, /) -> int: ...
    @property
    def threads(self, /) -> list[FindStackThread]: ...
    @property
    def unwalked(self, /) -> list[UnwalkedThread]: ...

@final
class FindStackThread(BaseRecord):
    """
    A thread with a stack frame that matches the `!findstack` pattern.
    """
    @property
    def frames(self, /) -> list[StackFrame] |None:
        """
        The whole walked stack, innermost first. `None` below level 2.
        """
    @property
    def match_count(self, /) -> int:
        """
        The number of frames that matched.
        """
    @property
    def matching_frames(self, /) -> list[StackFrame] |None:
        """
        The frames that matched. `None` at level 0.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...
    @property
    def truncated(self, /) -> int |None:
        """
        The number of frames past the walk limit, which ntoseye did not
        search. `None` below level 2.
        """

@final
class FltFilter(BaseRecord):
    """
    A registered minifilter (`_FLT_FILTER`) and its instances.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def altitude(self, /) -> str: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def instances(self, /) -> list[FltInstance]: ...
    @property
    def instances_stopped(self, /) -> str |None:
        """
        Why the instance walk stopped before the list head. `None` if the
        walk completed.
        """
    @property
    def name(self, /) -> str: ...

@final
class FltFilterFrame(BaseRecord):
    """
    A filter manager frame and its registered minifilters.
    """
    @property
    def address(self, /) -> int:
        """
        The `_FLTP_FRAME`.
        """
    @property
    def filters(self, /) -> list[FltFilter]: ...
    @property
    def frame_id(self, /) -> int: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the frame list stopped before the list head. `None`
        if the walk completed.
        """

@final
class FltFilters(BaseRecord):
    """
    The registered minifilters of each filter manager frame
    (`!fltkd.filters`).
    """
    @property
    def frames(self, /) -> list[FltFilterFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the frame walk stopped before the list head. `None` if the walk
        completed.
        """

@final
class FltInstance(BaseRecord):
    """
    A minifilter attached to a volume (`_FLT_INSTANCE`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def altitude(self, /) -> str: ...
    @property
    def filter(self, /) -> int:
        """
        Its `_FLT_FILTER`.
        """
    @property
    def filter_name(self, /) -> str |None: ...
    @property
    def name(self, /) -> str: ...
    @property
    def volume(self, /) -> int:
        """
        Its `_FLT_VOLUME`.
        """
    @property
    def volume_name(self, /) -> str |None: ...

@final
class FltInstanceFrame(BaseRecord):
    """
    A filter manager frame and its minifilter instances.
    """
    @property
    def address(self, /) -> int:
        """
        The `_FLTP_FRAME`.
        """
    @property
    def frame_id(self, /) -> int: ...
    @property
    def instances(self, /) -> list[FltInstance]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the frame list stopped before the list head. `None`
        if the walk completed.
        """

@final
class FltInstances(BaseRecord):
    """
    The minifilter instances of each filter manager frame
    (`!fltkd.instances`).
    """
    @property
    def frames(self, /) -> list[FltInstanceFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the frame walk stopped before the list head. `None` if the walk
        completed.
        """

@final
class FltVolume(BaseRecord):
    """
    A volume that the filter manager attached to (`_FLT_VOLUME`), and the
    instances on it.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def device_name(self, /) -> str: ...
    @property
    def file_system(self, /) -> str |None:
        """
        The `_FLT_FILESYSTEM_TYPE` name without its `FLT_FSTYPE_` prefix.
        """
    @property
    def instances(self, /) -> list[FltInstance]: ...
    @property
    def instances_stopped(self, /) -> str |None:
        """
        Why the instance walk stopped before the list head. `None` if the
        walk completed.
        """

@final
class FltVolumeFrame(BaseRecord):
    """
    A filter manager frame and its volumes.
    """
    @property
    def address(self, /) -> int:
        """
        The `_FLTP_FRAME`.
        """
    @property
    def frame_id(self, /) -> int: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the frame list stopped before the list head. `None`
        if the walk completed.
        """
    @property
    def volumes(self, /) -> list[FltVolume]: ...

@final
class FltVolumes(BaseRecord):
    """
    The volumes of each filter manager frame (`!fltkd.volumes`).
    """
    @property
    def frames(self, /) -> list[FltVolumeFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the frame walk stopped before the list head. `None` if the walk
        completed.
        """

@final
class Frame:
    """
    One recovered stack frame with the register context used for locals.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, name: str, /) -> int |None:
        """
        Get a local variable by name.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def index(self, /) -> int:
        """
        The position of the frame. The innermost frame is 0.
        """
    @property
    def inline(self, /) -> bool:
        """
        Whether the frame is a call that the compiler inlined into the physical
        frame after it. The two frames share the `ip`, `sp`, and registers.
        """
    @property
    def ip(self, /) -> int:
        """
        The instruction pointer of the frame.
        """
    @property
    def locals(self, /) -> dict[str, int |None]:
        """
        The local variables, evaluated in the recovered context of this frame.
        """
    @property
    def registers(self, /) -> Registers:
        """
        The registers of the frame: the live register file (writable) for the
        innermost frame of a running thread, and the recovered subset
        (read-only) for other frames.
        """
    @property
    def source(self, /) -> str |None:
        """
        How ntoseye recovered the frame (unwind data, frame pointer, ...).
        """
    @property
    def sp(self, /) -> int:
        """
        The stack pointer of the frame.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `ip`, if it resolves to one. For an inline frame, the
        function that the compiler inlined.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The thread that owns this stack.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class FunctionEntry(BaseRecord):
    """
    The function-table entry that covers an address, and the entry of each
    chained parent (`.fnent`).
    """
    @property
    def entries(self, /) -> list[RuntimeFunction]:
        """
        The entry that covers the address, then each parent that its chained
        unwind info names, in order.
        """
    @property
    def image_base(self, /) -> int: ...
    @property
    def incomplete(self, /) -> str |None:
        """
        The reason that the chain ends before its last parent. None if the
        chain is complete.
        """
    @property
    def module(self, /) -> str:
        """
        The module that contains the function.
        """

@final
class Gdt(BaseRecord):
    """
    The GDT of a processor and its bounded descriptors (`!gdt`).
    """
    @property
    def base(self, /) -> int:
        """
        The address of the table.
        """
    @property
    def entries(self, /) -> list[GdtDescriptor]: ...
    @property
    def entry_count(self, /) -> int:
        """
        The number of slots that the limit describes, which can be larger
        than the number of decoded entries.
        """
    @property
    def limit(self, /) -> int:
        """
        The table limit: the table size in bytes, minus one.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the table has more than 256 slots.
        """

@final
class GdtDescriptor(BaseRecord):
    """
    One decoded GDT descriptor. A system descriptor uses two slots.
    """
    @property
    def base(self, /) -> Diagnostic[int]:
        """
        The segment base.
        """
    @property
    def default_size(self, /) -> Diagnostic[bool]:
        """
        The D/B bit: 32-bit default operand size.
        """
    @property
    def descriptor_kind(self, /) -> Diagnostic[str]:
        """
        `system` or `code/data`.
        """
    @property
    def dpl(self, /) -> Diagnostic[int]:
        """
        The descriptor privilege level.
        """
    @property
    def granularity(self, /) -> Diagnostic[bool]:
        """
        The G bit: the limit is in 4 KiB pages.
        """
    @property
    def high_raw(self, /) -> Diagnostic[int |None]:
        """
        The second slot of a system descriptor. The diagnostic value is
        None for other descriptors.
        """
    @property
    def index(self, /) -> int:
        """
        The slot index.
        """
    @property
    def limit(self, /) -> Diagnostic[int]:
        """
        The segment limit, in bytes.
        """
    @property
    def long_mode(self, /) -> Diagnostic[bool]:
        """
        The L bit: a 64-bit code segment.
        """
    @property
    def present(self, /) -> Diagnostic[bool]: ...
    @property
    def raw(self, /) -> Diagnostic[int]:
        """
        The 8 raw bytes of the descriptor.
        """
    @property
    def type_code(self, /) -> Diagnostic[int]:
        """
        The raw type field.
        """

@final
class GlobalFlag(BaseRecord):
    """
    One GFlags flag that is set.
    """
    @property
    def abbreviation(self, /) -> str:
        """
        The GFlags abbreviation (`hpa`, `ust`, ...).
        """
    @property
    def bit(self, /) -> int:
        """
        The bit mask of the flag.
        """
    @property
    def description(self, /) -> str: ...

@final
class GlobalFlags(BaseRecord):
    """
    `nt!NtGlobalFlag` and the `_PEB.NtGlobalFlag` of the current process
    (`!gflag`).
    """
    @property
    def kernel(self, /) -> int:
        """
        `nt!NtGlobalFlag`.
        """
    @property
    def kernel_address(self, /) -> int:
        """
        The address of `nt!NtGlobalFlag`.
        """
    @property
    def kernel_flags(self, /) -> list[GlobalFlag]: ...
    @property
    def process(self, /) -> ProcessIdentity |None:
        """
        The current process. `None` if no process is selected.
        """
    @property
    def process_flags(self, /) -> Diagnostic[ProcessGlobalFlags]:
        """
        The flags of the current process, read from its PEB.
        """

@final
class HandleEntry(BaseRecord):
    """
    A handle-table entry (`!handle <handle>`).
    """
    @property
    def attributes(self, /) -> Diagnostic[int]:
        """
        The attribute bits of the entry (inherit, protect-from-close, audit).
        """
    @property
    def entry(self, /) -> int:
        """
        The `_HANDLE_TABLE_ENTRY`.
        """
    @property
    def granted_access(self, /) -> Diagnostic[int]: ...
    @property
    def handle(self, /) -> int: ...
    @property
    def name(self, /) -> Diagnostic[str |None]:
        """
        The name of the object, or None for an unnamed object.
        """
    @property
    def object(self, /) -> Diagnostic[int]:
        """
        The body of the object.
        """
    @property
    def type_name(self, /) -> Diagnostic[str |None]: ...

@final
class HandleTable(BaseRecord):
    """
    The handle table of a process (`!handle`).
    """
    @property
    def advertised_handles(self, /) -> int:
        """
        The handle count that the table reports.
        """
    @property
    def entries(self, /) -> list[HandleEntry]: ...
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The process that owns the table.
        """
    @property
    def scanned_handles(self, /) -> int: ...
    @property
    def skipped_entries(self, /) -> int:
        """
        The number of entries that ntoseye could not read.
        """
    @property
    def table(self, /) -> int:
        """
        The `_HANDLE_TABLE`.
        """
    @property
    def table_level(self, /) -> int:
        """
        The level of the table (0-2), which is the number of pointer levels
        before the entries.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the enumeration stopped at its limit.
        """

@final
class HandleTrace(BaseRecord):
    """
    One `_HANDLE_TRACE_DB_ENTRY`.
    """
    @property
    def handle(self, /) -> int: ...
    @property
    def kind(self, /) -> int:
        """
        1 open, 2 close, 3 bad reference.
        """
    @property
    def kind_name(self, /) -> str:
        """
        `OPEN`, `CLOSE`, `BAD REFERENCE`, or `UNKNOWN`.
        """
    @property
    def process_id(self, /) -> int: ...
    @property
    def stack(self, /) -> list[HandleTraceFrame]:
        """
        Newest frame first.
        """
    @property
    def thread_id(self, /) -> int: ...

@final
class HandleTraceFrame(BaseRecord):
    """
    A return address on the stack of a handle trace.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol of the address in the traced process. None if no symbol
        resolves.
        """

@final
class HandleTraces(BaseRecord):
    """
    The handle traces of a process (`!htrace`).
    """
    @property
    def debug_info(self, /) -> int |None:
        """
        The `_HANDLE_TRACE_DEBUG_INFO`. None if handle tracing is off.
        """
    @property
    def object_table(self, /) -> int: ...
    @property
    def parsed(self, /) -> int:
        """
        The number of ring slots that ntoseye read.
        """
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The traced process.
        """
    @property
    def recorded(self, /) -> int:
        """
        The total number of recorded traces, of which the ring keeps the
        last `table_size`.
        """
    @property
    def table_size(self, /) -> int:
        """
        The capacity of the ring.
        """
    @property
    def traces(self, /) -> list[HandleTrace]:
        """
        The matching traces, newest first.
        """
    @property
    def unreadable(self, /) -> int:
        """
        The number of ring slots that ntoseye could not read.
        """

@final
class Heap:
    """
    One heap of a process, from its PEB heap list.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The heap address.
        """
    @property
    def index(self, /) -> int:
        """
        The index of the heap in the PEB list.
        """
    def inspect(self, /, list_entries: bool = False) -> HeapDetail:
        """
        Decode this heap (`!heap -h`), with its entries if `list_entries` is
        true.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class HeapBlock(BaseRecord):
    """
    One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
    chunk, or a segment-heap LFH block.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def checksum_ok(self, /) -> bool |None:
        """
        Whether the header checksum is correct. None if the block kind has
        no checksum.
        """
    @property
    def flags(self, /) -> int |None:
        """
        The header flags. None if the block kind has no header of its own.
        """
    @property
    def index(self, /) -> int |None:
        """
        The position in the region or subsegment. None for VS chunks.
        """
    @property
    def kind(self, /) -> str:
        """
        `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
        """
    @property
    def previous_size(self, /) -> int |None:
        """
        The size in bytes of the previous block. None if the block kind
        does not record it.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes, with the header.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int |None:
        """
        The number of unused bytes at the end of the block. None if the
        block does not record them.
        """
    @property
    def user(self, /) -> int |None:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int |None:
        """
        The number of bytes that the caller can use.
        """

@final
class HeapBlockSearch(BaseRecord):
    """
    The heap block that contains an address (`!heap -x <addr>`,
    `Heaps.find_block()`).
    """
    @property
    def address(self, /) -> int:
        """
        The search address.
        """
    @property
    def block(self, /) -> HeapMatchNtEntry |HeapMatchNtLfhBlock |HeapMatchNtVirtual |HeapMatchNtSegment |HeapMatchPage |HeapMatchVsChunk |HeapMatchLfhBlock |HeapMatchRange |HeapMatchLarge |None:
        """
        The location of the address in the heap. None if no heap contains
        it.
        """
    @property
    def errors(self, /) -> list[str]:
        """
        The heaps that ntoseye could not search, and the reasons.
        """
    @property
    def found(self, /) -> bool:
        """
        Whether a heap contains the address.
        """
    @property
    def heap(self, /) -> HeapIdentity |None:
        """
        The heap that contains the address. None if no heap contains it.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether a heap list or heap walk stopped at its limit, in which case
        the search may have missed the block.
        """

@final
class HeapDetail(BaseRecord):
    """
    One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def error(self, /) -> str |None:
        """
        The reason that ntoseye could not decode the heap.
        """
    @property
    def index(self, /) -> int:
        """
        Position in the PEB heap list.
        """
    @property
    def kind(self, /) -> str:
        """
        `nt`, `segment`, or `unknown (<signature>)`.
        """
    @property
    def list_entries(self, /) -> bool:
        """
        Whether ntoseye walked and listed the entries, chunks, and blocks.
        """
    @property
    def nt(self, /) -> NtHeap |None:
        """
        The NT (`_HEAP`) decoding. None for other heap kinds or if the
        decoding failed.
        """
    @property
    def segment(self, /) -> SegmentHeap |None:
        """
        The segment-heap decoding. None for other heap kinds or if the
        decoding failed.
        """

@final
class HeapIdentity(BaseRecord):
    """
    A heap, identified by its PEB-list position, address, and kind.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        Position in the PEB heap list.
        """
    @property
    def kind(self, /) -> str:
        """
        `nt`, `segment`, or `unknown (<signature>)`.
        """

@final
class HeapIterator:
    """
    Iterator over `proc.heaps`.
    """
    def __iter__(self, /) -> HeapIterator: ...
    def __next__(self, /) -> Heap: ...

@final
class HeapLargeAllocation(BaseRecord):
    """
    A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def extra_present(self, /) -> bool: ...
    @property
    def kind(self, /) -> str:
        """
        Always `large`.
        """
    @property
    def metadata(self, /) -> int:
        """
        The metadata record of the allocation.
        """
    @property
    def pages(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes: `pages` pages.
        """
    @property
    def unused_bytes(self, /) -> int:
        """
        The number of unused bytes at the end of the allocation.
        """

@final
class HeapMatchLarge(BaseRecord):
    """
    An address inside a segment-heap large allocation.
    """
    @property
    def allocation(self, /) -> HeapLargeAllocation: ...
    @property
    def kind(self, /) -> str:
        """
        Always `large`.
        """

@final
class HeapMatchLfhBlock(BaseRecord):
    """
    An address inside a segment-heap LFH block.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        The position of the block in the subsegment.
        """
    @property
    def kind(self, /) -> str:
        """
        Always `lfh-block`.
        """
    @property
    def range(self, /) -> HeapPageRange: ...
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def subsegment(self, /) -> LfhSubsegment:
        """
        The subsegment that contains the block. Its `blocks` list is empty.
        """

@final
class HeapMatchNtEntry(BaseRecord):
    """
    An address inside an NT-heap entry.
    """
    @property
    def entry(self, /) -> NtHeapEntry: ...
    @property
    def kind(self, /) -> str:
        """
        Always `nt-entry`.
        """
    @property
    def segment(self, /) -> int:
        """
        The `_HEAP_SEGMENT` that contains the entry.
        """

@final
class HeapMatchNtLfhBlock(BaseRecord):
    """
    An address inside a legacy-LFH block of an NT heap.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def entry(self, /) -> NtHeapEntry:
        """
        The busy entry that contains the region.
        """
    @property
    def index(self, /) -> int:
        """
        The position of the block in the region.
        """
    @property
    def kind(self, /) -> str:
        """
        Always `nt-lfh-block`.
        """
    @property
    def region(self, /) -> NtLfhUserBlocks:
        """
        The user block region. Its `blocks` list is empty.
        """
    @property
    def segment(self, /) -> int:
        """
        The `_HEAP_SEGMENT` that contains the region.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes per block.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """

@final
class HeapMatchNtSegment(BaseRecord):
    """
    An address in an NT-heap segment that is not in an entry: in the heap
    header, in an uncommitted range, or after the point where the walk
    stopped.
    """
    @property
    def kind(self, /) -> str:
        """
        Always `nt-segment`.
        """
    @property
    def segment(self, /) -> int: ...
    @property
    def stopped(self, /) -> HeapWalkStop |None:
        """
        Where the entry walk stopped, and why. None if the walk did not stop
        early.
        """

@final
class HeapMatchNtVirtual(BaseRecord):
    """
    An address inside an NT-heap virtually allocated block.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def commit_size(self, /) -> int: ...
    @property
    def entry(self, /) -> int:
        """
        The block header.
        """
    @property
    def kind(self, /) -> str:
        """
        Always `nt-virtual`.
        """
    @property
    def reserve_size(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes: the larger of the reserve size and the commit
        size.
        """
    @property
    def state(self, /) -> str:
        """
        Always `virtual`.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """

@final
class HeapMatchPage(BaseRecord):
    """
    An address in a segment-heap range that the heap allocated directly
    from its segment.
    """
    @property
    def kind(self, /) -> str:
        """
        Always `page`.
        """
    @property
    def range(self, /) -> HeapPageRange: ...
    @property
    def size(self, /) -> int:
        """
        The size of the range in bytes.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """

@final
class HeapMatchRange(BaseRecord):
    """
    An address in a segment-heap page range that is not in a block of its
    subsegment: in the header, the bitmap, or the unused bytes at the end.
    """
    @property
    def kind(self, /) -> str:
        """
        Always `range`.
        """
    @property
    def range(self, /) -> HeapPageRange: ...

@final
class HeapMatchVsChunk(BaseRecord):
    """
    An address inside a segment-heap VS chunk.
    """
    @property
    def chunk(self, /) -> VsChunk: ...
    @property
    def kind(self, /) -> str:
        """
        Always `vs-chunk`.
        """
    @property
    def range(self, /) -> HeapPageRange: ...
    @property
    def subsegment(self, /) -> int:
        """
        The `_HEAP_VS_SUBSEGMENT` that contains the chunk.
        """

@final
class HeapOverview(BaseRecord):
    """
    One heap in the PEB list, with its usage totals.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        Position in the PEB heap list.
        """
    @property
    def kind(self, /) -> str:
        """
        `nt`, `segment`, or `unknown (<signature>)`.
        """
    @property
    def stats(self, /) -> Diagnostic[HeapStats]:
        """
        Unavailable if ntoseye cannot read the heap signature, layout, memory,
        or symbols.
        """

@final
class HeapPageRange(BaseRecord):
    """
    A page range (`_HEAP_PAGE_RANGE_DESCRIPTOR`) of a page segment.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def committed_pages(self, /) -> int: ...
    @property
    def end(self, /) -> int:
        """
        The first byte after the range.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the subsegment.
        """
    @property
    def flags(self, /) -> int:
        """
        The descriptor's `RangeFlags`.
        """
    @property
    def kind(self, /) -> str:
        """
        `unused`, `free`, `page` (allocated directly from the segment),
        `vs`, or `lfh`.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes: `units * unit_size`.
        """
    @property
    def subsegment(self, /) -> VsSubsegment |LfhSubsegment |None:
        """
        The VS or LFH subsegment in the range, with its blocks. `None` for
        other kinds, or if ntoseye cannot read the subsegment. Also `None` in
        a `Heaps.find_block()` result, because `find_block()` does not decode
        the subsegment.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the subsegment has more blocks than the walk limit.
        """
    @property
    def unit_size(self, /) -> int:
        """
        Bytes per unit.
        """
    @property
    def units(self, /) -> int: ...
    @property
    def unused_bytes(self, /) -> int:
        """
        The number of unused bytes at the end of the range.
        """

@final
class HeapStats(BaseRecord):
    """
    The usage totals of one heap.
    """
    @property
    def committed(self, /) -> int:
        """
        Committed bytes.
        """
    @property
    def flags(self, /) -> int:
        """
        `_HEAP.Flags` (NT heap) or `GlobalFlags` (segment heap).
        """
    @property
    def free(self, /) -> int:
        """
        Free bytes: the free blocks of an NT heap, or the free committed
        pages of a segment heap.
        """
    @property
    def front_end(self, /) -> int |None:
        """
        The address of the NT-heap front end (LFH). None if the heap has no
        front end or is a segment heap.
        """
    @property
    def front_end_type(self, /) -> int:
        """
        The NT-heap `FrontEndHeapType`. 0 for a segment heap.
        """
    @property
    def large_allocations(self, /) -> int:
        """
        The number of segment-heap large allocations. 0 for an NT heap.
        """
    @property
    def lfh_subsegments(self, /) -> int:
        """
        The number of segment-heap LFH page ranges. 0 for an NT heap.
        """
    @property
    def page_allocations(self, /) -> int:
        """
        The number of segment-heap ranges allocated directly from a segment.
        0 for an NT heap.
        """
    @property
    def reserved(self, /) -> int:
        """
        Reserved bytes.
        """
    @property
    def segments(self, /) -> int:
        """
        The number of NT-heap segments or segment-heap page segments.
        """
    @property
    def virtual_blocks(self, /) -> int:
        """
        The number of NT-heap virtually allocated blocks. 0 for a segment heap.
        """
    @property
    def vs_subsegments(self, /) -> int:
        """
        The number of segment-heap VS page ranges. 0 for an NT heap.
        """

@final
class HeapSummary(BaseRecord):
    """
    A process's PEB heap list (`!heap` / `!heap -s`).
    """
    @property
    def heaps(self, /) -> list[HeapOverview]: ...
    @property
    def peb(self, /) -> int:
        """
        The process environment block that ntoseye read the list from.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the list is longer than the walk limit, which leaves it
        incomplete.
        """

@final
class HeapWalkStop(BaseRecord):
    """
    The address where a heap walk stopped, and the reason.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def reason(self, /) -> str: ...

@final
class Heaps:
    """
    The PEB heap list of a process.
    """
    def __contains__(self, index: int, /) -> bool: ...
    def __getitem__(self, index: int, /) -> Heap: ...
    def __iter__(self, /) -> HeapIterator: ...
    def __len__(self, /) -> int: ...
    def find_block(self, /, addr: int) -> HeapBlockSearch:
        """
        Find the heap block that contains `addr` (`!heap -x`).
        """
    def get(self, /, index: int) -> Heap |None: ...

@final
class Hypercall(BaseRecord):
    """
    One call code of the hypervisor's hypercall table.
    """
    @property
    def code(self, /) -> int: ...
    @property
    def handler(self, /) -> int: ...
    @property
    def implemented(self, /) -> bool:
        """
        Whether the call has its own handler, not the reserved code 0's.
        """
    @property
    def input_element_size(self, /) -> int: ...
    @property
    def input_size(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        The TLFS name, or None for a code that the TLFS does not list.
        """
    @property
    def output_element_size(self, /) -> int: ...
    @property
    def output_size(self, /) -> int: ...
    @property
    def rep(self, /) -> bool:
        """
        Whether the call is a rep hypercall.
        """
    @property
    def variable_header(self, /) -> bool:
        """
        Whether the call takes a variable-size header.
        """

@final
class HypercallCaller:
    """
    The virtual processor whose hypercall a processor halted in the Windows
    hypervisor handles (`cpu.hypercall_caller()`), found as `!hvcall` and a
    hypercall breakpoint's filter find it: the call as the caller made it,
    and the caller's memory, which a hypercall breakpoint's condition reads.
    """
    def __repr__(self, /) -> str: ...
    @property
    def hypercall(self, /) -> DecodedHypercall |None:
        """
        The call with its input decoded, as `!hvcall` shows it, or `None`
        when the caller's registers are not known.
        """
    @property
    def partition_id(self, /) -> int:
        """
        The caller's partition ID (the root partition's is 1).
        """
    def read(self, /, address: int, size: int, physical: bool = False) -> bytes:
        """
        Read `size` bytes of the caller's memory, as a hypercall
        breakpoint's condition reads it: guest virtual memory through the
        calling VTL's page tables (its CR3), or with `physical=True` guest
        physical memory (a slow call's input, at the GPA in `rdx`), both
        through its EPT. The memory is read now, so read it while the target
        is halted at the call. Raises `NtoseyeError` when the caller's state
        at the call is not known, when a page is not mapped, and for a
        virtual address unless the caller is in 4-level long-mode paging.
        The memory is read-only.
        """
    @property
    def registers(self, /) -> dict[str, int]:
        """
        The caller's registers at its VMCALL by name (`rcx`, `rdx`, `r8`,
        `rip`, `cr3`, ...), as a hypercall breakpoint's condition sees them:
        RIP, RSP, flags, control and segment registers from the calling
        VTL's eVMCS, and the general-purpose registers when ntoseye
        recovered them. Empty when the state ntoseye found is an older
        exit's.
        """
    @property
    def root(self, /) -> bool:
        """
        Whether the caller is a VP of the root partition (Windows itself)
        rather than of a guest partition.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Return the caller as a plain `dict` (`partition_id`, `root`,
        `vp_index`, `vtl`, `registers`, and `hypercall`, the call's dict or
        `None`).
        """
    @property
    def vp_index(self, /) -> int:
        """
        The caller's VP index in its partition.
        """
    @property
    def vtl(self, /) -> int:
        """
        The VTL that made the call.
        """

@final
class HypercallElement(BaseRecord):
    """
    One element of a rep hypercall's input list.
    """
    @property
    def fields(self, /) -> list[HypercallField]: ...
    @property
    def index(self, /) -> int: ...

@final
class HypercallField(BaseRecord):
    """
    One field of a hypercall's input, as the Hyper-V TLFS lays it out.
    """
    @property
    def meaning(self, /) -> str |None:
        """
        What the value means, where it has a name or stands for a set
        (`HV_PARTITION_ID_SELF`, `VPs 0-3`, a register's TLFS name).
        """
    @property
    def name(self, /) -> str:
        """
        The TLFS parameter name, with its member for a structure
        (`ProcessorSet.ValidBanksMask`) and its index for an array
        (`Message[2]`); `Input[n]` for the raw qwords of a call whose
        layout ntoseye does not know.
        """
    @property
    def offset(self, /) -> int:
        """
        The offset in the input, from its first byte.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes, at most 8.
        """
    @property
    def value(self, /) -> int: ...

@final
class HypercallFilter(BaseRecord):
    """
    What a hypercall breakpoint (`!hvbp`) stops on: one call code, from
    any caller or from one partition or VP of the Windows hypervisor.
    """
    @property
    def code(self, /) -> int:
        """
        The call code: the low 16 bits of the caller's RCX.
        """
    @property
    def name(self, /) -> str |None:
        """
        The TLFS name, or None for a code that the TLFS does not list.
        """
    @property
    def partition(self, /) -> int |None:
        """
        The caller's partition ID. None for any caller.
        """
    @property
    def vp(self, /) -> int |None:
        """
        The caller's VP index in `partition`. None for any VP.
        """

@final
class HypervisorPartition:
    """
    A partition of the Windows hypervisor, as it was when listed.
    """
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The address of the hypervisor's partition object.
        """
    @property
    def id(self, /) -> int:
        """
        The partition ID (the root partition's is 1).
        """
    @property
    def parent_id(self, /) -> int |None:
        """
        The parent partition's ID, or `None` for the root partition.
        """
    @property
    def privilege_names(self, /) -> list[str]:
        """
        The TLFS names of the privileges in `privileges`
        (`["AccessVpRunTimeReg", ..., "CreatePartitions", ...]`). Set bits
        that the TLFS lists as reserved have no name and are left out.
        """
    @property
    def privileges(self, /) -> int:
        """
        The partition's privileges, as the TLFS `HV_PARTITION_PRIVILEGE_MASK`.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Return the partition as a plain `dict` (`address`, `id`, `parent_id`,
        `privileges`, `privilege_names`, and `virtual_processors`, a list of their dicts).
        """
    @property
    def virtual_processors(self, /) -> list[VirtualProcessor]:
        """
        The partition's virtual processors, by index.
        """

@final
class HypervisorProcessor(BaseRecord):
    """
    A logical processor whose current VP a VP is: the one that runs it, or
    ran it last.
    """
    @property
    def block(self, /) -> int:
        """
        The processor block (the processor's GS base in the hypervisor).
        """
    @property
    def number(self, /) -> int |None:
        """
        The processor number, or None on builds before 10.0.19041.
        """

@final
class HypervisorVtl:
    """
    One VTL of a virtual processor: the hypervisor's context for it and, when
    found, its eVMCS and the guest state saved there.
    """
    def __repr__(self, /) -> str: ...
    @property
    def context(self, /) -> int:
        """
        The address of the hypervisor's context object for this VTL.
        """
    def disassemble(self, /, address: int, count: int, physical: bool = False) -> list[DisassembledInstruction]:
        """
        Disassemble `count` instructions of this VTL's guest at `address`, as
        `!hvu` does: read as `read` reads it (guest virtual, or with
        `physical=True` guest physical), and decoded in the mode the VTL left
        off in, 64-bit in IA-32e mode with a 64-bit code segment, else
        32-bit. Branch and RIP-relative comments are addresses: there are no
        symbols for a guest. The listing stops at the first unreadable page,
        so it can hold fewer than `count` instructions. Raises `NtoseyeError`
        when the first instruction is unreadable, without the VTL's eVMCS
        state, for real-mode or 16-bit code, and for a virtual address
        unless the guest is in 4-level long-mode paging.
        """
    @property
    def ept_pointer(self, /) -> int |None:
        """
        The VTL's EPT pointer, the root of its second-level address
        translation, or `None` without the eVMCS.
        """
    @property
    def exit_reason(self, /) -> int |None:
        """
        The basic reason (Intel SDM Appendix C) the VTL last left for the
        hypervisor, or `None` without the eVMCS.
        """
    @property
    def level(self, /) -> int:
        """
        The VTL (0 for NT, 1 for the secure kernel).
        """
    def read(self, /, address: int, size: int, physical: bool = False) -> bytes:
        """
        Read `size` bytes of the memory of this VTL's guest, as `!hvd` does:
        guest virtual memory through the VTL's page tables (its saved CR3),
        or with `physical=True` guest physical memory, both through the VTL's
        EPT. Raises `NtoseyeError` without the VTL's eVMCS state or when a
        page is not mapped, and for a virtual address unless the guest is in
        4-level long-mode paging. The memory is read-only.
        """
    @property
    def rip(self, /) -> int |None:
        """
        The guest RIP where the VTL left off, or `None` without the eVMCS.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Return the VTL as a plain `dict` (`level`, `context`, `vmcs`,
        `ept_pointer`, `rip`, `exit_reason`).
        """
    def translate(self, /, gpa: int) -> EptMapping |None:
        """
        Translate a guest physical address through this VTL's EPT, as
        `!hvept` does. Returns `None` when no entry maps it, and raises
        `NtoseyeError` without the VTL's eVMCS state or when a table is
        unreadable.
        """
    def translate_virtual(self, /, address: int) -> tuple[int, int] |None:
        """
        Translate a guest virtual address of this VTL's guest through its page
        tables and its EPT: `(guest_physical, host_physical)`, or `None` when
        the page tables do not map it. Raises `NtoseyeError` unless the guest
        is in 4-level long-mode paging.
        """
    @property
    def vmcs(self, /) -> int |None:
        """
        The physical address of the VTL's eVMCS, or `None` when ntoseye did
        not find where the context keeps it (no `hv-evmcs`).
        """
    def vmcs_fields(self, /) -> Record:
        """
        Every field of this VTL's eVMCS, read now, named as the TLFS names it
        (`guest_rip`, `msr_bitmap`, ...), as `!hvvmcs` shows them:
        `fields.guest_rip` or `fields["guest_rip"]`. Raises `NtoseyeError`
        without the VTL's eVMCS.
        """

@final
class Idt(BaseRecord):
    """
    The IDT of a processor (`!idt`), with one vector or the bounded full
    table.
    """
    @property
    def base(self, /) -> int:
        """
        The address of the table.
        """
    @property
    def entries(self, /) -> list[IdtGate]: ...
    @property
    def limit(self, /) -> int:
        """
        The table limit: the table size in bytes, minus one.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the descriptor is shorter than the full table.
        """
    @property
    def vector(self, /) -> int |None:
        """
        The requested vector, or None for the full table.
        """

@final
class IdtGate(BaseRecord):
    """
    One decoded AMD64 IDT gate.
    """
    @property
    def address(self, /) -> int:
        """
        The address of the gate in the table.
        """
    @property
    def dpl(self, /) -> Diagnostic[int]:
        """
        The descriptor privilege level.
        """
    @property
    def gate_name(self, /) -> Diagnostic[str]:
        """
        `interrupt`, `trap`, `task`, or `reserved`.
        """
    @property
    def gate_type(self, /) -> Diagnostic[int]:
        """
        The raw gate type.
        """
    @property
    def handler(self, /) -> Diagnostic[int]:
        """
        The interrupt handler that the gate points to.
        """
    @property
    def ist(self, /) -> Diagnostic[int]:
        """
        The interrupt stack table index (0: none).
        """
    @property
    def ki_isr_thunk(self, /) -> Diagnostic[str |None]:
        """
        For a handler in `KiIsrThunk` (a chained interrupt), the offset of
        the handler in `KiIsrThunk` and the location of
        `_KINTERRUPT.DispatchCode`. The diagnostic value is None for other
        handlers.
        """
    @property
    def non_nt_hook(self, /) -> Diagnostic[bool]:
        """
        Whether the handler is in a module other than NT.
        """
    @property
    def present(self, /) -> Diagnostic[bool]: ...
    @property
    def selector(self, /) -> Diagnostic[int]:
        """
        The code segment selector.
        """
    @property
    def symbol(self, /) -> Diagnostic[str |None]:
        """
        The symbol of the handler. The diagnostic value is None if no
        symbol resolved.
        """
    @property
    def vector(self, /) -> int: ...

@final
class ImageByteDiff(BaseRecord):
    """
    One byte that differs from the cached image.
    """
    @property
    def actual(self, /) -> int:
        """
        The byte in memory.
        """
    @property
    def expected(self, /) -> int:
        """
        The byte in the cached image.
        """
    @property
    def kind(self, /) -> str |None:
        """
        The self-patch kind of the byte. `None` for a genuine mismatch.
        """
    @property
    def rva(self, /) -> int: ...

@final
class ImageCheck(BaseRecord):
    """
    A module's in-memory code, compared with its cached image (`!chkimg`).
    Each range list has a limit, and its `*_overflow` flag is true if more
    ranges exist.
    """
    @property
    def all_mismatch_range_overflow(self, /) -> bool: ...
    @property
    def all_mismatch_ranges(self, /) -> list[ImageMismatchRange]:
        """
        Mismatch ranges, with self-patches.
        """
    @property
    def base_address(self, /) -> int: ...
    @property
    def byte_diffs(self, /) -> list[ImageByteDiff]:
        """
        Byte-level differences. Empty if you do not request them (`-d`).
        """
    @property
    def byte_diffs_truncated(self, /) -> bool: ...
    @property
    def genuine_mismatched_bytes(self, /) -> int:
        """
        The number of mismatched bytes, without known self-patches.
        """
    @property
    def mismatch_range_overflow(self, /) -> bool: ...
    @property
    def mismatch_ranges(self, /) -> list[ImageMismatchRange]:
        """
        Genuine mismatch ranges.
        """
    @property
    def module(self, /) -> str:
        """
        The full path.
        """
    @property
    def sections(self, /) -> list[ImageSectionCheck]: ...
    @property
    def self_patch_range_overflow(self, /) -> bool: ...
    @property
    def self_patch_ranges(self, /) -> list[ImageSelfPatchRange]: ...
    @property
    def self_patches(self, /) -> ImageSelfPatchCounts: ...
    @property
    def short_name(self, /) -> str: ...
    @property
    def total_mismatched_bytes(self, /) -> int:
        """
        The number of mismatched bytes, with known self-patches.
        """

@final
class ImageDataDirectory(BaseRecord):
    """
    One `IMAGE_DATA_DIRECTORY` entry.
    """
    @property
    def index(self, /) -> int:
        """
        The slot of the entry in the directory table.
        """
    @property
    def name(self, /) -> str:
        """
        `Export`, `Import`, `Debug`, ...
        """
    @property
    def rva(self, /) -> int: ...
    @property
    def size(self, /) -> int: ...

@final
class ImageDebugEntry(BaseRecord):
    """
    One `IMAGE_DEBUG_DIRECTORY` entry.
    """
    @property
    def address_of_raw_data(self, /) -> int: ...
    @property
    def characteristics(self, /) -> int: ...
    @property
    def codeview(self, /) -> Diagnostic[CodeViewRecord] |None:
        """
        The decoded CodeView record. `None` for other entry types.
        """
    @property
    def pointer_to_raw_data(self, /) -> int: ...
    @property
    def size_of_data(self, /) -> int: ...
    @property
    def time_date_stamp(self, /) -> int: ...
    @property
    def type(self, /) -> int:
        """
        The `IMAGE_DEBUG_TYPE_*` value.
        """
    @property
    def type_name(self, /) -> str:
        """
        `CODEVIEW`, `POGO`, ...
        """
    @property
    def version(self, /) -> str:
        """
        `major.minor`.
        """

@final
class ImageExportDirectory(BaseRecord):
    """
    `IMAGE_EXPORT_DIRECTORY`.
    """
    @property
    def address_of_functions(self, /) -> int: ...
    @property
    def address_of_name_ordinals(self, /) -> int: ...
    @property
    def address_of_names(self, /) -> int: ...
    @property
    def characteristics(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        The DLL name that the directory records.
        """
    @property
    def number_of_functions(self, /) -> int: ...
    @property
    def number_of_names(self, /) -> int: ...
    @property
    def ordinal_base(self, /) -> int: ...
    @property
    def time_date_stamp(self, /) -> int: ...
    @property
    def version(self, /) -> str:
        """
        `major.minor`.
        """

@final
class ImageExports(BaseRecord):
    """
    The export directory and the exports of an image (`!dh -e`).
    """
    @property
    def directory(self, /) -> ImageExportDirectory |None:
        """
        `None` if the image has no exports.
        """
    @property
    def exports(self, /) -> list[Export]: ...

@final
class ImageFileHeader(BaseRecord):
    """
    `IMAGE_FILE_HEADER`.
    """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_FILE_*` flags that are set in `characteristics`.
        """
    @property
    def machine(self, /) -> int: ...
    @property
    def machine_name(self, /) -> str:
        """
        `AMD64`, `I386`, ...
        """
    @property
    def number_of_sections(self, /) -> int: ...
    @property
    def number_of_symbols(self, /) -> int: ...
    @property
    def pointer_to_symbol_table(self, /) -> int: ...
    @property
    def size_of_optional_header(self, /) -> int: ...
    @property
    def time_date_stamp(self, /) -> int: ...

@final
class ImageHeaders(BaseRecord):
    """
    The headers of a mapped image (`!dh`).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def data_directories(self, /) -> list[ImageDataDirectory]: ...
    @property
    def debug_directory(self, /) -> Diagnostic[list[ImageDebugEntry]] |None:
        """
        The debug directory. `None` if you did not ask for it.
        """
    @property
    def exports(self, /) -> Diagnostic[ImageExports] |None:
        """
        The export directory. `None` if you did not ask for it.
        """
    @property
    def file_header(self, /) -> ImageFileHeader: ...
    @property
    def format(self, /) -> str:
        """
        `PE32` or `PE32+`.
        """
    @property
    def imports(self, /) -> Diagnostic[list[ImageImportDescriptor]] |None:
        """
        The import descriptors. `None` if you did not ask for them.
        """
    @property
    def module(self, /) -> str |None:
        """
        The loaded module at `base`, if there is one.
        """
    @property
    def optional_header(self, /) -> ImageOptionalHeader: ...
    @property
    def sections(self, /) -> list[ImageSectionHeader]: ...

@final
class ImageImport(BaseRecord):
    """
    One imported function.
    """
    @property
    def bound(self, /) -> int |None:
        """
        The bound address in the import address table.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the import name.
        """
    @property
    def hint(self, /) -> int |None:
        """
        The export-name-table hint, for a named import.
        """
    @property
    def name(self, /) -> str |None:
        """
        The imported name. `None` for an import by ordinal, or for an import
        that ntoseye could not read.
        """
    @property
    def ordinal(self, /) -> int |None:
        """
        The ordinal, for an import by ordinal.
        """

@final
class ImageImportDescriptor(BaseRecord):
    """
    One `IMAGE_IMPORT_DESCRIPTOR`, which identifies a DLL that the image imports from.
    """
    @property
    def forwarder_chain(self, /) -> int: ...
    @property
    def import_address_table(self, /) -> int: ...
    @property
    def import_name_table(self, /) -> int: ...
    @property
    def imports(self, /) -> list[ImageImport]: ...
    @property
    def incomplete(self, /) -> str |None:
        """
        The reason that the thunk walk stopped early, if it did.
        """
    @property
    def name(self, /) -> str |None:
        """
        The DLL name. `None` if ntoseye could not read it.
        """
    @property
    def name_error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the DLL name.
        """
    @property
    def time_date_stamp(self, /) -> int: ...

@final
class ImageMismatchRange(BaseRecord):
    """
    A contiguous RVA range of mismatched bytes.
    """
    @property
    def end(self, /) -> int:
        """
        The end, exclusive.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """
    @property
    def start(self, /) -> int: ...

@final
class ImageOptionalHeader(BaseRecord):
    """
    `IMAGE_OPTIONAL_HEADER` (PE32 or PE32+).
    """
    @property
    def base_of_code(self, /) -> int: ...
    @property
    def base_of_data(self, /) -> int |None:
        """
        Only for PE32. `None` for PE32+.
        """
    @property
    def checksum(self, /) -> int: ...
    @property
    def dll_characteristics(self, /) -> int: ...
    @property
    def dll_characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_DLLCHARACTERISTICS_*` flags that are set.
        """
    @property
    def entry_point(self, /) -> int |None:
        """
        The mapped entry point. `None` if the image has no entry point.
        """
    @property
    def entry_point_rva(self, /) -> int: ...
    @property
    def file_alignment(self, /) -> int: ...
    @property
    def image_base(self, /) -> int:
        """
        The preferred base address for which the image was linked.
        """
    @property
    def image_version(self, /) -> str:
        """
        `major.minor`.
        """
    @property
    def linker_version(self, /) -> str:
        """
        `major.minor`.
        """
    @property
    def loader_flags(self, /) -> int: ...
    @property
    def magic(self, /) -> int: ...
    @property
    def number_of_rva_and_sizes(self, /) -> int: ...
    @property
    def operating_system_version(self, /) -> str:
        """
        `major.minor`.
        """
    @property
    def section_alignment(self, /) -> int: ...
    @property
    def size_of_code(self, /) -> int: ...
    @property
    def size_of_headers(self, /) -> int: ...
    @property
    def size_of_heap_commit(self, /) -> int: ...
    @property
    def size_of_heap_reserve(self, /) -> int: ...
    @property
    def size_of_image(self, /) -> int: ...
    @property
    def size_of_initialized_data(self, /) -> int: ...
    @property
    def size_of_stack_commit(self, /) -> int: ...
    @property
    def size_of_stack_reserve(self, /) -> int: ...
    @property
    def size_of_uninitialized_data(self, /) -> int: ...
    @property
    def subsystem(self, /) -> int: ...
    @property
    def subsystem_name(self, /) -> str:
        """
        `Native`, `Windows GUI`, ...
        """
    @property
    def subsystem_version(self, /) -> str:
        """
        `major.minor`.
        """
    @property
    def win32_version_value(self, /) -> int: ...

@final
class ImageSectionCheck(BaseRecord):
    """
    The comparison of one executable section with the cached image.
    """
    @property
    def genuine_mismatches(self, /) -> int:
        """
        The number of mismatched bytes, without known self-patches.
        """
    @property
    def name(self, /) -> str: ...
    @property
    def rva(self, /) -> int: ...
    @property
    def self_patches(self, /) -> ImageSelfPatchCounts: ...
    @property
    def skip_reason(self, /) -> str |None:
        """
        The reason for the skip. `None` if ntoseye compared the section.
        """
    @property
    def skipped(self, /) -> bool:
        """
        Whether ntoseye skipped the comparison of this section.
        """
    @property
    def total_mismatches(self, /) -> int:
        """
        The number of mismatched bytes, with known self-patches.
        """
    @property
    def unavailable(self, /) -> str |None:
        """
        The reason that ntoseye could not read the section memory. `None` if
        the read succeeded.
        """

@final
class ImageSectionHeader(BaseRecord):
    """
    One `IMAGE_SECTION_HEADER`.
    """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_SCN_*` flags that are set.
        """
    @property
    def name(self, /) -> str: ...
    @property
    def number_of_linenumbers(self, /) -> int: ...
    @property
    def number_of_relocations(self, /) -> int: ...
    @property
    def pointer_to_linenumbers(self, /) -> int: ...
    @property
    def pointer_to_raw_data(self, /) -> int: ...
    @property
    def pointer_to_relocations(self, /) -> int: ...
    @property
    def size_of_raw_data(self, /) -> int: ...
    @property
    def virtual_address(self, /) -> int:
        """
        The RVA of the section.
        """
    @property
    def virtual_size(self, /) -> int: ...

@final
class ImageSelfPatchCounts(BaseRecord):
    """
    The number of bytes that ntoseye identifies as known kernel self-patches,
    by kind.
    """
    @property
    def import_optimization(self, /) -> int: ...
    @property
    def ki_patch_self(self, /) -> int:
        """
        `KiPatchSelf` / JMP thunks.
        """
    @property
    def region_rebase(self, /) -> int:
        """
        Relocated addresses of the kernel VA regions that the kernel moves at
        boot.
        """
    @property
    def retpoline(self, /) -> int: ...
    @property
    def total(self, /) -> int: ...

@final
class ImageSelfPatchRange(BaseRecord):
    """
    A contiguous RVA range that ntoseye identifies as one kind of kernel
    self-patch.
    """
    @property
    def end(self, /) -> int:
        """
        The end, exclusive.
        """
    @property
    def function(self, /) -> str |None:
        """
        The function that contains the patch, if a symbol covers it.
        """
    @property
    def kind(self, /) -> str:
        """
        `import optimization`, `retpoline`, `KiPatchSelf/JMP thunk`, or
        `kernel VA region rebase`.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """
    @property
    def start(self, /) -> int: ...

@final
class InFlightIrp(BaseRecord):
    """
    An in-flight IRP that ntoseye found on the `IrpList` of a thread or in the
    `CurrentIrp` of a device (`irps`).
    """
    @property
    def current_location(self, /) -> int: ...
    @property
    def device(self, /) -> int |None:
        """
        The device of the current stack location. None if ntoseye cannot resolve it.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The driver that owns the device of the current stack location. None if
        ntoseye cannot resolve it.
        """
    @property
    def ethread(self, /) -> int |None: ...
    @property
    def irp(self, /) -> int: ...
    @property
    def pid(self, /) -> int |None:
        """
        The process that issued the IRP. None if ntoseye found the IRP on a device.
        """
    @property
    def source(self, /) -> str:
        """
        Where ntoseye found the IRP: `thread` or `device`.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def state(self, /) -> str |None:
        """
        The state name of the thread. None if ntoseye found the IRP on a device.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread that issued the IRP. None if ntoseye found the IRP on a device.
        """
    @property
    def wait_reason(self, /) -> str |None:
        """
        The wait-reason name of the thread. None if ntoseye found the IRP on a
        device.
        """

@final
class Inspect:
    """
    System-wide reports and helpers that decode an object at an address
    (`dbg.inspect`). The results are `Record`s with the same shape as the MCP
    JSON output.
    """
    def __repr__(self, /) -> str: ...
    def acl(self, /, address: int) -> Acl:
        """
        Decode an ACL and its ACEs (`!acl`).
        """
    def alpc_message(self, /, address: int) -> AlpcMessage:
        """
        Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
        """
    def alpc_port(self, /, address: int) -> AlpcPort:
        """
        Decode an ALPC port (`!alpc /p`). The result has the port kind, owner,
        connection, state, and queues, and for a connection port also its
        connections. `address` is the body or the header of the port object.
        """
    def alpc_process_ports(self, /, process: Process |None = None) -> AlpcProcessPorts:
        """
        Get the ALPC ports to which a process has handles (`!alpc /lpp`). The
        result has the connection ports that the process owns, with their
        connections, and the client ports through which the process is
        connected. `process` defaults to the current process.
        """
    def apcs(self, /, target: Process |Thread |int |None = None) -> ApcQueues:
        """
        Decode the kernel and user APC queues of all threads, of a process, or
        of a thread (`!apc`).
        """
    def bugcheck(self, /) -> Bugcheck |None:
        """
        Analyze the current bugcheck, or return `None` if no bugcheck is in
        progress on the target.
        """
    def callbacks(self, /) -> list[NotifyCallback]:
        """
        List the process, thread, and image notification callbacks.
        """
    def context_record(self, /, address: int) -> Frame:
        """
        Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
        """
    def control_area(self, /, address: int) -> ControlArea:
        """
        Decode the `_CONTROL_AREA` of a section, with its segment and its
        subsections (`!ca`).
        """
    def device(self, /, address: int) -> Device:
        """
        Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
        """
    def device_stack(self, /, device_or_node: Device |int) -> DeviceStack:
        """
        Decode the device stack that contains a device object or devnode
        (`!devstack`).
        """
    def devnode(self, /, node: int |None = None, recurse: bool = False) -> DevNode:
        """
        Decode a PnP device node (`!devnode`), and optionally its subtree up to
        a limit.
        """
    def dpcs(self, /) -> DpcQueues:
        """
        Get the DPCs that are queued on each processor (`!dpcs`).
        """
    def etw_buffers(self, /, logger: int |str) -> EtwLoggerBuffers:
        """
        List the trace buffers on the GlobalList of an ETW trace session
        (`!wmitrace.strdump logger`).
        """
    def etw_events(self, /, logger: int |str, count: int |None = None) -> EtwEventDump:
        """
        Decode the events that are still in the buffers of an ETW trace session,
        oldest first (`!wmitrace.logdump`). `count` keeps only the most recent
        events. For a WPP message, `message.text` is the message rendered from
        the TMF that a loaded PDB declares, and the raw `payload` is always
        kept.
        """
    def etw_logger(self, /, logger: int |str) -> EtwLogger:
        """
        Decode the `_WMI_LOGGER_CONTEXT` of one ETW trace session
        (`!wmitrace.logger`). `logger` is the logger ID, the context address, or
        the session name.
        """
    def etw_loggers(self, /) -> EtwLoggerTable:
        """
        List the active ETW trace sessions (`!wmitrace.strdump`).
        """
    def exception_record(self, /, address: int) -> ExceptionRecord:
        """
        Decode an `EXCEPTION_RECORD64` (`.exr`).
        """
    def file_cache(self, /) -> FileCache:
        """
        Get the mapped views of the cache manager for each file, from its VACB
        arrays (`!filecache`).
        """
    def file_object(self, /, address: int) -> FileObject:
        """
        Decode a `_FILE_OBJECT` (`!fileobj`).
        """
    def findstack(self, /, symbol: str, level: int = 1) -> FindStack:
        """
        List the threads that have a stack frame that matches a symbol or module
        (`!findstack`). The pattern is `module!prefix`, a module or function
        prefix alone, or a glob with `*`/`?`. `level` 0 counts the matching
        frames, 1 lists them, and 2 adds the full stack.
        """
    def flt_filters(self, /) -> FltFilters:
        """
        Get the registered minifilters of each filter manager frame, with their
        instances (`!fltkd.filters`).
        """
    def flt_instances(self, /, filter: int |str |None = None) -> FltInstances:
        """
        Get minifilter instances with their filter and volume
        (`!fltkd.instances`): all instances, or the instances of one filter
        given by name or by `_FLT_FILTER` address.
        """
    def flt_volumes(self, /) -> FltVolumes:
        """
        Get the volumes of each filter manager frame, with the instances on them
        (`!fltkd.volumes`).
        """
    def global_flags(self, /) -> GlobalFlags:
        """
        Decode `nt!NtGlobalFlag` and the `_PEB.NtGlobalFlag` of the current
        process into GFlags names (`!gflag`).
        """
    def ipi(self, /, processor: int |None = None) -> IpiState:
        """
        Get the interprocessor-interrupt state of all processors or of one
        processor (`!ipi`).
        """
    def irp(self, /, address: int) -> Irp:
        """
        Decode an in-flight `_IRP` and its current I/O stack location (`!irp`).
        """
    def irp_find(self, /, pool_type: str = "nonpaged", restart: int |None = None, criteria: str |None = None, value: int = 0) -> IrpFindResult:
        """
        Find IRPs by scanning pool for the allocations of `IoAllocateIrp`
        (`!irpfind`). `pool_type` is `"nonpaged"` or `"paged"`, and `restart`
        continues the scan from an address. `criteria` is one of the WinDbg
        criteria (`"arg"`, `"device"`, `"fileobject"`, `"mdlprocess"`,
        `"thread"`, `"userevent"`), which the scan matches against `value`.
        """
    def irps(self, /, filter: str |None = None) -> list[InFlightIrp]:
        """
        Find in-flight IRPs, with an optional filter by process or driver
        (`irps`).
        """
    def job(self, /, address: int |None = None) -> Job:
        """
        Decode a job object (`!job`). The result has the accounting, limits,
        flags, nesting, and the processes that are assigned to the job.
        `address` is the job or a process or thread whose job to decode, and
        `None` selects the job of the current process.
        """
    def lookaside(self, /, address: int) -> LookasideList:
        """
        Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
        """
    def lookasides(self, /) -> LookasideLists:
        """
        List exported nonpaged and paged `GENERAL_LOOKASIDE` lists (`!lookaside`).
        """
    def mdl(self, /, address: int, pfn_count: int |None = None) -> Mdl:
        """
        Decode an `_MDL` and the page frames after its header (`!mdl`).
        `pfn_count` replaces the page count that `ByteCount` spans from
        `ByteOffset`.
        """
    def memusage(self, /, process_limit: int = 64) -> SystemMemoryUsage:
        """
        Get the memory-use counters of the system and of each process, up to a
        limit (`!memusage`).
        """
    def object(self, /, object: int |str) -> ExecutiveObject:
        """
        Decode an executive object header and resolve the type and name of the
        object, also listing the entries of a directory (`!object`). `object` is
        the address of the object, or its path in the object namespace
        (`"\\Driver\\ACPI"`).
        """
    def object_security(self, /, object: int) -> ObjectSecurity:
        """
        Decode the security descriptor that the header of an object references
        (`!objsd`).
        """
    def pci(self, /, bus: int = 0, device: int |None = None, function: int |None = None, *, last_bus: int |None = None, raw: bool = False) -> PciScan:
        """
        Read and decode PCI configuration space (`!pci`) for the functions on
        `bus` (through `last_bus`), or for one `device` and `function`. It reads
        all 4 KiB of each function, with the extended capabilities, and `raw`
        adds the data as hex. This needs a halted target and a backend that can
        get to configuration space (kd/kdnet, or gdb on QEMU).
        """
    def pci_tree(self, /) -> PciTree:
        """
        Get the PCI bus hierarchy that pci.sys tracks (`!pcitree`).
        """
    def peb(self, /, process: Process, address: int |None = None) -> Peb:
        """
        Decode the PEB of a process, with its parameters and loader-list heads
        (`!peb`).
        """
    def pfn(self, /, value: int, physical_address: bool = False) -> Pfn:
        """
        Decode an `_MMPFN` by page-frame number or physical address (`!pfn`).
        """
    def pnp_triage(self, /) -> PnpTriage:
        """
        Get the device nodes that have PnP problems (`!pnptriage`).
        """
    def pool(self, /, address: int) -> PoolPage:
        """
        Decode the pool page or big-pool allocation that contains `address`
        (`!pool`).
        """
    def pool_find(self, /, tag: str, pool_type: str |None = None) -> PoolSearch:
        """
        Find pool allocations by tag (`!poolfind`), optionally in one pool type
        only.
        """
    def pool_usage(self, /, tag: str |None = None, *, sort: str = "tag", include_counts: bool = False) -> PoolUsage:
        """
        Add up pool tracker usage by tag (`!poolused`).
        """
    def pool_validate(self, /, address: int) -> PoolValidation:
        """
        Check the block headers of the pool page that contains `address`, and
        return the first inconsistency (`!poolval`).
        """
    def queued_locks(self, /) -> QueuedLocks:
        """
        Get the processors that own or wait for each numbered queued spinlock
        (`!qlocks`).
        """
    def ready(self, /, processor: int |None = None) -> ReadyQueues:
        """
        Read the dispatcher ready queues, up to a limit, for all processors or
        for one processor (`!ready`).
        """
    def resource(self, /, address: int) -> ExecutiveResource:
        """
        Decode an executive resource (`!locks address`).
        """
    def resources(self, /, limit: int = 256) -> ResourceList:
        """
        List the entries of the symbol-backed executive-resource list
        (`!locks`).
        """
    def running(self, /, include_idle: bool = False, include_stacks: bool = False) -> RunningProcessors:
        """
        Get the current, next, and idle threads on each processor (`!running`).
        """
    def security_descriptor(self, /, address: int, annotate_well_known: bool = False) -> SecurityDescriptor:
        """
        Decode a security descriptor, with its owner and group SIDs and its ACLs
        (`!sd`).
        """
    def sessions(self, /, session: int |None = None) -> Sessions:
        """
        List sessions, or one selected session, and their processes
        (`!session`).
        """
    def sid(self, /, address: int) -> Sid:
        """
        Decode a SID into its string form, authority, and well-known name
        (`!sid`).
        """
    def ssdt(self, /) -> list[SsdtTable]:
        """
        Get the kernel SSDT, and the win32k shadow table if it is initialized
        (`!ssdt`).
        """
    def stacks(self, /, level: int = 0, filter: str |None = None) -> ThreadStacks:
        """
        Get the thread states, wait reasons, and stacks, up to a limit
        (`!stacks`).
        """
    def system_ptes(self, /, free_runs: bool = False) -> SystemPtes:
        """
        Get the system PTE usage from each `_MI_SYSTEM_PTE_TYPE` bitmap
        allocator (`!sysptes`). `free_runs` lists the free blocks of each
        allocator.
        """
    def teb(self, /, thread: Thread, address: int |None = None) -> Teb:
        """
        Decode the TEB of a thread and its WOW64 companion (`!teb`).
        """
    def time(self, /) -> TargetTime:
        """
        Get the target system time and uptime (`.time`).
        """
    def timer(self, /, address: int) -> KernelTimer:
        """
        Decode a `_KTIMER` and its DPC (`!timer address`).
        """
    def timers(self, /) -> TimerTable:
        """
        Read the kernel timer-table entries, up to a limit, and their DPCs
        (`!timer`).
        """
    def trap_frame(self, /, address: int) -> TrapFrame:
        """
        Decode a `_KTRAP_FRAME` at `address` (`.trap`).
        """
    def triage(self, /) -> TriageReport:
        """
        Make the structured one-shot crash and debug report (`!analyze`).
        """
    def uniqstack(self, /, process: Process |None = None) -> UniqStacks:
        """
        Group threads by identical call stacks (`!uniqstack`), using all threads
        unless `process` limits it to the threads of one process.
        """
    def verifier(self, /) -> Verifier:
        """
        Get the Driver Verifier configuration and statistics (`!verifier`).
        """
    def version(self, /) -> TargetVersion:
        """
        Get the target, kernel, symbol, processor, and debugger version
        information (`vertarget`).
        """
    def vm(self, /, include_processes: bool = True) -> VmStatistics:
        """
        Get the system memory, pool, PTE, and page-file counters (`!vm`).
        """
    def vpb(self, /, address: int) -> Vpb:
        """
        Decode a volume parameter block (`!vpb`).
        """
    def wdf_device(self, /, handle: int) -> WdfDevice:
        """
        Get the device objects, state machines, and queues of a WDFDEVICE
        (`!wdfkd.wdfdevice`).
        """
    def wdf_driver_info(self, /, driver: str) -> WdfDriverInfo:
        """
        Get a KMDF client driver and its device objects, with the WDFDEVICEs
        behind them (`!wdfkd.wdfdriverinfo`). Use the driver name that
        `wdf_loader` shows, in any case and with or without `.sys`.
        """
    def wdf_handle(self, /, handle: int) -> WdfHandle:
        """
        Decode a WDF handle and the object that it identifies
        (`!wdfkd.wdfhandle`), or raise an exception if the value is not the
        handle of a live KMDF object.
        """
    def wdf_loader(self, /) -> WdfLoader:
        """
        Get the KMDF client drivers on the driver list of
        `Wdf01000!FxLibraryGlobals` (`!wdfkd.wdfldr`).
        """
    def wdf_log(self, /, driver: str) -> WdfLog:
        """
        Get the In-Flight Recorder log of a KMDF client driver, oldest record
        first (`!wdfkd.wdflogdump`). A record whose TMF message a loaded PDB
        declares is formatted from that message.
        """
    def wdf_queue(self, /, handle: int) -> WdfQueue:
        """
        Get the configuration, state, callbacks, and requests of a WDFQUEUE
        (`!wdfkd.wdfqueue`).
        """
    def work_queues(self, /, include_stacks: bool = False, queue_types: Sequence[str] |None = None) -> WorkQueues:
        """
        Get the executive worker queues, their pending work items, and their
        worker threads (`!exqueue`). `include_stacks` adds the stack of each
        worker, and `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`)
        limits the listed items to the priorities of those types.
        """
    def zombies(self, /, flags: int = 1) -> Zombies:
        """
        Scan nonpaged pool for exited processes and terminated threads whose
        objects still have references (`!zombies`). `flags` is 1 for
        processes, 2 for threads, or 3 for both.
        """

@final
class IoStackLocation(BaseRecord):
    """
    An `_IO_STACK_LOCATION`, which is the part of an IRP for one driver.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def completion_routine(self, /) -> int: ...
    @property
    def context(self, /) -> int:
        """
        The context argument of the completion routine.
        """
    @property
    def device_object(self, /) -> int: ...
    @property
    def file_object(self, /) -> int: ...
    @property
    def major_function(self, /) -> int:
        """
        The `IRP_MJ_*` code.
        """
    @property
    def major_function_name(self, /) -> str:
        """
        The name of the major function (`IRP_MJ_READ`, ...).
        """
    @property
    def minor_function(self, /) -> int: ...

@final
class IoWorkItem(BaseRecord):
    """
    An `_IO_WORKITEM` that `IoQueueWorkItem` queued. Its work item runs
    `nt!IopProcessWorkItem`, which calls `routine`.
    """
    @property
    def address(self, /) -> int:
        """
        The `_IO_WORKITEM` that holds the queued `_WORK_QUEUE_ITEM`.
        """
    @property
    def context(self, /) -> int: ...
    @property
    def io_object(self, /) -> int:
        """
        The device or driver object that the item was allocated for.
        """
    @property
    def routine(self, /) -> int: ...
    @property
    def routine_symbol(self, /) -> str |None:
        """
        `routine` as a symbol, when one resolves.
        """

@final
class IpiProcessor(BaseRecord):
    """
    The IPI state of one processor.
    """
    @property
    def awaiting(self, /) -> list[int]:
        """
        The processors whose pending list holds a request from this processor.
        """
    @property
    def fields(self, /) -> Record:
        """
        The `_KPRCB` IPI fields that this build has, by name, each as a
        `Diagnostic` of its value.
        """
    @property
    def frozen_state(self, /) -> Diagnostic[str] |None:
        """
        The decoded `IpiFrozen` value (`Running`, `Frozen`, ...). `None` if the
        build does not have the field.
        """
    @property
    def kprcb(self, /) -> int: ...
    @property
    def pending(self, /) -> Diagnostic[list[IpiRequest]]:
        """
        The requests in the queue of this processor that are not taken yet, in
        list order. Unavailable on builds without a mailbox for each sender, or
        if ntoseye cannot read the list.
        """
    @property
    def pending_truncated(self, /) -> bool:
        """
        Whether the walk of the pending list stopped at its limit or at a
        repeated mailbox.
        """
    @property
    def processor(self, /) -> int: ...

@final
class IpiRequest(BaseRecord):
    """
    A request that a sender put in the IPI mailbox list of a processor.
    """
    @property
    def mailbox(self, /) -> int:
        """
        The `_REQUEST_MAILBOX` slot of the sender in the array of the receiver.
        """
    @property
    def parameters(self, /) -> Diagnostic[list[int]]:
        """
        The three parameters of the worker (`RequestPacket.CurrentPacket`).
        """
    @property
    def request_summary(self, /) -> Diagnostic[int]: ...
    @property
    def request_type(self, /) -> Diagnostic[str |None]:
        """
        The type of the request summary, if the type is known.
        """
    @property
    def sender(self, /) -> int |None:
        """
        The processor that sent the request. `None` if the mailbox is outside
        the array of the receiver.
        """
    @property
    def worker_routine(self, /) -> Diagnostic[int]: ...
    @property
    def worker_symbol(self, /) -> str |None:
        """
        The symbol of the worker routine, if ntoseye can resolve it.
        """

@final
class IpiState(BaseRecord):
    """
    The interprocessor interrupt state of each processor (`!ipi`).
    """
    @property
    def errors(self, /) -> list[ProcessorError]: ...
    @property
    def processors(self, /) -> list[IpiProcessor]: ...

@final
class Irp(BaseRecord):
    """
    An `_IRP` and its current I/O stack location (`!irp`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def current_location(self, /) -> int:
        """
        `CurrentLocation`, which is more than `stack_count` after the IRP
        completes.
        """
    @property
    def current_stack(self, /) -> IoStackLocation |None:
        """
        None if the current location is out of range or ntoseye cannot read it.
        """
    @property
    def io_status(self, /) -> int |None:
        """
        `IoStatus.Status` as an NTSTATUS. None if ntoseye cannot read it.
        """
    @property
    def mdl_address(self, /) -> int: ...
    @property
    def pending_returned(self, /) -> bool: ...
    @property
    def requestor_mode(self, /) -> int:
        """
        0 for `KernelMode`, 1 for `UserMode`.
        """
    @property
    def size(self, /) -> int:
        """
        `Size` in bytes, including the stack locations.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def thread(self, /) -> int:
        """
        `Tail.Overlay.Thread`, the thread that issued the IRP.
        """
    @property
    def type(self, /) -> int:
        """
        `Type`, which is `IO_TYPE_IRP` (6) for a valid IRP.
        """
    @property
    def user_buffer(self, /) -> int: ...
    @property
    def user_event(self, /) -> int: ...

@final
class IrpDispatchRoutine(BaseRecord):
    """
    One slot in the `MajorFunction` dispatch table.
    """
    @property
    def index(self, /) -> int:
        """
        The `IRP_MJ_*` code.
        """
    @property
    def name(self, /) -> str:
        """
        The name of the major function (`IRP_MJ_CREATE`, ...).
        """
    @property
    def routine(self, /) -> int: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to the routine. None if no symbol resolves.
        """

@final
class IrpFindCriteria(BaseRecord):
    """
    The criteria that an `!irpfind` search used to match IRPs.
    """
    @property
    def name(self, /) -> str:
        """
        `arg`, `device`, `fileobject`, `mdlprocess`, `thread`, or
        `userevent`.
        """
    @property
    def value(self, /) -> int: ...

@final
class IrpFindResult(BaseRecord):
    """
    One `!irpfind` pool scan.
    """
    @property
    def big_pool_status(self, /) -> str:
        """
        The result of the big-pool table scan.
        """
    @property
    def criteria(self, /) -> IrpFindCriteria |None:
        """
        None if the scan has no filter.
        """
    @property
    def interrupted(self, /) -> bool: ...
    @property
    def irps(self, /) -> list[PoolIrp]: ...
    @property
    def pool(self, /) -> str:
        """
        `nonpaged` or `paged`.
        """
    @property
    def region_end(self, /) -> int: ...
    @property
    def region_start(self, /) -> int: ...
    @property
    def restart(self, /) -> int |None:
        """
        The address where the page scan can continue. None if the scan finished.
        """
    @property
    def scan_start(self, /) -> int:
        """
        The address where the page scan started: the region start or the
        restart address.
        """
    @property
    def scanned_pages(self, /) -> int: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the result limit caused ntoseye to leave out IRPs, which
        happens when the page scan stopped at `restart` or ntoseye did not
        check some big-pool allocations.
        """

@final
class Irql(BaseRecord):
    """
    The current IRQL of a processor (`!irql`).
    """
    @property
    def level_name(self, /) -> Diagnostic[str]:
        """
        The Windows name of the level (`DISPATCH_LEVEL`, ...).
        """
    @property
    def note(self, /) -> str:
        """
        A note about KD break-ins. At a KD break-in, `value` is the IRQL
        that the debugger sees, which can differ from the level
        immediately before the break-in.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def value(self, /) -> Diagnostic[int]:
        """
        The IRQL.
        """

@final
class Job(BaseRecord):
    """
    A job object (`!job`), with its accounting, limits, flags, nesting, and
    assigned processes. A field that this build does not have is `None`.
    """
    @property
    def accounting(self, /) -> JobAccounting: ...
    @property
    def address(self, /) -> int:
        """
        The `_EJOB`.
        """
    @property
    def child_job_list_termination(self, /) -> ListEnd: ...
    @property
    def child_jobs(self, /) -> list[int]: ...
    @property
    def job_flag_names(self, /) -> list[str]:
        """
        The `JobFlags` bits that are set, by their PDB names.
        """
    @property
    def job_flags(self, /) -> int |None:
        """
        `_EJOB.JobFlags`.
        """
    @property
    def job_id(self, /) -> int |None: ...
    @property
    def limit_flag_names(self, /) -> list[str]:
        """
        The `JOB_OBJECT_LIMIT_*` names of the limit flags that are set. A
        bit that has no name shows as its hex value.
        """
    @property
    def limits(self, /) -> JobLimits: ...
    @property
    def nesting_depth(self, /) -> int |None: ...
    @property
    def parent_job(self, /) -> int |None:
        """
        `None` for a top-level job.
        """
    @property
    def process_list_termination(self, /) -> ListEnd: ...
    @property
    def processes(self, /) -> list[ProcessIdentity]: ...
    @property
    def root_job(self, /) -> int |None:
        """
        `None` for a top-level job.
        """
    @property
    def server_silo_globals(self, /) -> int |None:
        """
        `None` for a job that is not a server silo.
        """
    @property
    def session_id(self, /) -> int |None: ...
    @property
    def silo(self, /) -> bool:
        """
        True if the job is a silo.
        """
    @property
    def unreadable_processes(self, /) -> list[int]:
        """
        The `_EPROCESS` addresses on the job list that ntoseye could not decode.
        """

@final
class JobAccounting(BaseRecord):
    """
    The `_EJOB` accounting of a job. A field that this build does not have is
    `None`.
    """
    @property
    def active_processes(self, /) -> int |None: ...
    @property
    def current_job_memory_used(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def peak_job_memory_used(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def peak_process_memory_used(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def this_period_total_kernel_time(self, /) -> int |None:
        """
        In 100 ns units.
        """
    @property
    def this_period_total_user_time(self, /) -> int |None:
        """
        In 100 ns units.
        """
    @property
    def total_cycle_time(self, /) -> int |None:
        """
        In CPU cycles.
        """
    @property
    def total_kernel_time(self, /) -> int |None:
        """
        In 100 ns units.
        """
    @property
    def total_page_fault_count(self, /) -> int |None: ...
    @property
    def total_processes(self, /) -> int |None:
        """
        The number of processes that were ever assigned to the job.
        """
    @property
    def total_terminated_processes(self, /) -> int |None:
        """
        The number of processes that a job limit violation terminated.
        """
    @property
    def total_user_time(self, /) -> int |None:
        """
        In 100 ns units.
        """

@final
class JobLimits(BaseRecord):
    """
    The `_EJOB` limit settings of a job. A field that this build does not
    have is `None`.
    """
    @property
    def active_process_limit(self, /) -> int |None: ...
    @property
    def effective_limit_flags(self, /) -> int |None:
        """
        The limit bits in effect, with the bits from nesting.
        """
    @property
    def job_memory_limit(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def limit_flags(self, /) -> int |None:
        """
        The `JOB_OBJECT_LIMIT_*` bits that are set.
        """
    @property
    def maximum_working_set_size(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def minimum_working_set_size(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def per_job_user_time_limit(self, /) -> int |None:
        """
        In 100 ns units.
        """
    @property
    def per_process_user_time_limit(self, /) -> int |None:
        """
        In 100 ns units.
        """
    @property
    def priority_class(self, /) -> int |None: ...
    @property
    def process_memory_limit(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def scheduling_class(self, /) -> int |None: ...
    @property
    def ui_restrictions_class(self, /) -> int |None:
        """
        The `JOB_OBJECT_UILIMIT_*` bits that are set.
        """

@final
class KernelTimer(BaseRecord):
    """
    A `_KTIMER` and its decoded DPC.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def dpc(self, /) -> Diagnostic[int |None]:
        """
        The decoded `_KDPC` address. The value inside is `None` if the timer
        has no DPC.
        """
    @property
    def dpc_encoded(self, /) -> Diagnostic[int |None]:
        """
        `Dpc` in the encoded form that the kernel stores.
        """
    @property
    def dpc_routine(self, /) -> Diagnostic[int |None]:
        """
        The DPC's `DeferredRoutine`.
        """
    @property
    def dpc_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `dpc_routine` as a symbol, if it resolves to one.
        """
    @property
    def due_time(self, /) -> Diagnostic[int]:
        """
        `DueTime`, the interrupt time when the timer expires (see
        `TargetTime.interrupt_time`).
        """
    @property
    def period(self, /) -> Diagnostic[int]:
        """
        `Period` in milliseconds. 0 for a one-shot timer.
        """

@final
class LastError(BaseRecord):
    """
    A thread's Win32 last error and last NTSTATUS (`!gle`).
    """
    @property
    def last_error_name(self, /) -> Diagnostic[str |None]:
        """
        The symbolic name of the error, or `None` if the name is unknown.
        """
    @property
    def last_error_value(self, /) -> Diagnostic[int]: ...
    @property
    def last_status_name(self, /) -> Diagnostic[str |None]:
        """
        The symbolic name of the status, or `None` if the name is unknown.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]: ...
    @property
    def teb(self, /) -> int:
        """
        The `_TEB` that ntoseye read.
        """
    @property
    def teb32(self, /) -> LastError32 |None:
        """
        The values from the WOW64 `_TEB32`. `None` for a native thread.
        """

@final
class LastError32(BaseRecord):
    """
    A WOW64 thread's 32-bit last error and last NTSTATUS.
    """
    @property
    def last_error_name(self, /) -> Diagnostic[str |None]:
        """
        The symbolic name of the error, or `None` if the name is unknown.
        """
    @property
    def last_error_value(self, /) -> Diagnostic[int]: ...
    @property
    def last_status_name(self, /) -> Diagnostic[str |None]:
        """
        The symbolic name of the status, or `None` if the name is unknown.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]: ...
    @property
    def teb(self, /) -> int:
        """
        The `_TEB32` that ntoseye read.
        """

@final
class LfhSubsegment(BaseRecord):
    """
    A segment-heap LFH subsegment (`_HEAP_LFH_SUBSEGMENT`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def bitmap(self, /) -> list[int]:
        """
        The `BlockBitmap` words: a qword on x64, a dword on x86. The low bit
        for a block is set while the block is busy.
        """
    @property
    def block_count(self, /) -> int: ...
    @property
    def block_size(self, /) -> int:
        """
        Bytes per block.
        """
    @property
    def blocks(self, /) -> list[HeapBlock]:
        """
        The blocks of the subsegment. Empty unless the entries were listed.
        """
    @property
    def blocks_per_word(self, /) -> int:
        """
        Blocks per `bitmap` word.
        """
    @property
    def bucket(self, /) -> int:
        """
        The LFH bucket of the subsegment.
        """
    @property
    def busy_count(self, /) -> int: ...
    @property
    def first_block(self, /) -> int: ...
    @property
    def free_count(self, /) -> int: ...

@final
class ListEnd(BaseRecord):
    """
    The end condition of a guest linked-list walk.
    """
    @property
    def address(self, /) -> int |None:
        """
        The address where a cycle closed.
        """
    @property
    def error(self, /) -> str |None:
        """
        The problem with a corrupt link. Some walks also set this for a null
        link.
        """
    @property
    def kind(self, /) -> str:
        """
        `head` (the walk came back to the list head), `null`, `cycle` (a
        loop that does not go through the head), `bound` (the walk reached
        its limit), or `corrupt`.
        """

@final
class LoadedModule(BaseRecord):
    """
    A loaded image (`lm`).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def checksum(self, /) -> int |None:
        """
        The PE checksum. `None` if the loader record does not contain one.
        """
    @property
    def end(self, /) -> int:
        """
        The address after the last byte of the image.
        """
    @property
    def file_version(self, /) -> str |None:
        """
        The file version from the version resource. `None` if ntoseye did not read it.
        """
    @property
    def name(self, /) -> str:
        """
        The image file name (`ntoskrnl.exe`).
        """
    @property
    def path(self, /) -> str |None:
        """
        The full image path, if the loader recorded one.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        The product version from the version resource. `None` if ntoseye did not read it.
        """
    @property
    def short_name(self, /) -> str:
        """
        The short name that `module!symbol` uses (`nt`).
        """
    @property
    def size(self, /) -> int:
        """
        The mapped image size in bytes.
        """
    @property
    def symbols(self, /) -> ModuleSymbols |None:
        """
        The symbol status. `None` except in `inspect()` of a kernel module.
        """
    @property
    def time_date_stamp(self, /) -> int |None:
        """
        The PE timestamp. `None` if the loader record does not contain one.
        """

@final
class LoaderListHead(BaseRecord):
    """
    A `_PEB_LDR_DATA` list head.
    """
    @property
    def address(self, /) -> int:
        """
        The `LIST_ENTRY` head.
        """
    @property
    def blink(self, /) -> Diagnostic[int]:
        """
        The last entry.
        """
    @property
    def flink(self, /) -> Diagnostic[int]:
        """
        The first entry.
        """

@final
class LoaderLists(BaseRecord):
    """
    The heads of the three `_PEB_LDR_DATA` module lists.
    """
    @property
    def in_initialization_order(self, /) -> Diagnostic[LoaderListHead]: ...
    @property
    def in_load_order(self, /) -> Diagnostic[LoaderListHead]: ...
    @property
    def in_memory_order(self, /) -> Diagnostic[LoaderListHead]: ...

@final
class LoaderModule(BaseRecord):
    """
    One module on a process's loader list (`!dlls`).
    """
    @property
    def base_address(self, /) -> int: ...
    @property
    def checksum(self, /) -> int |None:
        """
        The checksum from the PE header. `None` if ntoseye cannot read the
        header.
        """
    @property
    def entry_point(self, /) -> int |None:
        """
        The entry point. `None` if the loader entry has no entry point or
        ntoseye cannot read it.
        """
    @property
    def file_version(self, /) -> str |None:
        """
        The file version from the version resource. `None` if ntoseye cannot
        read it.
        """
    @property
    def is_32bit(self, /) -> bool:
        """
        Whether the module is on the WOW64 (32-bit) loader list.
        """
    @property
    def name(self, /) -> str:
        """
        The full path.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        The product version from the version resource. `None` if ntoseye
        cannot read it.
        """
    @property
    def short_name(self, /) -> str:
        """
        The file name.
        """
    @property
    def size(self, /) -> int:
        """
        The image size in bytes.
        """
    @property
    def time_date_stamp(self, /) -> int |None:
        """
        The link timestamp from the PE header. `None` if ntoseye cannot read
        the header.
        """

@final
class LoaderModules(BaseRecord):
    """
    The modules on a process's loader lists (`!dlls`), and how the walks
    ended.
    """
    @property
    def modules(self, /) -> list[LoaderModule]: ...
    @property
    def termination(self, /) -> ListEnd:
        """
        How the native loader-list walk ended.
        """
    @property
    def wow64_termination(self, /) -> ListEnd |None:
        """
        How the WOW64 loader-list walk ended. `None` for a native process.
        """

@final
class LoaderTerminations(BaseRecord):
    """
    How a process's native and WOW64 loader-list walks ended.
    """
    @property
    def termination(self, /) -> ListEnd: ...
    @property
    def wow64_termination(self, /) -> ListEnd |None:
        """
        `None` for a native process.
        """

@final
class LocalVariableLocation(BaseRecord):
    """
    The location of a local variable.
    """
    @property
    def kind(self, /) -> str:
        """
        `register`, `register_relative`, `frame_relative`, or
        `unavailable`.
        """
    @property
    def offset(self, /) -> int |None:
        """
        The signed displacement, for `register_relative` and
        `frame_relative`.
        """
    @property
    def reason(self, /) -> str |None:
        """
        The reason that the location is unknown, for `unavailable`.
        """
    @property
    def register(self, /) -> str |None:
        """
        The register, for `register` and `register_relative`.
        """

@final
class LookasideList(BaseRecord):
    """
    A decoded `_GENERAL_LOOKASIDE` list (`!lookaside`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def allocate_misses(self, /) -> Diagnostic[int]: ...
    @property
    def depth(self, /) -> Diagnostic[int]: ...
    @property
    def index(self, /) -> int:
        """
        The position in the list walk.
        """
    @property
    def size(self, /) -> Diagnostic[int]:
        """
        The allocation size in bytes.
        """
    @property
    def tag(self, /) -> Diagnostic[PoolTag]: ...
    @property
    def total_allocates(self, /) -> Diagnostic[int]: ...
    @property
    def total_frees(self, /) -> Diagnostic[int]: ...

@final
class LookasideLists(BaseRecord):
    """
    The system lookaside lists (`!lookaside`).
    """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt request stopped the walk.
        """
    @property
    def nonpaged_count(self, /) -> int: ...
    @property
    def nonpaged_termination(self, /) -> str:
        """
        How the nonpaged list walk ended.
        """
    @property
    def paged_count(self, /) -> int: ...
    @property
    def paged_termination(self, /) -> str:
        """
        How the paged list walk ended.
        """
    @property
    def records(self, /) -> list[LookasideList]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its limit before the end.
        """

@final
class Mdl(BaseRecord):
    """
    A decoded `_MDL` header and the page-frame array that follows it
    (`!mdl`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def byte_count(self, /) -> int: ...
    @property
    def byte_offset(self, /) -> int: ...
    @property
    def capacity(self, /) -> int:
        """
        The number of PFN slots that `size` leaves after the header.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `MDL_*` names of the set `flags` bits, low bit first.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def mapped_system_va(self, /) -> int: ...
    @property
    def next(self, /) -> int: ...
    @property
    def pfn_array(self, /) -> int:
        """
        The start of the PFN array, immediately after the header.
        """
    @property
    def pfns(self, /) -> list[int]: ...
    @property
    def process(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes of the header and the PFN array in the allocation.
        """
    @property
    def spanned_pages(self, /) -> int:
        """
        The number of pages that the described buffer spans.
        """
    @property
    def start_va(self, /) -> int: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the list has fewer PFNs than the buffer spans, which happens
        when a smaller count was requested.
        """

@final
class Memory:
    """
    A guest address space: `dbg.memory` (kernel), `proc.memory`, `cpu.memory`,
    or `dbg.physical`.
    """
    def describe(self, /, addr: int) -> AddressDescription:
        """
        Describe the loaded module, kernel region, or process VAD that contains
        `addr`.
        """
    def disassemble(self, /, addr: int, count: int) -> list[DisassembledInstruction]:
        """
        Disassemble `count` instructions at `addr` (`u`).
        """
    def disassemble_back(self, /, addr: int, count: int) -> list[DisassembledInstruction]:
        """
        Disassemble the `count` instructions that end at `addr` (`ub`).
        """
    def disassemble_function(self, /, addr: int) -> list[DisassembledInstruction]:
        """
        Disassemble the runtime function that contains `addr` (`uf`).
        """
    @property
    def dtb(self, /) -> int:
        """
        The directory-table base that this space uses.
        """
    def function_entry(self, /, addr: int) -> FunctionEntry:
        """
        Get the function-table entry and unwind info (AMD64 or ARM64) of the
        function that contains `addr`, with the chained parents (`.fnent`).
        """
    def page_in(self, /, addr: int) -> bool:
        """
        Make `addr` resident with the guest debugger worker (`.pagein`), which
        resumes the guest. When the worker completes, the guest stops and the
        method returns, and `dbg.stop` shows that stop.
        """
    @property
    def pointer_size(self, /) -> int:
        """
        The guest pointer width, in bytes (`$ptrsize`).
        """
    def ptov(self, /, physical: int) -> ReverseTranslation:
        """
        Map a physical address back to virtual addresses with the page tables of
        this space (`!ptov`).
        """
    def read(self, /, addr: int, n: int) -> bytes:
        """
        Read `n` bytes. A virtual read hides the breakpoint opcodes of this
        debugger.
        """
    def read_ansi_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`). `bits`
        sets the layout, as in `read_unicode_string`.
        """
    def read_pointer(self, /, addr: int) -> int:
        """
        Read a pointer-sized value at `addr` (`poi`).
        """
    def read_string(self, /, addr: int, max_len: int = 256) -> str:
        """
        Read a NUL-terminated ANSI string at `addr` (`da`).
        """
    def read_u16(self, /, addr: int) -> int:
        """
        Read a little-endian 16-bit integer.
        """
    def read_u32(self, /, addr: int) -> int:
        """
        Read a little-endian 32-bit integer.
        """
    def read_u64(self, /, addr: int) -> int:
        """
        Read a little-endian 64-bit integer.
        """
    def read_u8(self, /, addr: int) -> int:
        """
        Read a little-endian byte.
        """
    def read_unicode_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`). `bits` sets
        the layout: 32 for the x86 descriptors of a WOW64 process and 64 for
        native descriptors. By default, the `.effmach` setting selects the
        layout.
        """
    def read_wstring(self, /, addr: int, max_len: int = 256) -> str:
        """
        Read a NUL-terminated UTF-16 string at `addr` (`du`).
        """
    def search(self, /, pattern: bytes, start: int, length: int) -> list[MemorySearchMatch]:
        """
        Find matches, including overlapping ones, with symbol/module/VAD
        context. In a virtual space, the search skips pages that it cannot read,
        the breakpoints of this session read as the code that they replaced, and
        the search returns a maximum of 4096 matches.
        """
    def translate(self, /, addr: int) -> int |None:
        """
        Translate a virtual address with the page tables of this space (`!vtop`).
        """
    def translation(self, /, addr: int) -> AddressTranslation:
        """
        Get the full page-table walk and the final translation (`!pte` + `!vtop`).
        """
    def write(self, /, addr: int, data: bytes) -> None:
        """
        Write bytes to this address space.
        """
    def write_u16(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 16-bit integer.
        """
    def write_u32(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 32-bit integer.
        """
    def write_u64(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 64-bit integer.
        """
    def write_u8(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian byte.
        """

@final
class MemoryBasicInformation(BaseRecord):
    """
    The data that `VirtualQuery` reports for an address (`!vprot`). Each
    `MEM_*`/`PAGE_*` value has its name next to it.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def allocation_base(self, /) -> int:
        """
        The VAD's start; zero for free memory.
        """
    @property
    def allocation_protect(self, /) -> int: ...
    @property
    def allocation_protect_name(self, /) -> str: ...
    @property
    def base_address(self, /) -> int: ...
    @property
    def process(self, /) -> ProcessIdentity: ...
    @property
    def protect(self, /) -> int: ...
    @property
    def protect_name(self, /) -> str: ...
    @property
    def region_size(self, /) -> int:
        """
        The number of bytes from `base_address` to the first page with a
        different state or protection, or to the end of the VAD.
        """
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the scan stopped before the end of the region, at its limit
        or at a page table that it cannot read. If true, `region_size` is a
        lower bound.
        """
    @property
    def type(self, /) -> int: ...
    @property
    def type_name(self, /) -> str: ...
    @property
    def vad(self, /) -> int |None:
        """
        The VAD node; `None` for free memory.
        """

@final
class MemoryRegion(BaseRecord):
    """
    One VAD or kernel region (`proc.regions` items, address context).
    """
    @property
    def commit_charge(self, /) -> int |None:
        """
        The committed pages that are charged to the region.
        """
    @property
    def details(self, /) -> str |None:
        """
        A description: the mapped file, or the kernel region kind.
        """
    @property
    def end(self, /) -> int:
        """
        The end of the region (exclusive).
        """
    @property
    def private_memory(self, /) -> bool |None:
        """
        Whether the region is private (not shared or mapped).
        """
    @property
    def protection(self, /) -> int |None:
        """
        The VAD protection value, if known. It is an index into the memory
        manager's protection table, not a `PAGE_*` mask.
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes.
        """
    @property
    def start(self, /) -> int:
        """
        The first address of the region.
        """
    @property
    def vad_type(self, /) -> int |None:
        """
        The VAD type (`_MI_VAD_TYPE`), when known.
        """

@final
class MemoryRegionIterator:
    """
    Iterator over `proc.regions`.
    """
    def __iter__(self, /) -> MemoryRegionIterator: ...
    def __next__(self, /) -> MemoryRegion: ...

@final
class MemorySearchMatch(BaseRecord):
    """
    A memory-search hit, with its symbol and location data.
    """
    @property
    def address(self, /) -> int:
        """
        The address of the match.
        """
    @property
    def kind(self, /) -> str:
        """
        The kind of address: `kernel-module`, `user-image`,
        `kernel-region`, `private`, `mapped`, `unknown`, `physical`,
        `vtl1`, or `foreign` (a root outside NT and VTL1).
        """
    @property
    def module(self, /) -> AddressModule |None:
        """
        The module containing the match, if any.
        """
    @property
    def offset(self, /) -> int:
        """
        The offset of the match from the start of the search.
        """
    @property
    def region(self, /) -> MemoryRegion |None:
        """
        The region containing the match, if any.
        """
    @property
    def section(self, /) -> str |None:
        """
        The module section containing the match, if any.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol, if one resolves.
        """
    @property
    def va_type(self, /) -> str |None:
        """
        The `_MI_SYSTEM_VA_TYPE` name, for a kernel-region match.
        """

@final
class Module:
    """
    One loaded image in the kernel address space or in a process address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, name: str, /) -> int:
        """
        Get the address of a symbol in this module.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        The base address of the loaded image.
        """
    def check_image(self, /, include_diffs: bool = False) -> ImageCheck:
        """
        Compare the executable sections with the cached image (`!chkimg`).
        """
    @property
    def exports(self, /) -> list[Export]:
        """
        The exports from the mapped PE export directory.
        """
    def fetch_image(self, /) -> str:
        """
        Fetch the matching image from the symbol server cache (`.fetchimage`).
        """
    @property
    def file_version(self, /) -> str |None:
        """
        The file version from the version resource of the image.
        """
    def headers(self, /, exports: bool = False, imports: bool = False) -> ImageHeaders:
        """
        The PE headers of the mapped image (`!dh`), including the file and
        optional headers, data directories, sections, and the debug directory
        with its PDB identity. `exports` and `imports` add those directories.
        """
    def image(self, /, zero_fill: bool = False) -> bytes:
        """
        The mapped image in memory layout, for pefile/LIEF. A page that is not
        readable raises `MemoryAccessError`, unless `zero_fill` is set, which
        fills such pages with zeros (for example, a kernel's discarded INIT
        section).
        """
    def image_info(self, /) -> ModuleImageInfo:
        """
        The image identity of the module (`!lmi`): the machine, time stamp,
        size, checksum, and characteristics from the headers, and the debug
        directory with the CodeView PDB name, GUID, and age. The symbol state
        and the local PDB file follow.
        """
    def inspect(self, /) -> LoadedModule |LoaderModule:
        """
        The symbol status, load diagnostics, and PDB identity (`lmv`).
        """
    @property
    def name(self, /) -> str:
        """
        The image name.
        """
    @property
    def path(self, /) -> str |None:
        """
        The full image path, if the loader recorded one.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        The product version from the version resource of the image.
        """
    def reload_symbols(self, /) -> SymbolReloadReport:
        """
        Select, fetch, and index symbols for this module (`ld`, `.reload`).
        """
    @property
    def sections(self, /) -> list[Section]:
        """
        The PE sections and their mapped permissions.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the mapped image.
        """
    @property
    def symbols(self, /) -> ModuleSymbols:
        """
        The symbol status and PDB identity of the module (`lmv`).
        """
    @property
    def timestamp(self, /) -> int |None:
        """
        The PE timestamp, if the loader record contains one.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The module as a plain `dict`, in the shape that MCP renders.
        """
    def verifier(self, /) -> VerifierDriver:
        """
        Get the verifier data for this driver module.
        """

@final
class ModuleEventPolicy(BaseRecord):
    """
    One module load or unload filter (`sx* ld[:<module>]` or
    `sx* ud[:<module>]`).
    """
    @property
    def command(self, /) -> str |None:
        """
        The commands that run at a `break` stop.
        """
    @property
    def event(self, /) -> str:
        """
        `ld` for a load filter, `ud` for an unload filter.
        """
    @property
    def mode(self, /) -> str:
        """
        `break` stops at the event, and `notify` reports it.
        `second_chance` and `ignore` let the load or unload continue with
        no output.
        """
    @property
    def module(self, /) -> str |None:
        """
        The image-name glob that the filter matches, with or without
        extension. None for all modules (bare `ld` or `ud`).
        """

@final
class ModuleImageInfo(BaseRecord):
    """
    The image identity of a module (`!lmi`), with the file-header identity,
    the symbol state, and the debug directory, which includes the CodeView
    PDB name, GUID, and age.
    """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_FILE_*` flags that are set in `characteristics`.
        """
    @property
    def checksum(self, /) -> int: ...
    @property
    def debug_directory(self, /) -> Diagnostic[list[ImageDebugEntry]]: ...
    @property
    def machine(self, /) -> int: ...
    @property
    def machine_name(self, /) -> str:
        """
        `AMD64`, `I386`, ...
        """
    @property
    def module(self, /) -> LoadedModule: ...
    @property
    def size_of_image(self, /) -> int: ...
    @property
    def symbol_file(self, /) -> str |None:
        """
        The local PDB file, if a PDB is loaded.
        """
    @property
    def symbols(self, /) -> ModuleSymbols: ...
    @property
    def time_date_stamp(self, /) -> int: ...

@final
class ModuleIterator:
    """
    Iterator over `dbg.modules` / `proc.modules`.
    """
    def __iter__(self, /) -> ModuleIterator: ...
    def __next__(self, /) -> Module: ...

@final
class ModuleSymbols(BaseRecord):
    """
    The symbol status and PDB identity of a module (`lmv`).
    """
    @property
    def error(self, /) -> str |None:
        """
        The reason for the load failure, for status `failed`.
        """
    @property
    def pdb_age(self, /) -> int |None:
        """
        The age of the loaded PDB. `None` if there is no PDB.
        """
    @property
    def pdb_guid(self, /) -> str |None:
        """
        The GUID of the loaded PDB as 32 hex digits. `None` if there is no PDB.
        """
    @property
    def source(self, /) -> str |None:
        """
        The source of the PDB, if known.
        """
    @property
    def status(self, /) -> str:
        """
        `loaded`, `deferred`, `failed`, `unknown`, ...
        """

@final
class Modules:
    """
    A collection of modules: `dbg.modules` (kernel), `proc.modules` (loader
    lists), or `dbg.secure_kernel.modules` (secure kernel).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Module: ...
    def __iter__(self, /) -> ModuleIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Module |None:
        """
        The module that contains `addr`, or `None` if no module contains it.
        """
    def get(self, /, name: str) -> Module |None:
        """
        Find a module by its short name, ignoring case (`"nt"` is ntoskrnl).
        """
    @property
    def termination(self, /) -> LoaderTerminations |None:
        """
        How the loader lists of a process ended, which shows whether a list is
        complete, corrupt, or truncated. It has `termination` and
        `wow64_termination`, each `{kind, address, error}`, and is `None` for
        kernel modules.
        """

@final
class Msrs:
    """
    Model-specific registers on one processor (`rdmsr`/`wrmsr`, KD only).
    """
    def __getitem__(self, key: int |str, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setitem__(self, key: int |str, value: int, /) -> None: ...

@final
class NameIterator:
    """
    Iterator over names, for example the fields of a record or the registers
    of a register file.
    """
    def __iter__(self, /) -> NameIterator: ...
    def __next__(self, /) -> str: ...

@final
class NotifyCallback(BaseRecord):
    """
    A process, thread, or image notification callback (`callbacks`).
    """
    @property
    def block(self, /) -> int:
        """
        The `_EX_CALLBACK_ROUTINE_BLOCK`.
        """
    @property
    def context(self, /) -> int: ...
    @property
    def function(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        The slot of the callback in the kernel callback array.
        """
    @property
    def kind(self, /) -> str:
        """
        `process`, `thread`, or `image`.
        """
    @property
    def raw(self, /) -> int:
        """
        The raw `_EX_FAST_REF` value of the slot.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to the function. None if no symbol resolves.
        """

@final
class NtHeap(BaseRecord):
    """
    An NT (`_HEAP`) heap.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def encoding(self, /) -> int |None:
        """
        The XOR mask on the metadata of each entry header. None if the
        headers are not encoded.
        """
    @property
    def flags(self, /) -> int:
        """
        `_HEAP.Flags`.
        """
    @property
    def force_flags(self, /) -> int:
        """
        `_HEAP.ForceFlags`.
        """
    @property
    def front_end(self, /) -> int |None:
        """
        The front-end (LFH) heap. None if the heap has no front end.
        """
    @property
    def front_end_type(self, /) -> int:
        """
        `_HEAP.FrontEndHeapType`.
        """
    @property
    def granule(self, /) -> int:
        """
        The size in bytes of the `_HEAP_ENTRY` that starts each block: 16 on
        x64, 8 on x86.
        """
    @property
    def segments(self, /) -> list[NtHeapSegment]: ...
    @property
    def total_free_units(self, /) -> int:
        """
        The free space, in granules.
        """
    @property
    def virtual_blocks(self, /) -> list[NtVirtualBlock]:
        """
        Blocks that are too large for a segment, which the heap allocates
        separately.
        """
    @property
    def virtual_threshold(self, /) -> int:
        """
        `_HEAP.VirtualMemoryThreshold`, in granules.
        """

@final
class NtHeapEntry(BaseRecord):
    """
    An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
    """
    @property
    def address(self, /) -> int:
        """
        The entry header.
        """
    @property
    def checksum_ok(self, /) -> bool:
        """
        Whether the XOR checksum of the header is correct. Always true if the
        headers are not encoded.
        """
    @property
    def flags(self, /) -> int:
        """
        The flags byte of the header.
        """
    @property
    def granule(self, /) -> int:
        """
        The header size in bytes (see `NtHeap.granule`).
        """
    @property
    def kind(self, /) -> str:
        """
        Always `entry`.
        """
    @property
    def lfh(self, /) -> NtLfhUserBlocks |None:
        """
        The legacy-LFH user block region in this busy entry. `None` if the
        entry has no region or ntoseye cannot read it. Also `None` in a
        `Heaps.find_block()` result, because `find_block()` does not decode
        the region.
        """
    @property
    def lfh_error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the LFH region of the entry.
        """
    @property
    def lfh_truncated(self, /) -> bool:
        """
        Whether the `blocks` list of the region stops at the walk limit.
        """
    @property
    def previous_size(self, /) -> int:
        """
        The size in bytes of the previous entry.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes, with the header.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int:
        """
        The number of unused bytes at the end of the block.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int:
        """
        The number of bytes that the caller requested: the block size minus
        the header and the unused bytes.
        """

@final
class NtHeapSegment(BaseRecord):
    """
    One `_HEAP_SEGMENT` of an NT heap.
    """
    @property
    def address(self, /) -> int:
        """
        The segment header.
        """
    @property
    def base(self, /) -> int:
        """
        The first byte of the segment.
        """
    @property
    def end(self, /) -> int:
        """
        The first byte after the last page of the segment.
        """
    @property
    def entries(self, /) -> list[NtHeapEntry]:
        """
        The entry chain of the segment. Empty unless the entries were listed.
        """
    @property
    def first_entry(self, /) -> int: ...
    @property
    def last_valid_entry(self, /) -> int: ...
    @property
    def pages(self, /) -> int: ...
    @property
    def stopped(self, /) -> HeapWalkStop |None:
        """
        Where the chain walk stopped before `last_valid_entry`, and why. None
        if the walk did not stop before `last_valid_entry`.
        """
    @property
    def uncommitted(self, /) -> list[NtUncommittedRange]:
        """
        The uncommitted ranges that the entry chain skips.
        """
    @property
    def uncommitted_pages(self, /) -> int: ...

@final
class NtLfhUserBlocks(BaseRecord):
    """
    A legacy-LFH user block region in one busy NT-heap entry.
    """
    @property
    def block_count(self, /) -> int: ...
    @property
    def block_size(self, /) -> int:
        """
        Bytes per block.
        """
    @property
    def blocks(self, /) -> list[HeapBlock]:
        """
        The blocks of the region. Empty unless the entries were listed.
        """
    @property
    def busy_bitmap(self, /) -> list[int]:
        """
        One bit for each block, set if the block is busy. Block `i` is byte
        `i / 8`, bit `i % 8`.
        """
    @property
    def busy_count(self, /) -> int: ...
    @property
    def first_block(self, /) -> int: ...
    @property
    def header(self, /) -> int:
        """
        The `_HEAP_USERDATA_HEADER`.
        """
    @property
    def stride(self, /) -> int:
        """
        The distance in bytes between consecutive blocks.
        """
    @property
    def subsegment(self, /) -> int:
        """
        The `_HEAP_SUBSEGMENT` that owns the region.
        """

@final
class NtUncommittedRange(BaseRecord):
    """
    An uncommitted range of an NT-heap segment.
    """
    @property
    def end(self, /) -> int:
        """
        The first byte after the range.
        """
    @property
    def start(self, /) -> int: ...

@final
class NtVirtualBlock(BaseRecord):
    """
    An NT-heap block with a separate allocation (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
    """
    @property
    def commit_size(self, /) -> int:
        """
        Committed bytes.
        """
    @property
    def entry(self, /) -> int:
        """
        The block header.
        """
    @property
    def kind(self, /) -> str:
        """
        Always `virtual`.
        """
    @property
    def reserve_size(self, /) -> int:
        """
        Reserved bytes.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """

@final
class ObjectDirectoryEntry(BaseRecord):
    """
    A named object in an object directory.
    """
    @property
    def name(self, /) -> str: ...
    @property
    def object(self, /) -> int: ...
    @property
    def type(self, /) -> str |None:
        """
        The type of the object (`Directory`, `Driver`, `SymbolicLink`, ...).
        None if ntoseye cannot decode its header.
        """

@final
class ObjectSecurity(BaseRecord):
    """
    The security descriptor of an object, from its header (`!objsd`).
    """
    @property
    def descriptor(self, /) -> SecurityDescriptor |None:
        """
        `None` if the object has no descriptor.
        """
    @property
    def descriptor_address(self, /) -> int:
        """
        `fast_reference` without its count bits.
        """
    @property
    def fast_reference(self, /) -> int:
        """
        `SecurityDescriptor`, a fast reference whose low bits hold a
        reference count.
        """
    @property
    def header(self, /) -> int:
        """
        The `_OBJECT_HEADER`.
        """
    @property
    def object(self, /) -> int: ...

@final
class Operand(BaseRecord):
    """
    One explicit operand of a decoded instruction. Fields that do not apply
    to its `kind` are None.
    """
    @property
    def base(self, /) -> str |None:
        """
        A memory operand's base register, full and lowercase (`rip` when
        RIP-relative).
        """
    @property
    def displacement(self, /) -> int |None:
        """
        A memory operand's signed displacement: relative to the next
        instruction when RIP-relative, and the writeback offset of an ARM64
        post-indexed operand.
        """
    @property
    def full_register(self, /) -> str |None:
        """
        The architectural register that `register` is part of (`r8` for
        `r8d`, `x3` for `w3`; vector registers stay as written).
        """
    @property
    def immediate(self, /) -> int |None:
        """
        An immediate operand's value (negative when the instruction
        sign-extends it), or a branch operand's target address.
        """
    @property
    def index(self, /) -> str |None:
        """
        A memory operand's index register, full and lowercase.
        """
    @property
    def kind(self, /) -> str:
        """
        `register`, `memory`, `immediate`, `branch` (a branch or PC-relative
        label target), or `other`.
        """
    @property
    def register(self, /) -> str |None:
        """
        A register operand's register as written, lowercase (`r8d`, `w3`).
        """
    @property
    def scale(self, /) -> int |None:
        """
        The scale of `index`.
        """
    @property
    def segment(self, /) -> str |None:
        """
        A memory operand's x86 segment override (`gs`).
        """
    @property
    def size(self, /) -> int |None:
        """
        A memory operand's access size in bytes, when known (x86 only).
        """
    @property
    def text(self, /) -> str:
        """
        The operand as `asm` shows it.
        """

@final
class PageLocation(BaseRecord):
    """
    The `PageLocation` of a PFN, which is the list that holds the page.
    """
    @property
    def name(self, /) -> str:
        """
        The `_MMLISTS` name (`ActiveAndValid`, `StandbyPageList`, ...).
        """
    @property
    def value(self, /) -> int: ...

@final
class PageTableEntry(BaseRecord):
    """
    One page-table level of a walk, with the entry decoded into WinDbg-style
    flags. For an entry that points to a lower table, `writable`, `user`,
    and `nx` are the restrictions that the entry puts on everything below
    it.
    """
    @property
    def address(self, /) -> int:
        """
        The entry's virtual address.
        """
    @property
    def flags(self, /) -> str:
        """
        WinDbg's flag string for the entry.
        """
    @property
    def large_page(self, /) -> bool:
        """
        Whether the entry maps a large page instead of pointing to a lower
        table.
        """
    @property
    def level(self, /) -> str:
        """
        `PXE`, `PPE`, `PDE`, or `PTE`.
        """
    @property
    def nx(self, /) -> bool: ...
    @property
    def pfn(self, /) -> int:
        """
        The frame the entry points at.
        """
    @property
    def present(self, /) -> bool: ...
    @property
    def user(self, /) -> bool: ...
    @property
    def value(self, /) -> int:
        """
        The entry as read.
        """
    @property
    def writable(self, /) -> bool: ...

@final
class PciBar(BaseRecord):
    """
    A base address register.
    """
    @property
    def address(self, /) -> int:
        """
        The decoded base address.
        """
    @property
    def index(self, /) -> int:
        """
        The BAR number (0-5).
        """
    @property
    def kind(self, /) -> str:
        """
        `io`, `memory32`, or `memory64`.
        """
    @property
    def prefetchable(self, /) -> bool: ...
    @property
    def raw(self, /) -> int:
        """
        The raw register value (both halves for a 64-bit BAR).
        """

@final
class PciBus(BaseRecord):
    """
    A bus that pci.sys enumerated, with the devices on it and the buses
    behind its bridges.
    """
    @property
    def bridge_pdo(self, /) -> int:
        """
        The physical device object of the bridge. 0 for a root bus.
        """
    @property
    def child_buses(self, /) -> list[PciBus]: ...
    @property
    def devices(self, /) -> list[PciTreeDevice]: ...
    @property
    def extension(self, /) -> int:
        """
        The pci.sys bus extension.
        """
    @property
    def number(self, /) -> int: ...
    @property
    def subordinate(self, /) -> int:
        """
        The highest bus number behind this bus.
        """

@final
class PciBuses(BaseRecord):
    """
    The bus numbers of a type 1 or type 2 header.
    """
    @property
    def primary(self, /) -> int: ...
    @property
    def secondary(self, /) -> int: ...
    @property
    def subordinate(self, /) -> int: ...

@final
class PciCapability(BaseRecord):
    """
    An entry in a capability list.
    """
    @property
    def id(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        The name of the capability, if it is known.
        """
    @property
    def offset(self, /) -> int:
        """
        The offset of the entry in configuration space.
        """
    @property
    def version(self, /) -> int |None:
        """
        The version of an extended capability. `None` for a standard capability.
        """

@final
class PciConfigBytes(BaseRecord):
    """
    The raw configuration bytes that the caller requested.
    """
    @property
    def bytes(self, /) -> str:
        """
        The bytes, as hex.
        """
    @property
    def offset(self, /) -> int:
        """
        The offset of the first byte.
        """

@final
class PciFunction(BaseRecord):
    """
    The decoded configuration space of one function.
    """
    @property
    def bars(self, /) -> list[PciBar]: ...
    @property
    def base_class(self, /) -> int: ...
    @property
    def bus(self, /) -> int: ...
    @property
    def buses(self, /) -> PciBuses |None:
        """
        Type 1 and 2 headers only.
        """
    @property
    def capabilities(self, /) -> list[PciCapability]: ...
    @property
    def class_name(self, /) -> str |None:
        """
        The name of the class code, if it is known.
        """
    @property
    def command(self, /) -> int: ...
    @property
    def command_flags(self, /) -> list[str]:
        """
        The names of the bits that are set in the command register.
        """
    @property
    def config(self, /) -> PciConfigBytes |None:
        """
        The requested raw range (`raw=True`). Otherwise `None`.
        """
    @property
    def device(self, /) -> int: ...
    @property
    def device_id(self, /) -> int: ...
    @property
    def expansion_rom(self, /) -> int |None:
        """
        The expansion ROM base register (types 0 and 1).
        """
    @property
    def extended_capabilities(self, /) -> list[PciCapability]:
        """
        The PCI Express extended capabilities. Empty for a conventional
        function, or if ntoseye read only 256 bytes.
        """
    @property
    def function(self, /) -> int: ...
    @property
    def header_type(self, /) -> int: ...
    @property
    def interrupt_line(self, /) -> int: ...
    @property
    def interrupt_pin(self, /) -> int:
        """
        0 for none, 1-4 for INTA#-INTD#.
        """
    @property
    def multifunction(self, /) -> bool: ...
    @property
    def prog_if(self, /) -> int: ...
    @property
    def revision(self, /) -> int: ...
    @property
    def segment(self, /) -> int: ...
    @property
    def status(self, /) -> int: ...
    @property
    def status_flags(self, /) -> list[str]:
        """
        The names of the bits that are set in the status register.
        """
    @property
    def sub_class(self, /) -> int: ...
    @property
    def subsystem_id(self, /) -> int |None:
        """
        Type 0 and 2 headers only.
        """
    @property
    def subsystem_vendor_id(self, /) -> int |None:
        """
        Type 0 and 2 headers only.
        """
    @property
    def vendor_id(self, /) -> int: ...

@final
class PciScan(BaseRecord):
    """
    The functions that a `!pci` scan found.
    """
    @property
    def functions(self, /) -> list[PciFunction]: ...
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt request stopped the scan early.
        """

@final
class PciSegment(BaseRecord):
    """
    A PCI segment and its root buses.
    """
    @property
    def address(self, /) -> int:
        """
        The pci.sys segment record.
        """
    @property
    def root_buses(self, /) -> list[PciBus]: ...
    @property
    def segment(self, /) -> int: ...

@final
class PciTree(BaseRecord):
    """
    The PCI hierarchy that pci.sys tracks (`!pcitree`).
    """
    @property
    def errors(self, /) -> list[str]:
        """
        Each bus or function that ntoseye could not read, after which the
        walk does not continue in the list that holds it.
        """
    @property
    def segments(self, /) -> list[PciSegment]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its limit before the end.
        """

@final
class PciTreeDevice(BaseRecord):
    """
    A device that pci.sys enumerated (`!pcitree`).
    """
    @property
    def base_class(self, /) -> int: ...
    @property
    def bus(self, /) -> int: ...
    @property
    def class_name(self, /) -> str |None:
        """
        The name of the class code, if it is known.
        """
    @property
    def device(self, /) -> int: ...
    @property
    def device_id(self, /) -> int: ...
    @property
    def extension(self, /) -> int:
        """
        The pci.sys device extension.
        """
    @property
    def function(self, /) -> int: ...
    @property
    def header_type(self, /) -> int: ...
    @property
    def instance_path(self, /) -> str |None:
        """
        The PnP instance path of the device, if pci.sys recorded one.
        """
    @property
    def pdo(self, /) -> int:
        """
        The physical device object of the device.
        """
    @property
    def prog_if(self, /) -> int: ...
    @property
    def revision(self, /) -> int: ...
    @property
    def sub_class(self, /) -> int: ...
    @property
    def subsystem_id(self, /) -> int: ...
    @property
    def subsystem_vendor_id(self, /) -> int: ...
    @property
    def vendor_id(self, /) -> int: ...

@final
class Pcr(BaseRecord):
    """
    The main KPCR and KPRCB data of a processor (`!pcr`). A field is a
    diagnostic if its read can fail separately from the other reads.
    """
    @property
    def current_prcb(self, /) -> Diagnostic[int]:
        """
        `_KPCR.CurrentPrcb`.
        """
    @property
    def current_thread(self, /) -> Diagnostic[int]:
        """
        The running `_KTHREAD`.
        """
    @property
    def gdtr(self, /) -> Diagnostic[DescriptorRegister]:
        """
        The global descriptor table register.
        """
    @property
    def idle_thread(self, /) -> Diagnostic[int]:
        """
        The idle `_KTHREAD` of the processor.
        """
    @property
    def idtr(self, /) -> Diagnostic[DescriptorRegister]:
        """
        The interrupt descriptor table register.
        """
    @property
    def irql(self, /) -> Diagnostic[int]:
        """
        The current IRQL.
        """
    @property
    def kd_version_block(self, /) -> Diagnostic[int]:
        """
        `_KPCR.KdVersionBlock`.
        """
    @property
    def kpcr(self, /) -> Diagnostic[int]:
        """
        The `_KPCR` address.
        """
    @property
    def kprcb(self, /) -> int:
        """
        The `_KPRCB` address.
        """
    @property
    def next_thread(self, /) -> Diagnostic[int]:
        """
        The `_KTHREAD` selected to run next.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def self_pcr(self, /) -> Diagnostic[int]:
        """
        `_KPCR.Self`.
        """
    @property
    def tss_base(self, /) -> Diagnostic[int]:
        """
        The address of the task state segment.
        """

@final
class Peb(BaseRecord):
    """
    A process's `_PEB` (`!peb`). ntoseye reads each field separately.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def api_set_map(self, /) -> Diagnostic[int]:
        """
        The API set schema.
        """
    @property
    def being_debugged(self, /) -> Diagnostic[int]:
        """
        `BeingDebugged`: nonzero while a user-mode debugger is attached.
        """
    @property
    def image_base_address(self, /) -> Diagnostic[int]: ...
    @property
    def ldr(self, /) -> Diagnostic[int]:
        """
        The `_PEB_LDR_DATA` address.
        """
    @property
    def loader_lists(self, /) -> Diagnostic[LoaderLists]:
        """
        The loader's module list heads.
        """
    @property
    def number_of_heaps(self, /) -> Diagnostic[int]: ...
    @property
    def number_of_processors(self, /) -> Diagnostic[int]: ...
    @property
    def os_build_number(self, /) -> Diagnostic[int]: ...
    @property
    def os_major_version(self, /) -> Diagnostic[int]: ...
    @property
    def os_minor_version(self, /) -> Diagnostic[int]: ...
    @property
    def peb32(self, /) -> Peb32 |None:
        """
        The WOW64 `_PEB32`. `None` for a native process.
        """
    @property
    def process_heap(self, /) -> Diagnostic[int]:
        """
        The default heap.
        """
    @property
    def process_heaps(self, /) -> Diagnostic[int]:
        """
        The heap pointer array.
        """
    @property
    def process_parameters(self, /) -> Diagnostic[int]:
        """
        The `_RTL_USER_PROCESS_PARAMETERS` address.
        """
    @property
    def process_parameters_detail(self, /) -> Diagnostic[ProcessParameters]:
        """
        The decoded process parameters.
        """
    @property
    def session_id(self, /) -> Diagnostic[int]: ...

@final
class Peb32(BaseRecord):
    """
    A WOW64 process's 32-bit `_PEB32`. ntoseye reads each field separately.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def being_debugged(self, /) -> Diagnostic[int]:
        """
        `BeingDebugged`: nonzero while a user-mode debugger is attached.
        """
    @property
    def image_base_address(self, /) -> Diagnostic[int]: ...
    @property
    def ldr(self, /) -> Diagnostic[int]:
        """
        The `_PEB_LDR_DATA32` address.
        """
    @property
    def loader_lists(self, /) -> Diagnostic[LoaderLists]:
        """
        The loader's 32-bit module list heads.
        """
    @property
    def number_of_heaps(self, /) -> Diagnostic[int]: ...
    @property
    def number_of_processors(self, /) -> Diagnostic[int]: ...
    @property
    def os_build_number(self, /) -> Diagnostic[int]: ...
    @property
    def os_major_version(self, /) -> Diagnostic[int]: ...
    @property
    def os_minor_version(self, /) -> Diagnostic[int]: ...
    @property
    def process_heap(self, /) -> Diagnostic[int]:
        """
        The default heap.
        """
    @property
    def process_heaps(self, /) -> Diagnostic[int]:
        """
        The heap pointer array.
        """
    @property
    def process_parameters(self, /) -> Diagnostic[int]:
        """
        The 32-bit process parameters' address.
        """
    @property
    def process_parameters_detail(self, /) -> Diagnostic[ProcessParameters]:
        """
        The decoded 32-bit process parameters.
        """
    @property
    def session_id(self, /) -> Diagnostic[int]: ...

@final
class Pfn(BaseRecord):
    """
    A decoded `_MMPFN` record (`!pfn`). Union members that the page state
    does not use are `None`: the list links when the page is not on a list,
    `share_count` and `ws_index` when the page is not active, and `event`
    when the page is not in transition.
    """
    @property
    def blink(self, /) -> int |None: ...
    @property
    def cache_attribute(self, /) -> CacheAttribute: ...
    @property
    def event(self, /) -> int |None: ...
    @property
    def flink(self, /) -> int |None: ...
    @property
    def modified(self, /) -> bool: ...
    @property
    def node_blink_low(self, /) -> int |None: ...
    @property
    def node_flink_low(self, /) -> int |None: ...
    @property
    def original_pte(self, /) -> int: ...
    @property
    def page_color(self, /) -> Diagnostic[int]:
        """
        Not available if the `_MMPFN` of this build has no `PageColor`.
        """
    @property
    def page_location(self, /) -> PageLocation: ...
    @property
    def pfn(self, /) -> int:
        """
        The page frame number.
        """
    @property
    def physical_address(self, /) -> int |None:
        """
        The requested physical address, for a physical-address selector.
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def pte_address(self, /) -> int: ...
    @property
    def pte_frame(self, /) -> int:
        """
        The PFN of the page table that holds the PTE of the page.
        """
    @property
    def record(self, /) -> int:
        """
        The `_MMPFN` record's address.
        """
    @property
    def reference_count(self, /) -> int: ...
    @property
    def selector(self, /) -> PfnSelector: ...
    @property
    def share_count(self, /) -> int |None: ...
    @property
    def used_entry_count(self, /) -> int: ...
    @property
    def ws_index(self, /) -> int |None:
        """
        The working-set index.
        """

@final
class PfnSelector(BaseRecord):
    """
    The input to `!pfn`.
    """
    @property
    def kind(self, /) -> str:
        """
        `pfn` or `physical_address`.
        """
    @property
    def value(self, /) -> int: ...

@final
class PhysicalMapping(BaseRecord):
    """
    A virtual address that maps a physical page.
    """
    @property
    def large(self, /) -> bool:
        """
        Whether a large page maps it.
        """
    @property
    def virtual_address(self, /) -> int: ...

@final
class PnpTriage(BaseRecord):
    """
    PnP triage groups from one limited walk of the device tree
    (`!pnptriage`).
    """
    @property
    def not_started(self, /) -> list[DevNodeSummary]:
        """
        Nodes that are not started, not removed, and not deleted.
        """
    @property
    def pending_irps(self, /) -> list[DevNodeSummary]:
        """
        Nodes with a pending IRP.
        """
    @property
    def problems(self, /) -> list[DevNodeSummary]:
        """
        Nodes with a problem code.
        """
    @property
    def started(self, /) -> int: ...
    @property
    def total(self, /) -> int:
        """
        The number of nodes walked.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its limit of 4096 nodes.
        """

@final
class PoolBlock(BaseRecord):
    """
    A `_POOL_HEADER` block in a pool page.
    """
    @property
    def allocated(self, /) -> bool: ...
    @property
    def body(self, /) -> int:
        """
        The address of the allocation, immediately after the header.
        """
    @property
    def header(self, /) -> int:
        """
        The pool header's address.
        """
    @property
    def marked(self, /) -> bool:
        """
        Whether the block holds the requested address.
        """
    @property
    def pool_type(self, /) -> int:
        """
        The header's `PoolType` bits.
        """
    @property
    def previous_size(self, /) -> int:
        """
        The previous block's size in bytes.
        """
    @property
    def size(self, /) -> int:
        """
        The block size in bytes, with the header.
        """
    @property
    def state(self, /) -> str:
        """
        `allocated`, `free`, or a description of what is wrong.
        """
    @property
    def tag(self, /) -> int: ...
    @property
    def tag_name(self, /) -> str:
        """
        The tag as its four characters.
        """
    @property
    def target_offset(self, /) -> int |None:
        """
        The offset of the requested address in the block, if the block holds it.
        """

@final
class PoolIrp(BaseRecord):
    """
    An IRP that `!irpfind` found in pool.
    """
    @property
    def completed(self, /) -> bool:
        """
        Whether all stack locations are used, which means that completion of
        the IRP is in progress or done.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The driver that owns the device of the current stack location. None if
        ntoseye cannot resolve it.
        """
    @property
    def irp(self, /) -> Irp: ...
    @property
    def mdl_process(self, /) -> int |None:
        """
        `MdlAddress->Process`. None if the IRP has no MDL.
        """
    @property
    def original_file_object(self, /) -> int:
        """
        `Tail.Overlay.OriginalFileObject`.
        """
    @property
    def pool_header(self, /) -> int |None:
        """
        The `_POOL_HEADER` before the IRP. None for a big-pool allocation.
        """
    @property
    def tag(self, /) -> str:
        """
        The pool tag of the allocation.
        """

@final
class PoolMatch(BaseRecord):
    """
    A pool allocation with the search tag (`!poolfind`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def allocated(self, /) -> bool: ...
    @property
    def index(self, /) -> int |None:
        """
        The `PoolBigPageTable` index, for a big-pool match.
        """
    @property
    def pool_type(self, /) -> str |None:
        """
        `NonPagedPool` or `PagedPool`, when known.
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes.
        """
    @property
    def source(self, /) -> str:
        """
        Where the search found the allocation: a pool range scan or the big-pool
        table.
        """
    @property
    def state(self, /) -> str: ...
    @property
    def table_entry(self, /) -> int |None:
        """
        The `PoolBigPageTable` entry, for a big-pool match.
        """
    @property
    def tag(self, /) -> int: ...
    @property
    def tag_name(self, /) -> str:
        """
        The tag as its four characters.
        """

@final
class PoolPage(BaseRecord):
    """
    The pool page holding an address (`!pool`).
    """
    @property
    def big(self, /) -> BigPoolAllocation |None:
        """
        The large allocation that holds the address, if the address is in one.
        """
    @property
    def blocks(self, /) -> list[PoolBlock]: ...
    @property
    def message(self, /) -> str |None:
        """
        The reason that no blocks were decoded, if none were.
        """
    @property
    def near_symbol(self, /) -> str |None:
        """
        The nearest symbol to the address, if one resolves.
        """
    @property
    def page(self, /) -> int:
        """
        The page's address.
        """
    @property
    def page_kind(self, /) -> str:
        """
        The layout of the page: its pool kind, or the reason that the page
        could not be decoded.
        """
    @property
    def region(self, /) -> PoolRegion |None:
        """
        The pool range holding the page, when known.
        """
    @property
    def segment_heap_hint(self, /) -> str |None:
        """
        Set if the page belongs to the segment heap, whose blocks have no
        pool headers.
        """
    @property
    def target(self, /) -> int:
        """
        The requested address.
        """
    @property
    def target_index(self, /) -> int |None:
        """
        The index in `blocks` of the block that holds the requested address.
        """

@final
class PoolProblem(BaseRecord):
    """
    A pool header inconsistency.
    """
    @property
    def header(self, /) -> int:
        """
        The header where the problem is.
        """
    @property
    def message(self, /) -> str:
        """
        What is wrong.
        """

@final
class PoolRangeScan(BaseRecord):
    """
    How far `!poolfind` scanned one virtual pool range.
    """
    @property
    def end(self, /) -> int:
        """
        The end of the range (exclusive).
        """
    @property
    def name(self, /) -> str: ...
    @property
    def pages(self, /) -> int:
        """
        The number of pages in the range, mapped or not.
        """
    @property
    def scanned_pages(self, /) -> int:
        """
        The number of mapped pages that the scan read.
        """
    @property
    def start(self, /) -> int: ...
    @property
    def stopped_at(self, /) -> int |None:
        """
        The mapped page where the scan stopped, if the match limit or an
        interrupt stopped it early. The scan did not read this page.
        """

@final
class PoolRegion(BaseRecord):
    """
    A virtual pool range.
    """
    @property
    def end(self, /) -> int:
        """
        The end of the range (exclusive).
        """
    @property
    def name(self, /) -> str: ...
    @property
    def start(self, /) -> int: ...

@final
class PoolSearch(BaseRecord):
    """
    A pool-tag search (`!poolfind`).
    """
    @property
    def big_status(self, /) -> str |None:
        """
        The read status of the big-pool table, if the search included it.
        """
    @property
    def found(self, /) -> int:
        """
        The number of matches found, including those past the listing limit.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt request stopped the search.
        """
    @property
    def matches(self, /) -> list[PoolMatch]: ...
    @property
    def pool_type(self, /) -> str |None:
        """
        The pool that the search was limited to, if any.
        """
    @property
    def ranges(self, /) -> list[PoolRangeScan]: ...
    @property
    def tag(self, /) -> str:
        """
        The searched tag.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether more matches were found than are listed.
        """

@final
class PoolTag(BaseRecord):
    """
    A pool tag.
    """
    @property
    def name(self, /) -> str:
        """
        The tag as its four characters.
        """
    @property
    def value(self, /) -> int: ...

@final
class PoolTagUsage(BaseRecord):
    """
    The pool usage of one tag, in bytes (`!poolused`). A value is `None` if
    the tracker has no entry for that pool.
    """
    @property
    def nonpaged_allocs(self, /) -> int |None:
        """
        `None` unless allocation counts were requested.
        """
    @property
    def nonpaged_bytes(self, /) -> int |None: ...
    @property
    def nonpaged_frees(self, /) -> int |None:
        """
        `None` unless allocation counts were requested.
        """
    @property
    def paged_allocs(self, /) -> int |None:
        """
        `None` unless allocation counts were requested.
        """
    @property
    def paged_bytes(self, /) -> int |None: ...
    @property
    def paged_frees(self, /) -> int |None:
        """
        `None` unless allocation counts were requested.
        """
    @property
    def tag(self, /) -> int: ...
    @property
    def tag_name(self, /) -> str:
        """
        The tag as its four characters.
        """

@final
class PoolUsage(BaseRecord):
    """
    Pool usage by tag, from the pool tracker (`!poolused`).
    """
    @property
    def big_status(self, /) -> str:
        """
        The read status of the big-pool table.
        """
    @property
    def include_counts(self, /) -> bool:
        """
        Whether allocation and free counts were requested.
        """
    @property
    def rows(self, /) -> list[PoolTagUsage]: ...
    @property
    def rows_truncated(self, /) -> bool:
        """
        Whether more tags matched than are listed.
        """
    @property
    def sort(self, /) -> str:
        """
        The sort order: `tag`, `nonpaged_bytes`, or `paged_bytes`.
        """
    @property
    def tag_filter(self, /) -> str |None:
        """
        The tag pattern that filters the rows, if any.
        """
    @property
    def tracker_status(self, /) -> str:
        """
        The read status of the pool tracker table.
        """

@final
class PoolValidation(BaseRecord):
    """
    The blocks of the pool page that holds an address, with a check of
    header consistency (`!poolval`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def blocks(self, /) -> list[PoolBlock]: ...
    @property
    def layout(self, /) -> str:
        """
        `chained` (the classic pool) or `segment heap`.
        """
    @property
    def page(self, /) -> int:
        """
        The page's address.
        """
    @property
    def problem(self, /) -> PoolProblem |None:
        """
        The first inconsistency found.
        """
    @property
    def region(self, /) -> PoolRegion |None:
        """
        The pool range holding the page, when known.
        """
    @property
    def valid(self, /) -> bool:
        """
        Whether the headers are consistent (`problem` is `None`).
        """

@final
class Prcb(BaseRecord):
    """
    Selected `_KPRCB` fields of a processor (`!prcb`).
    """
    @property
    def current_thread(self, /) -> Diagnostic[int]:
        """
        The running `_KTHREAD`.
        """
    @property
    def dpc_routine_active(self, /) -> Diagnostic[int]:
        """
        `_KPRCB.DpcRoutineActive`.
        """
    @property
    def idle_thread(self, /) -> Diagnostic[int]:
        """
        The idle `_KTHREAD` of the processor.
        """
    @property
    def interrupt_count(self, /) -> Diagnostic[int]:
        """
        `_KPRCB.InterruptCount`.
        """
    @property
    def kprcb(self, /) -> int:
        """
        The `_KPRCB` address.
        """
    @property
    def next_thread(self, /) -> Diagnostic[int]:
        """
        The `_KTHREAD` selected to run next.
        """
    @property
    def number(self, /) -> Diagnostic[int]:
        """
        `_KPRCB.Number`.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def processor_state(self, /) -> Diagnostic[ProcessorStateArea]: ...

@final
class ProcedureLocal(BaseRecord):
    """
    A PDB local or parameter.
    """
    @property
    def byte_size(self, /) -> int |None:
        """
        `None` if the size of the type is unknown.
        """
    @property
    def location(self, /) -> LocalVariableLocation: ...
    @property
    def name(self, /) -> str: ...
    @property
    def parameter(self, /) -> bool:
        """
        True for a parameter, False for a local.
        """
    @property
    def type_name(self, /) -> str:
        """
        The PDB type spelling.
        """

@final
class Process:
    """
    One process, with identity fields and views bound to its address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> ApcQueues:
        """
        Decode the kernel and user APC queues of this process (`!apc`).
        """
    @property
    def dtb(self, /) -> int:
        """
        The process page-table root.
        """
    @property
    def eprocess(self, /) -> int:
        """
        The `_EPROCESS` virtual address.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in the symbol scope of this process.
        """
    def handle(self, /, value: int) -> HandleEntry:
        """
        Decode a handle in the handle table of this process.
        """
    def handle_traces(self, /, handle: int |None = None, max_traces: int |None = None) -> HandleTraces:
        """
        Get the stacks that handle tracing recorded for the handles of this
        process, newest first and at most `max_traces` of them (`!htrace`). If
        you give `handle`, you get only the stacks of that handle. `debug_info`
        is `None` if tracing is off for the process.
        """
    def handles(self, /, limit: int = 256) -> HandleTable:
        """
        List a maximum of `limit` handles in the handle table of this process.
        """
    @property
    def heaps(self, /) -> Heaps:
        """
        The heaps in the PEB of this process.
        """
    @property
    def memory(self, /) -> Memory:
        """
        The virtual memory, through the page tables of this process.
        """
    @property
    def modules(self, /) -> Modules:
        """
        The modules from the PEB loader lists of this process.
        """
    @property
    def name(self, /) -> str:
        """
        The image name.
        """
    @property
    def object(self, /) -> Struct:
        """
        The process `_EPROCESS` cursor.
        """
    @property
    def peb(self, /) -> Struct |None:
        """
        The process `_PEB` cursor, or `None` if the process has no PEB.
        """
    @property
    def pid(self, /) -> int:
        """
        The process identifier.
        """
    @property
    def ppid(self, /) -> int:
        """
        The parent process identifier.
        """
    def protection(self, /, address: int) -> MemoryBasicInformation:
        """
        Get the region that contains `address`, as `VirtualQuery` reports it
        (`!vprot`). The result has the base, the allocation base and
        protection, the region size, the state, the protection, and the type.
        """
    @property
    def regions(self, /) -> Regions:
        """
        The process VAD regions (`!vad` / `vmmap`).
        """
    @property
    def session(self, /) -> int |None:
        """
        The Windows session identifier.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        The symbols, resolved in the address space of this process.
        """
    @property
    def threads(self, /) -> Threads:
        """
        The Windows threads that this process owns.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Get the process identity as a plain `dict` (`pid`, `name`, `dtb`,
        `eprocess`, `wow64`), in the shape that MCP shows.
        """
    def token(self, /) -> Token:
        """
        Get the process token and its security information.
        """
    @property
    def types(self, /) -> Types:
        """
        The PDB types and cursors, bound to the address space of this process.
        """
    @property
    def wow64(self, /) -> bool:
        """
        True if this process has a WOW64 (32-bit) PEB.
        """

@final
class ProcessGlobalFlags(BaseRecord):
    """
    The `_PEB.NtGlobalFlag` of a process.
    """
    @property
    def flags(self, /) -> list[GlobalFlag]: ...
    @property
    def value(self, /) -> int: ...

@final
class ProcessIdentity(BaseRecord):
    """
    The identity of a process (`ps`, `!process 0 0`).
    """
    @property
    def dtb(self, /) -> int:
        """
        The directory table base (page-table root).
        """
    @property
    def eprocess(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        The image name.
        """
    @property
    def pid(self, /) -> int: ...
    @property
    def wow64(self, /) -> bool:
        """
        True if it is a 32-bit process that runs under WOW64.
        """

@final
class ProcessIterator:
    """
    Iterator over `dbg.processes`.
    """
    def __iter__(self, /) -> ProcessIterator: ...
    def __next__(self, /) -> Process: ...

@final
class ProcessMemoryUsage(BaseRecord):
    """
    One process's memory counters, in bytes.
    """
    @property
    def pagefile_usage(self, /) -> Diagnostic[int]: ...
    @property
    def peak_pagefile_usage(self, /) -> Diagnostic[int]: ...
    @property
    def peak_virtual_size(self, /) -> Diagnostic[int]: ...
    @property
    def peak_working_set_size(self, /) -> Diagnostic[int]: ...
    @property
    def private_usage(self, /) -> Diagnostic[int]: ...
    @property
    def process(self, /) -> ProcessIdentity: ...
    @property
    def virtual_size(self, /) -> Diagnostic[int]: ...
    @property
    def working_set_size(self, /) -> Diagnostic[int]: ...

@final
class ProcessParameters(BaseRecord):
    """
    A process's `_RTL_USER_PROCESS_PARAMETERS`. ntoseye reads each string
    separately, and a string that is paged out is unavailable.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def command_line(self, /) -> Diagnostic[str]: ...
    @property
    def current_directory(self, /) -> Diagnostic[str]: ...
    @property
    def desktop_info(self, /) -> Diagnostic[str]: ...
    @property
    def dll_path(self, /) -> Diagnostic[str]:
        """
        The DLL search path.
        """
    @property
    def environment(self, /) -> Diagnostic[int]:
        """
        The environment block's address.
        """
    @property
    def environment_size(self, /) -> Diagnostic[int]:
        """
        The environment block's size in bytes.
        """
    @property
    def image_path_name(self, /) -> Diagnostic[str]:
        """
        The image's full path.
        """
    @property
    def runtime_data(self, /) -> Diagnostic[str]: ...
    @property
    def shell_info(self, /) -> Diagnostic[str]: ...
    @property
    def window_title(self, /) -> Diagnostic[str]: ...

@final
class Processes:
    """
    The running processes, with their PIDs as keys (`dbg.processes`). Each
    iteration reads the process list again, and `find(name)` matches image
    names.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, pid: int, /) -> Process: ...
    def __iter__(self, /) -> ProcessIterator: ...
    def __len__(self, /) -> int: ...
    def find(self, /, name: str) -> list[Process]:
        """
        Find all processes whose image name is an exact match, ignoring case.
        """
    def get(self, /, pid: int) -> Process |None:
        """
        Find a process by PID. Return `None` if the PID does not exist.
        """

@final
class ProcessorError(BaseRecord):
    """
    A processor whose state ntoseye could not read.
    """
    @property
    def message(self, /) -> str: ...
    @property
    def processor(self, /) -> int: ...

@final
class ProcessorStateArea(BaseRecord):
    """
    The `_KPROCESSOR_STATE` embedded in a `_KPRCB`.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def context_frame(self, /) -> Diagnostic[int]:
        """
        The address of the `_CONTEXT` embedded in the processor state.
        """
    @property
    def name(self, /) -> str:
        """
        The type name.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the structure in bytes.
        """
    @property
    def special_registers(self, /) -> Diagnostic[SpecialRegistersArea]: ...

@final
class PteWalk(BaseRecord):
    """
    A full page-table walk (`!pte`), with the levels that the walk reached
    from the top down. A large-page mapping stops the walk early, so it has
    fewer levels.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int:
        """
        The address space walked.
        """
    @property
    def levels(self, /) -> list[PageTableEntry]: ...

@final
class QueuedLock(BaseRecord):
    """
    A numbered queued spinlock and the processors that own it or wait for it.
    """
    @property
    def holders(self, /) -> list[QueuedLockHolder]: ...
    @property
    def lock(self, /) -> int |None:
        """
        The spinlock, from the first processor entry that identifies it.
        """
    @property
    def name(self, /) -> str:
        """
        The name of the queue number without the `LockQueue` prefix and the
        `Lock` suffix (`IoCancel`). `LockQueue[n]` if the name is not known.
        """
    @property
    def number(self, /) -> int:
        """
        The `_KSPIN_LOCK_QUEUE_NUMBER` of the lock.
        """

@final
class QueuedLockHolder(BaseRecord):
    """
    The entry of a processor in a queued spinlock that it owns or waits for.
    """
    @property
    def processor(self, /) -> int: ...
    @property
    def reason(self, /) -> str |None:
        """
        How a corrupt entry does not agree with the queue links. `None` for
        other entries.
        """
    @property
    def state(self, /) -> str:
        """
        `owner`, `waiting`, or `corrupt`. `corrupt` means that the bits of the
        entry do not agree with the queue links.
        """
    @property
    def wait_order(self, /) -> int |None:
        """
        The 1-based position in the wait queue after the owner. `None` if the
        processor does not wait.
        """

@final
class QueuedLocks(BaseRecord):
    """
    All numbered queued spinlocks on all processors (`!qlocks`).
    """
    @property
    def errors(self, /) -> list[ProcessorError]: ...
    @property
    def locks(self, /) -> list[QueuedLock]: ...
    @property
    def processors(self, /) -> list[int]:
        """
        The processors whose `_KPRCB.LockQueue` ntoseye read.
        """

@final
class ReadyQueue(BaseRecord):
    """
    The ready list of one processor for one priority.
    """
    @property
    def entries(self, /) -> list[ReadyThread]: ...
    @property
    def priority(self, /) -> int: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def termination(self, /) -> ListEnd:
        """
        How the list walk ended.
        """

@final
class ReadyQueues(BaseRecord):
    """
    The dispatcher ready queues (`!ready`).
    """
    @property
    def errors(self, /) -> list[SchedulerError]: ...
    @property
    def queues(self, /) -> list[ReadyQueue]:
        """
        The queues that are not empty.
        """
    @property
    def total(self, /) -> int:
        """
        The total number of threads in `queues`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry limit.
        """

@final
class ReadyThread(BaseRecord):
    """
    A thread on a dispatcher ready queue.
    """
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` linked on the queue.
        """
    @property
    def thread(self, /) -> Diagnostic[ThreadSummary]:
        """
        The decoded thread.
        """

@final
class Record(BaseRecord):
    """
    An immutable, ordered set of named fields with attribute access.
    """
    def __getattr__(self, name: str, /) -> Any: ...

@final
class Regions:
    """
    The VAD regions of a process (`!vad`).
    """
    def __contains__(self, addr: int, /) -> bool: ...
    def __getitem__(self, addr: int, /) -> MemoryRegion: ...
    def __iter__(self, /) -> MemoryRegionIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> MemoryRegion |None:
        """
        Find the VAD region that contains `addr`, or return `None`.
        """

@final
class RegisterValue(BaseRecord):
    """
    One register of the current context (`r`).
    """
    @property
    def name(self, /) -> str: ...
    @property
    def value(self, /) -> int |str:
        """
        An int, or a `0x`-prefixed 32-digit hex string for a vector
        register.
        """

@final
class Registers:
    """
    A register file that is bound to a vCPU or to a recovered frame context.
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getattr__(self, name: str, /) -> int: ...
    def __getitem__(self, name: str, /) -> int: ...
    def __iter__(self, /) -> NameIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None: ...
    def __setitem__(self, name: str, value: int, /) -> None: ...
    def get(self, /, name: str, default: int |None = None) -> int |None:
        """
        The value of register `name`, or `default` when this file has no such
        register (a recovered frame holds only what unwinding recovered).
        """
    def items(self, /) -> list[tuple[str, int]]:
        """
        `(name, value)` pairs, sorted by name.
        """
    def keys(self, /) -> list[str]:
        """
        The register names, sorted.
        """
    def to_dict(self, /) -> dict[str, int]:
        """
        The registers as a plain `dict`, sorted by name.
        """

@final
class ResourceList(BaseRecord):
    """
    The executive-resource list of the kernel (`!locks`).
    """
    @property
    def head(self, /) -> int:
        """
        `nt!ExpSystemResourcesList`.
        """
    @property
    def resources(self, /) -> list[ExecutiveResource]: ...
    @property
    def termination(self, /) -> ListEnd: ...

@final
class ResourceOwner(BaseRecord):
    """
    A thread that owns an executive resource.
    """
    @property
    def count(self, /) -> int:
        """
        The number of times that the thread acquired the resource.
        """
    @property
    def thread(self, /) -> int: ...

@final
class ReverseTranslation(BaseRecord):
    """
    The virtual addresses that map a physical address (`!ptov`).
    """
    @property
    def bounded(self, /) -> bool:
        """
        Whether the walk stopped at its limit before the end.
        """
    @property
    def dtb(self, /) -> int: ...
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt request stopped the walk.
        """
    @property
    def mappings(self, /) -> list[PhysicalMapping]: ...
    @property
    def physical(self, /) -> int: ...
    @property
    def table_pages(self, /) -> int:
        """
        The number of page-table pages that the walk read.
        """

@final
class RunStatus(BaseRecord):
    """
    Whether the target runs, and where it stopped.
    """
    @property
    def attached_process(self, /) -> ProcessIdentity |None:
        """
        The process that you selected with `.process`. `dt`, `dq`, and
        similar commands read its memory, and the selection stays after the
        target resumes.
        """
    @property
    def coherent(self, /) -> bool:
        """
        False after a reboot until the kernel's loaded-module list exists,
        and process and module enumeration is not valid until then.
        """
    @property
    def current_thread(self, /) -> str:
        """
        The selected backend thread/vCPU.
        """
    @property
    def kernel_base(self, /) -> int:
        """
        The `nt` base that ntoseye found again. It changes across a reboot.
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer when halted. None while the target runs.
        """
    @property
    def running(self, /) -> bool: ...
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        For a vCPU halted in the Windows hypervisor, the VTL states that the
        hypervisor saved for the vCPU's virtual processor, VTL0 first.
        """
    @property
    def serving(self, /) -> ServedVp |None:
        """
        For a vCPU halted in the Windows hypervisor, the guest partition's
        virtual processor it serves, as `VcpuStatus.serving`.
        """
    @property
    def stopped_process(self, /) -> ProcessIdentity |None:
        """
        The process whose page tables the stopped vCPU has loaded.
        """
    @property
    def stopped_thread(self, /) -> ThreadSummary |None:
        """
        The Windows thread that the stopped vCPU runs. Its owner can be
        different from `stopped_process` (`KeStackAttachProcess`).
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to `rip` when halted. For code outside NT, the
        name identifies that code (`hv+0x3a6bde`).
        """

@final
class RunningProcessor(BaseRecord):
    """
    A processor's running, next, and idle threads (`!running`).
    """
    @property
    def current_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The thread that runs on the processor. The value inside is `None` if
        no thread runs.
        """
    @property
    def idle_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The processor's idle thread.
        """
    @property
    def index(self, /) -> int:
        """
        The processor number.
        """
    @property
    def kpcr(self, /) -> Diagnostic[int]: ...
    @property
    def next_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The thread selected to run next. The value inside is `None` if there
        is no next thread.
        """
    @property
    def prcb(self, /) -> Diagnostic[int]: ...
    @property
    def short_stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The first frames of the running thread. `None` if stacks were not
        requested.
        """

@final
class RunningProcessors(BaseRecord):
    """
    The running threads of all processors (`!running`).
    """
    @property
    def processors(self, /) -> list[RunningProcessor]: ...

@final
class RuntimeFunction(BaseRecord):
    """
    One function-table entry and its unwind data. Addresses are absolute,
    and the `*_rva` fields hold the raw image-relative values.
    """
    @property
    def begin(self, /) -> int: ...
    @property
    def begin_rva(self, /) -> int: ...
    @property
    def end(self, /) -> int: ...
    @property
    def end_rva(self, /) -> int: ...
    @property
    def symbol(self, /) -> str:
        """
        The symbol at `begin`.
        """
    @property
    def unwind(self, /) -> Amd64UnwindInfo |Arm64PackedUnwind |Arm64XdataUnwind |None:
        """
        The decoded unwind data. None if ntoseye cannot read it.
        """
    @property
    def unwind_data(self, /) -> int:
        """
        The raw unwind word of the entry: the RVA of the unwind info, or
        the packed unwind data on ARM64.
        """
    @property
    def unwind_info(self, /) -> int |None:
        """
        The address of the unwind info. None for ARM64 packed unwind data.
        """

@final
class SavedVtlState(BaseRecord):
    """
    One VTL of a virtual processor, as the Windows hypervisor last saved it
    in the VTL's Enlightened VMCS. A VMCS holds no general-purpose register
    other than `rsp`; `general_registers` has the others when they are known.
    """
    @property
    def cr0(self, /) -> int: ...
    @property
    def cr3(self, /) -> int:
        """
        The page-table root of the VTL.
        """
    @property
    def cr4(self, /) -> int: ...
    @property
    def cs(self, /) -> int: ...
    @property
    def current(self, /) -> bool:
        """
        Whether the VP assist page names this state's eVMCS as current. The
        current VTL is the one that entered the hypervisor or that the
        hypervisor is about to enter.
        """
    @property
    def dr7(self, /) -> int: ...
    @property
    def ds(self, /) -> int: ...
    @property
    def es(self, /) -> int: ...
    @property
    def evmcs(self, /) -> int:
        """
        The physical address of the eVMCS page that ntoseye read the state
        from.
        """
    @property
    def exit_instruction_length(self, /) -> int:
        """
        The length of the instruction that caused the exit, for exits that
        an instruction caused.
        """
    @property
    def exit_interruption_info(self, /) -> int:
        """
        The vector and type of the event behind an exception or interrupt
        exit (Intel SDM, VM-exit interruption information).
        """
    @property
    def exit_qualification(self, /) -> int:
        """
        Reason-specific detail of the last exit, such as the access that
        caused an EPT violation (Intel SDM, exit qualification).
        """
    @property
    def exit_reason(self, /) -> int:
        """
        The VM-exit reason of the last exit from the VTL. Bits 15:0 hold the
        basic reason, and bit 31 is set for a failed VM entry.
        """
    @property
    def exit_reason_name(self, /) -> str |None:
        """
        The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
        common reason.
        """
    @property
    def fs(self, /) -> int: ...
    @property
    def fs_base(self, /) -> int: ...
    @property
    def general_registers(self, /) -> Record |None:
        """
        The guest's general-purpose registers other than `rsp` at the last
        exit (`rax` to `r15`), read where the hypervisor's VM-exit entry
        code saved them. Experimental: where that is, is read off the
        entry code. None when they are not known: for a VTL that is not
        the current one, while the vCPU is on `host_rip` (unless it stopped
        there on a breakpoint, when they are the vCPU's own) or still saving
        them, or when the entry code does not save them in one block.
        """
    @property
    def gs(self, /) -> int: ...
    @property
    def gs_base(self, /) -> int: ...
    @property
    def host_rip(self, /) -> int:
        """
        The hypervisor's VM-exit entry point.
        """
    @property
    def host_rsp(self, /) -> int:
        """
        The stack the hypervisor's VM-exit entry point runs on.
        """
    @property
    def hypercall(self, /) -> DecodedHypercall |None:
        """
        The hypercall of a VMCALL exit whose general-purpose registers are
        known, with its input decoded.
        """
    @property
    def may_be_stale(self, /) -> bool:
        """
        The vCPU is stopped on `host_rip`, and not by a breakpoint there.
        KVM writes the eVMCS when it enters the hypervisor, and a stop from
        outside can fall between a VM exit and that entry, so this state
        may still describe the exit before the one in progress. The
        guest's general-purpose registers are then still in the vCPU's own
        registers. A breakpoint on `host_rip` fires after the write.
        Only the current state, the exiting VTL's, can be behind; when no
        state of the VP is current, every state is marked.
        """
    @property
    def rflags(self, /) -> int: ...
    @property
    def rip(self, /) -> int: ...
    @property
    def rsp(self, /) -> int: ...
    @property
    def ss(self, /) -> int: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `rip` in the VTL's address space, if one resolves.
        """
    @property
    def vtl(self, /) -> int:
        """
        0 or 1.
        """

@final
class SchedulerError(BaseRecord):
    """
    A processor or queue read that failed during a scheduler walk.
    """
    @property
    def message(self, /) -> str: ...
    @property
    def processor(self, /) -> int |None:
        """
        The processor of the error, if there is one.
        """
    @property
    def queue(self, /) -> int |None:
        """
        The queue of the error, if there is one.
        """

@final
class Section(BaseRecord):
    """
    One PE section with its name, RVA, mapped size, and `rwx` permissions.
    """
    @property
    def name(self, /) -> str:
        """
        The section name (`.text`).
        """
    @property
    def permissions(self, /) -> str:
        """
        The mapped permissions as `rwx`, with `-` for a missing permission.
        """
    @property
    def rva(self, /) -> int:
        """
        The offset of the section from the image base.
        """
    @property
    def size(self, /) -> int:
        """
        The mapped size of the section.
        """

@final
class SecureKernel:
    """
    The secure kernel (`securekernel.exe`) that runs in VTL1. Its views use its
    system address space and are read-only, so writes raise `NtoseyeError`.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        The base address of `securekernel.exe`.
        """
    @property
    def dtb(self, /) -> int:
        """
        The secure kernel's system page-table root.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in the symbol scope of the secure kernel.
        Registers hold VTL0 state, and this method does not accept them.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory, read through the system page tables of the secure
        kernel.
        """
    @property
    def modules(self, /) -> Modules:
        """
        The modules that the secure kernel loaded (`securekernel.exe`,
        `skci.dll`, ...).
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        The symbols of the secure kernel's modules (`securekernel!...`). NT
        symbols do not resolve here.
        """
    @property
    def trustlets(self, /) -> list[Trustlet]:
        """
        The processes (trustlets) of the secure kernel. Each access walks the
        list again and validates it against the NT process list. Raises
        `NtoseyeError` if ntoseye does not recognize the process layout of this
        build.
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types, read through VTL1 memory. The public secure-kernel PDB has no
        types, so give NT types with their module name (`nt!_LIST_ENTRY`).
        """

@final
class SecurityDescriptor(BaseRecord):
    """
    A decoded absolute or self-relative security descriptor (`!sd`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def control(self, /) -> Diagnostic[int]:
        """
        `SECURITY_DESCRIPTOR.Control`.
        """
    @property
    def control_names(self, /) -> Diagnostic[str]:
        """
        The names of the control bits that are set.
        """
    @property
    def dacl(self, /) -> Diagnostic[Acl |None]:
        """
        Its value is `None` if the DACL is absent or is a null (unrestricted) ACL.
        """
    @property
    def group(self, /) -> Diagnostic[Sid |None]:
        """
        The group SID. Its value is `None` for a null group.
        """
    @property
    def owner(self, /) -> Diagnostic[Sid |None]:
        """
        The owner SID. Its value is `None` for a null owner.
        """
    @property
    def revision(self, /) -> Diagnostic[int]: ...
    @property
    def sacl(self, /) -> Diagnostic[Acl |None]:
        """
        Its value is `None` if the SACL is absent or is a null ACL.
        """
    @property
    def self_relative(self, /) -> Diagnostic[bool]:
        """
        Whether `control` has `SE_SELF_RELATIVE`.
        """
    @property
    def unsupported_revision(self, /) -> bool:
        """
        Whether the revision is not 1.
        """

@final
class SegmentHeap(BaseRecord):
    """
    A segment heap (`_SEGMENT_HEAP`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def committed_pages(self, /) -> int: ...
    @property
    def contexts(self, /) -> list[SegmentHeapContext]:
        """
        The segment contexts (`SegContexts`), one for each page-segment size
        class.
        """
    @property
    def encoding_keys(self, /) -> SegmentHeapKeys:
        """
        The `ntdll!RtlpHpHeapGlobals` keys that encode chunk headers.
        """
    @property
    def free_committed_pages(self, /) -> int: ...
    @property
    def global_flags(self, /) -> int:
        """
        `_SEGMENT_HEAP.GlobalFlags`.
        """
    @property
    def granule(self, /) -> int:
        """
        The size in bytes of the `_HEAP_VS_CHUNK_HEADER` that starts each VS
        chunk: 16 on x64, 8 on x86.
        """
    @property
    def large_allocations(self, /) -> list[HeapLargeAllocation]: ...
    @property
    def large_committed_pages(self, /) -> int: ...
    @property
    def large_reserved_pages(self, /) -> int: ...
    @property
    def lfh_free_committed_pages(self, /) -> int: ...
    @property
    def reserved_pages(self, /) -> int: ...
    @property
    def vs_free_committed_pages(self, /) -> int: ...

@final
class SegmentHeapContext(BaseRecord):
    """
    A segment context (`_HEAP_SEG_CONTEXT`) of a segment heap.
    """
    @property
    def index(self, /) -> int:
        """
        Position in `SegContexts`.
        """
    @property
    def max_allocation_size(self, /) -> int:
        """
        The maximum allocation size for this context, in bytes.
        """
    @property
    def segment_mask(self, /) -> int: ...
    @property
    def segment_size(self, /) -> int:
        """
        Bytes per page segment.
        """
    @property
    def segments(self, /) -> list[SegmentHeapPageSegment]: ...
    @property
    def unit_shift(self, /) -> int:
        """
        log2 of `unit_size`.
        """
    @property
    def unit_size(self, /) -> int:
        """
        Bytes per page-range unit.
        """

@final
class SegmentHeapKeys(BaseRecord):
    """
    `ntdll!RtlpHpHeapGlobals`: the encoding keys of a segment heap.
    """
    @property
    def heap(self, /) -> int:
        """
        The VS chunk header key (`HeapKey`).
        """
    @property
    def lfh(self, /) -> int:
        """
        The LFH block-offsets key (`LfhKey`).
        """

@final
class SegmentHeapPageSegment(BaseRecord):
    """
    A page segment (`_HEAP_PAGE_SEGMENT`) of a segment context.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def ranges(self, /) -> list[HeapPageRange]: ...

@final
class ServedVp(BaseRecord):
    """
    The guest partition's virtual processor that a processor in the
    Windows hypervisor runs or last ran: the VP whose exit it handles, or
    which it is about to enter.
    """
    @property
    def current(self, /) -> bool:
        """
        Whether the processor's VP assist page names this VTL's eVMCS: the
        processor handles this VP's exit, or is about to enter it.
        """
    @property
    def exit_reason(self, /) -> int |None:
        """
        The VM-exit reason of the VTL's last exit.
        """
    @property
    def exit_reason_name(self, /) -> str |None:
        """
        The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
        common reason.
        """
    @property
    def general_registers(self, /) -> Record |None:
        """
        The guest's general-purpose registers other than `rsp` at the last
        exit, as `SavedVtlState.general_registers`. None when they are not
        known.
        """
    @property
    def hypercall(self, /) -> DecodedHypercall |None:
        """
        The hypercall of a VMCALL exit whose registers are known.
        """
    @property
    def partition_id(self, /) -> int: ...
    @property
    def rip(self, /) -> int |None:
        """
        Where the VTL left off, when the partition walk read its state.
        """
    @property
    def vp_index(self, /) -> int: ...
    @property
    def vtl(self, /) -> int:
        """
        The VTL the VP runs in.
        """

@final
class Session(BaseRecord):
    """
    A session and its processes.
    """
    @property
    def id(self, /) -> int |None:
        """
        `None` for processes whose session is unknown.
        """
    @property
    def processes(self, /) -> list[ProcessIdentity]:
        """
        The processes in the session.
        """

@final
class SessionProcess(BaseRecord):
    """
    A process and its session ID.
    """
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The process record.
        """
    @property
    def session(self, /) -> int |None:
        """
        `None` if ntoseye cannot get the ID from `_EPROCESS` or from the primary
        token.
        """

@final
class SessionProcesses(BaseRecord):
    """
    The processes of a session, with an optional image glob filter
    (`!sprocess`).
    """
    @property
    def detailed(self, /) -> bool:
        """
        Whether a non-zero flags argument requested the detailed list.
        """
    @property
    def image_glob(self, /) -> str |None: ...
    @property
    def process_count(self, /) -> int: ...
    @property
    def processes(self, /) -> list[SessionProcess]: ...
    @property
    def selected_session(self, /) -> int |None:
        """
        `None` for all sessions.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the process walk stopped at its limit.
        """

@final
class Sessions(BaseRecord):
    """
    Sessions and their processes (`!session`).
    """
    @property
    def process_count(self, /) -> int: ...
    @property
    def selected_session(self, /) -> int |None:
        """
        The requested session. `None` if you requested all sessions, or if the
        selected process has no known ID.
        """
    @property
    def sessions(self, /) -> list[Session]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the process walk stopped at its limit.
        """

@final
class Sid(BaseRecord):
    """
    A decoded SID (`!sid`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def authority(self, /) -> int:
        """
        The identifier authority.
        """
    @property
    def revision(self, /) -> int: ...
    @property
    def sid(self, /) -> str:
        """
        The canonical string form (`S-1-5-18`).
        """
    @property
    def sub_authorities(self, /) -> list[int]: ...
    @property
    def well_known(self, /) -> str |None:
        """
        The built-in name, if the SID is a well-known SID.
        """

@final
class SidAndAttributes(BaseRecord):
    """
    A token SID and its `SE_GROUP_*` attributes.
    """
    @property
    def attributes(self, /) -> int: ...
    @property
    def sid(self, /) -> str: ...

@final
class SourceLocation(BaseRecord):
    """
    PDB source metadata for an address.
    """
    @property
    def column(self, /) -> int |None:
        """
        `None` if the PDB records no column.
        """
    @property
    def file(self, /) -> str:
        """
        The source file as the PDB records it.
        """
    @property
    def line(self, /) -> int: ...
    @property
    def local_path(self, /) -> str |None:
        """
        The local file that the source path maps it to. `None` if no mapping
        applies.
        """
    @property
    def local_state(self, /) -> str |None:
        """
        `found`, `missing`, or `differs`. `found` means that the file is
        there and, if the PDB records a checksum, that it is the compiled
        file. `differs` means that the file is there but its checksum does
        not match the compiled file. `None` if `local_path` is `None`.
        """

@final
class SpecialRegistersArea(BaseRecord):
    """
    The location of `_KSPECIAL_REGISTERS` in a processor state.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        The type name.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the structure in bytes.
        """

@final
class SsdtEntry(BaseRecord):
    """
    A slot in a system-service table.
    """
    @property
    def index(self, /) -> int:
        """
        The system-service number.
        """
    @property
    def module(self, /) -> str |None:
        """
        The module that contains the routine. None if no module contains it.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol of the routine. None if no symbol resolves.
        """
    @property
    def target(self, /) -> int:
        """
        The routine that the slot resolves to.
        """

@final
class SsdtTable(BaseRecord):
    """
    A system-service table, either the kernel SSDT or the win32k shadow (`ssdt`).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def entries(self, /) -> list[SsdtEntry]: ...
    @property
    def label(self, /) -> str:
        """
        The label of the table.
        """
    @property
    def limit(self, /) -> int:
        """
        The number of services.
        """

@final
class StackFrame(BaseRecord):
    """
    One frame of a stack walk.
    """
    @property
    def index(self, /) -> int:
        """
        The position of the frame in the stack walk. The innermost frame is 0.
        """
    @property
    def inline(self, /) -> bool:
        """
        True for a call that the compiler inlined into the physical frame
        after it, so the call has no stack frame of its own. `symbol` is the
        inlined function, and `ip` and `sp` are those of the physical frame.
        """
    @property
    def ip(self, /) -> int:
        """
        The instruction pointer.
        """
    @property
    def source(self, /) -> str:
        """
        How ntoseye recovered the frame: `current`, `seed`, `unwind`,
        `prolog` (read off its function's prolog, for the Windows
        hypervisor's code without its file), or `scan`.
        """
    @property
    def source_location(self, /) -> SourceLocation |None:
        """
        The source line of the frame, if line information resolves it. For
        an inline frame this is the line in the inlined function, and for a
        caller it is the line of the call.
        """
    @property
    def sp(self, /) -> int:
        """
        The stack pointer.
        """
    @property
    def symbol(self, /) -> str:
        """
        The symbol at `ip`. Empty if no symbol resolves.
        """

class Stop:
    """
    The reason why the target stopped. Each stop is one of the nested kinds,
    which you can test with `isinstance(stop, Stop.Breakpoint)` or `match`. A
    stop is bound to the target generation in which it occurred.
    """
    def __repr__(self, /) -> str: ...
    @property
    def breakpoints(self, /) -> list[Breakpoint]:
        """
        The breakpoint or watchpoint handles for this stop. The list is empty
        for other kinds of stop, so `bp in stop.breakpoints` works on all stops.
        """
    @property
    def cpu(self, /) -> Cpu:
        """
        The processor that stopped.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process whose page tables were active at this stop, if known.
        """
    def record(self, /) -> ExceptionRecord:
        """
        Decode the current exception record (`.exr -1`).
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer that ntoseye recorded at this stop.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol that ntoseye recorded at this stop, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread that runs on the stopped vCPU, if known.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @final
    class Breakpoint(Stop):
        """
        A code breakpoint or data-watchpoint hit. If the breakpoint condition
        fails to evaluate, ntoseye sets `condition_error` and stops on the hit
        instead of skipping it.
        """
        __match_args__: Final = ("condition_error", "_context")
        def __new__(cls, /, condition_error: str |None, _context: _StopContext) -> Stop.Breakpoint: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def condition_error(self, /) -> str |None:
            """
            The reason why the breakpoint condition failed to evaluate, if it failed.
            """
    @final
    class Bugcheck(Stop):
        """
        The guest is in a bugcheck (BSOD). `info` is the bugcheck analysis.
        """
        __match_args__: Final = ("info", "_context")
        def __new__(cls, /, info: Bugcheck |None, _context: _StopContext) -> Stop.Bugcheck: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def info(self, /) -> Bugcheck |None:
            """
            The bugcheck analysis: the code, the parameters, and the culprit from
            `!analyze`.
            """
    @final
    class Exception(Stop):
        """
        A Windows exception, with its `code` (NTSTATUS), the first-chance flag,
        and the faulting address.
        """
        __match_args__: Final = ("code", "first_chance", "address", "_context")
        def __new__(cls, /, code: int, first_chance: bool |None, address: int |None, _context: _StopContext) -> Stop.Exception: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def address(self, /) -> int |None:
            """
            The faulting address, if the exception has one.
            """
        @property
        def code(self, /) -> int:
            """
            The NTSTATUS code of the exception.
            """
        @property
        def first_chance(self, /) -> bool |None:
            """
            True if this is the first chance, or `None` if the backend does not
            give this data.
            """
    @final
    class Interrupt(Stop):
        """
        A break-in (`interrupt()`), or a different stop that has no exception code.
        """
        __match_args__: Final = ("_context",)
        def __new__(cls, /, _context: _StopContext) -> Stop.Interrupt: ...
        @property
        def _context(self, /) -> _StopContext: ...
    @final
    class ModuleLoad(Stop):
        """
        A kernel image loaded, and an `"ld"` filter set to `"break"` matched it
        (`dbg.exceptions.set("ld:<module>", "break")`, `sxe ld`). The module is
        in the module list with its symbols loaded and its breakpoints set, and
        its entry point has not run.
        """
        __match_args__: Final = ("module", "_context")
        def __new__(cls, /, module: Module, _context: _StopContext) -> Stop.ModuleLoad: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def module(self, /) -> Module:
            """
            The loaded kernel module.
            """
    @final
    class ModuleUnload(Stop):
        """
        A kernel image is unloading, and a `"ud"` filter set to `"break"`
        matched it (`dbg.exceptions.set("ud:<module>", "break")`, `sxe ud`).
        The driver's unload routine has run, and the module is still in the
        module list with its symbols.
        """
        __match_args__: Final = ("module", "_context")
        def __new__(cls, /, module: Module, _context: _StopContext) -> Stop.ModuleUnload: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def module(self, /) -> Module:
            """
            The unloading kernel module.
            """
    @final
    class Reboot(Stop):
        """
        The guest rebooted, so all earlier handles are now stale. While
        `coherent` is false, the kernel module list does not exist yet, but
        kernel symbols and breakpoints work and `run()` lets the boot continue.
        """
        __match_args__: Final = ("kernel_base", "coherent", "_context")
        def __new__(cls, /, kernel_base: int |None, coherent: bool, _context: _StopContext) -> Stop.Reboot: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def coherent(self, /) -> bool:
            """
            True if the kernel module list exists.
            """
        @property
        def kernel_base(self, /) -> int |None:
            """
            The base address of the new kernel (KASLR moves it).
            """
    @final
    class Step(Stop):
        """
        A completed step.
        """
        __match_args__: Final = ("_context",)
        def __new__(cls, /, _context: _StopContext) -> Stop.Step: ...
        @property
        def _context(self, /) -> _StopContext: ...

@final
class Struct:
    """
    A reflective cursor: a PDB type bound to an address in an address space.
    """
    def __dir__(self, /) -> list[str]:
        """
        The PDB fields and the public members of the cursor, for tab completion.
        """
    def __eq__(self, other: object, /) -> bool: ...
    def __getattr__(self, name: str, /) -> Any:
        """
        Reflective field access. A missing field raises `AttributeError`.
        """
    def __getitem__(self, key: str |int, /) -> Any:
        """
        The field value, or a sibling cursor for an integer index
        (`((T*)p)[i]`).
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None:
        """
        `cursor.Field = value`, which accepts only real PDB fields.
        """
    def __setitem__(self, name: str, value: Any, /) -> None:
        """
        Write a PDB field by name.
        """
    @property
    def addr(self, /) -> int:
        """
        The address of this cursor.
        """
    def address_of(self, /, name: str) -> int:
        """
        The address of field `name`, as `&cursor->name` in C, which a watchpoint
        or a raw read needs. For a bitfield, this is the address of its storage
        unit.
        """
    def cast(self, /, type_name: str) -> Struct:
        """
        Use this address as a different PDB type.
        """
    def follow(self, /, name: str) -> Struct:
        """
        Follow a pointer field to its typed target.
        """
    def read(self, /) -> dict[str, Any]:
        """
        Read a snapshot of the full struct into a dictionary, without nested
        struct fields.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def type(self, /) -> Type:
        """
        The PDB type of this cursor.
        """
    def walk(self, /, head_field: str, record_type: str, link_field: str) -> list[Struct]:
        """
        Walk a list whose head is a field of this cursor.
        """

@final
class Subsection(BaseRecord):
    """
    A `_SUBSECTION` after a control area.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def base_pte(self, /) -> int:
        """
        Its first prototype PTE.
        """
    @property
    def protection(self, /) -> int:
        """
        The MM protection in `SubsectionFlags`.
        """
    @property
    def ptes(self, /) -> int: ...
    @property
    def sectors(self, /) -> int: ...
    @property
    def starting_sector(self, /) -> int: ...
    @property
    def unused_ptes(self, /) -> int: ...

@final
class Symbol(BaseRecord):
    """
    The symbol nearest below an address (`ln`, `Symbols.nearest()`).
    """
    def __str__(self, /) -> str:
        """
        `module!name+0xoffset`.
        """
    @property
    def address(self, /) -> int:
        """
        The address of the symbol.
        """
    @property
    def module(self, /) -> str:
        """
        The module that contains the symbol.
        """
    @property
    def name(self, /) -> str:
        """
        The symbol name.
        """
    @property
    def offset(self, /) -> int:
        """
        The distance in bytes from the symbol to the queried address.
        """

@final
class SymbolCandidate(BaseRecord):
    """
    One definition that a symbol name resolves to.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def compiland(self, /) -> str |None:
        """
        The compiland that defines a private symbol.
        """
    @property
    def module(self, /) -> str: ...
    @property
    def visibility(self, /) -> str:
        """
        `public` or `private`.
        """

@final
class SymbolLoadDiagnostic(BaseRecord):
    """
    One problem that ntoseye found when it loaded the symbols of a module.
    """
    @property
    def compiland(self, /) -> str |None:
        """
        The compiland of the problem, if the problem is specific to one compiland.
        """
    @property
    def message(self, /) -> str: ...
    @property
    def module(self, /) -> str: ...
    @property
    def phase(self, /) -> str:
        """
        The load step that reported it.
        """

@final
class SymbolReloadReport(BaseRecord):
    """
    The result of a symbol reload. It counts the modules that loaded, had
    no PDB, were skipped, or failed, and keeps the first diagnostics up to
    a limit.
    """
    @property
    def diagnostic_count(self, /) -> int:
        """
        The number of all diagnostics, including those after the limit of `diagnostics`.
        """
    @property
    def diagnostics(self, /) -> list[SymbolLoadDiagnostic]: ...
    @property
    def failed(self, /) -> int: ...
    @property
    def loaded(self, /) -> int: ...
    @property
    def no_pdb(self, /) -> int: ...
    @property
    def skipped(self, /) -> int: ...
    @property
    def total(self, /) -> int: ...
    @property
    def unloaded(self, /) -> int:
        """
        The number of modules with symbols that unloaded after the previous refresh.
        """

@final
class SymbolSearchMatch(BaseRecord):
    """
    A symbol that a name search matched.
    """
    @property
    def address(self, /) -> int |None:
        """
        `None` if the match does not resolve to a unique address.
        """
    @property
    def module(self, /) -> str |None: ...
    @property
    def name(self, /) -> str: ...

@final
class Symbols:
    """
    Symbol lookup in one address space (`dbg.symbols`, `proc.symbols`).
    """
    def __contains__(self, name: str, /) -> bool:
        """
        True if one or more symbol candidates have this name.
        """
    def __getitem__(self, name: str, /) -> int:
        """
        Get the address of a symbol, or raise `SymbolNotFoundError` if the symbol is not
        found.
        """
    def candidates(self, /, name: str) -> list[SymbolCandidate]:
        """
        Get all exact candidates, with the module and, for private symbols, the compiland.
        """
    def get(self, /, name: str) -> int |None:
        """
        Get the address of a symbol, or `None` if the symbol is not found.
        """
    def import_image(self, /, path: str) -> str:
        """
        Copy a PE file into the symbol cache under the key in its own header, and
        return its path in the cache (`.fetchimage /f`). Use it for an image that
        no symbol server has, such as the Windows hypervisor's `hvix64.exe`.
        """
    def locals_at(self, /, addr: int) -> list[ProcedureLocal]:
        """
        List the PDB layouts of the locals and parameters of the innermost frame
        at `addr`, which are those of the inlined call if the compiler inlined a
        call there. This method does not evaluate the values.
        """
    def nearest(self, /, addr: int) -> Symbol |None:
        """
        Get the nearest symbol, or `None` if no symbol covers `addr`.
        """
    @property
    def path(self, /) -> list[str]:
        """
        The ordered symbol sources (`.sympath`). An assignment replaces the full path.
        """
    @path.setter
    def path(self, /, sources: Sequence[str]) -> None: ...
    def reload(self, /) -> SymbolReloadReport:
        """
        Reload symbols in this space, and resolve symbolic breakpoints again.
        """
    def reset_path(self, /) -> None:
        """
        Restore the default symbol sources (`.symfix`).
        """
    def search(self, /, query: str, limit: int = 50) -> list[SymbolSearchMatch]:
        """
        Search symbol names by fuzzy match. Use `module!query` to search in one module.
        """
    def source_addresses(self, /, file: str, line: int) -> list[int]:
        """
        Get all loaded addresses that match a source file and line.
        """
    def source_location(self, /, addr: int) -> SourceLocation |None:
        """
        Get the PDB source metadata and the mapped local path for an address.
        """
    @property
    def source_path(self, /) -> list[str]:
        """
        The ordered source-path mappings (`.srcpath`). An assignment replaces all of them.
        """
    @source_path.setter
    def source_path(self, /, paths: Sequence[str]) -> None: ...

@final
class SystemMemoryUsage(BaseRecord):
    """
    System memory counters and per-process usage (`!memusage`).
    """
    @property
    def available_pages(self, /) -> Diagnostic[int]: ...
    @property
    def commit_limit_pages(self, /) -> Diagnostic[int]: ...
    @property
    def committed_pages(self, /) -> Diagnostic[int]: ...
    @property
    def nonpaged_pool_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def paged_pool_pages(self, /) -> Diagnostic[int]: ...
    @property
    def physical_pages(self, /) -> Diagnostic[int]: ...
    @property
    def process_count(self, /) -> int:
        """
        The number of processes, including those past the listing limit.
        """
    @property
    def processes(self, /) -> list[ProcessMemoryUsage]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether more processes exist than are listed.
        """

@final
class SystemPteRun(BaseRecord):
    """
    A run of free system PTEs, which is a sequence of clear bits in an
    allocation bitmap.
    """
    @property
    def pte(self, /) -> int:
        """
        The address of the first PTE in the run.
        """
    @property
    def ptes(self, /) -> int:
        """
        The length in PTEs.
        """
    @property
    def va(self, /) -> int |None:
        """
        The virtual address that this PTE maps, if `MmPteBase` is known.
        """

@final
class SystemPteType(BaseRecord):
    """
    One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are
    in PTEs.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def base_pte(self, /) -> int: ...
    @property
    def base_va(self, /) -> int |None:
        """
        The virtual address that `base_pte` maps. `None` without `MmPteBase`.
        """
    @property
    def bitmap(self, /) -> int: ...
    @property
    def bitmap_bits(self, /) -> int: ...
    @property
    def bitmap_free(self, /) -> int:
        """
        The free PTEs, counted from the clear bits of the bitmap.
        """
    @property
    def failures(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def free(self, /) -> int:
        """
        `TotalFreeSystemPtes`.
        """
    @property
    def free_run_count(self, /) -> int: ...
    @property
    def free_runs(self, /) -> list[SystemPteRun]:
        """
        The free runs in address order, if the list was requested.
        """
    @property
    def free_runs_truncated(self, /) -> bool: ...
    @property
    def largest_free_run(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        The `MiState` path of the allocator, e.g. `Vs.SystemPteInfo`.
        """
    @property
    def ptes_per_bit(self, /) -> int:
        """
        The number of PTEs that each bitmap bit covers.
        """
    @property
    def total(self, /) -> int:
        """
        `TotalSystemPtes`, the number of PTEs made available so far.
        """
    @property
    def tracking(self, /) -> bool:
        """
        Whether the kernel tracks which driver mapped each PTE (`TrackPtes`).
        """
    @property
    def unreadable_bitmap_bytes(self, /) -> int:
        """
        The bitmap bytes that could not be read, which count as allocated.
        """
    @property
    def unscanned_bitmap_bits(self, /) -> int:
        """
        The bits past the read limit for one bitmap, which no count
        includes.
        """
    @property
    def used(self, /) -> int:
        """
        `total` minus `free`.
        """
    @property
    def va_type(self, /) -> str |None:
        """
        The `_MI_SYSTEM_VA_TYPE` name, without the `MiVa` prefix.
        """

@final
class SystemPtes(BaseRecord):
    """
    Every system-PTE bitmap allocator in `MiState` (`!sysptes`). Counts
    are in PTEs.
    """
    @property
    def flags(self, /) -> int:
        """
        The requested flags.
        """
    @property
    def free(self, /) -> int: ...
    @property
    def total(self, /) -> int: ...
    @property
    def types(self, /) -> list[SystemPteType]: ...
    @property
    def used(self, /) -> int: ...

@final
class TargetDump(BaseRecord):
    """
    The data that a crash dump header records.
    """
    @property
    def bugcheck_code(self, /) -> int: ...
    @property
    def bugcheck_parameters(self, /) -> list[int]: ...
    @property
    def directory_table_base(self, /) -> int:
        """
        The kernel page-table root that the dump records.
        """
    @property
    def exception_code(self, /) -> int |None:
        """
        The exception code that the dump records.
        """
    @property
    def is_triage(self, /) -> bool:
        """
        Whether the dump is a triage (minidump-style) dump.
        """
    @property
    def kernel_base(self, /) -> int |None: ...
    @property
    def machine_image_type(self, /) -> int:
        """
        The machine type (`IMAGE_FILE_MACHINE_*`).
        """
    @property
    def major_version(self, /) -> int: ...
    @property
    def minor_version(self, /) -> int: ...
    @property
    def number_processors(self, /) -> int: ...
    @property
    def product_type(self, /) -> int: ...
    @property
    def service_pack_build(self, /) -> int: ...
    @property
    def system_time(self, /) -> int |None:
        """
        The time when the dump was taken (FILETIME).
        """
    @property
    def triage_overflowed(self, /) -> bool:
        """
        Whether the triage data of the dump overflowed.
        """
    @property
    def uptime_seconds(self, /) -> int |None:
        """
        The system uptime in seconds.
        """

@final
class TargetKernel(BaseRecord):
    """
    The identity of the kernel image.
    """
    @property
    def base(self, /) -> int: ...
    @property
    def file_version(self, /) -> str |None: ...
    @property
    def name(self, /) -> str:
        """
        The file name of the image.
        """
    @property
    def pdb_age(self, /) -> int |None:
        """
        The age of the PDB.
        """
    @property
    def pdb_guid(self, /) -> str |None:
        """
        The GUID of the PDB, which identifies the symbols.
        """
    @property
    def product_version(self, /) -> str |None: ...
    @property
    def short_name(self, /) -> str:
        """
        The module name (`nt`).
        """
    @property
    def size(self, /) -> int |None:
        """
        The image size in bytes.
        """

@final
class TargetTime(BaseRecord):
    """
    The UTC time and uptime of the target (`.time`).
    """
    @property
    def interrupt_time(self, /) -> int |None:
        """
        `KUSER_SHARED_DATA.InterruptTime`: the time since boot, in 100 ns
        units. The `due_time` of clock timers uses this clock.
        """
    @property
    def system_time(self, /) -> int |None:
        """
        The UTC time of the target (FILETIME).
        """
    @property
    def system_time_iso(self, /) -> str |None:
        """
        `system_time` as ISO 8601.
        """
    @property
    def uptime(self, /) -> str |None:
        """
        The uptime as formatted text.
        """
    @property
    def uptime_seconds(self, /) -> int |None:
        """
        Seconds since boot.
        """

@final
class TargetVersion(BaseRecord):
    """
    The version data of the target (`vertarget`), with the build,
    architecture, kernel, symbols, debugger version, time, and dump
    metadata.
    """
    @property
    def architecture(self, /) -> str: ...
    @property
    def backend(self, /) -> str |None:
        """
        The backend attached to the target.
        """
    @property
    def build_lab(self, /) -> str |None:
        """
        The build lab string.
        """
    @property
    def build_number(self, /) -> int |None: ...
    @property
    def debugger_version(self, /) -> str: ...
    @property
    def dump(self, /) -> TargetDump |None:
        """
        The crash dump header. `None` for a live target.
        """
    @property
    def kernel(self, /) -> TargetKernel |None:
        """
        The kernel image. `None` if ntoseye did not find it.
        """
    @property
    def major_version(self, /) -> int |None: ...
    @property
    def minor_version(self, /) -> int |None: ...
    @property
    def processors(self, /) -> int |None:
        """
        The number of processors in the target.
        """
    @property
    def product(self, /) -> str:
        """
        The product name.
        """
    @property
    def symbol_path(self, /) -> str: ...
    @property
    def symbol_status(self, /) -> str |None:
        """
        The symbol status label of the kernel. `None` if ntoseye did not
        find the kernel.
        """
    @property
    def time(self, /) -> TargetTime: ...

@final
class Teb(BaseRecord):
    """
    A thread's `_TEB` (`!teb`). ntoseye reads each field separately.
    """
    @property
    def activation_context(self, /) -> Diagnostic[int |None]:
        """
        The active activation context, or `None` if there is no active
        context.
        """
    @property
    def address(self, /) -> int: ...
    @property
    def client_id_unique_process(self, /) -> Diagnostic[int]: ...
    @property
    def client_id_unique_thread(self, /) -> Diagnostic[int]: ...
    @property
    def count_of_owned_critical_sections(self, /) -> Diagnostic[int]: ...
    @property
    def last_error_value(self, /) -> Diagnostic[int]:
        """
        The Win32 last error.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]:
        """
        The last NTSTATUS.
        """
    @property
    def peb(self, /) -> Diagnostic[int]:
        """
        The process's `_PEB`.
        """
    @property
    def stack_base(self, /) -> Diagnostic[int]: ...
    @property
    def stack_limit(self, /) -> Diagnostic[int]: ...
    @property
    def teb32(self, /) -> Teb32 |None:
        """
        The WOW64 `_TEB32`. `None` for a native thread.
        """
    @property
    def tls_pointer(self, /) -> Diagnostic[int]:
        """
        The thread-local storage array.
        """
    @property
    def wow64_reserved(self, /) -> Diagnostic[int]:
        """
        `WOW32Reserved`: the WOW64 transition thunk.
        """
    @property
    def wow_teb_offset(self, /) -> Diagnostic[int]:
        """
        `WowTebOffset`: the byte offset to the WOW64 `_TEB32`, or 0 if there
        is no `_TEB32`.
        """

@final
class Teb32(BaseRecord):
    """
    A WOW64 thread's 32-bit `_TEB32`. ntoseye reads each field separately.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def client_id_unique_process(self, /) -> Diagnostic[int]: ...
    @property
    def client_id_unique_thread(self, /) -> Diagnostic[int]: ...
    @property
    def count_of_owned_critical_sections(self, /) -> Diagnostic[int]: ...
    @property
    def last_error_value(self, /) -> Diagnostic[int]:
        """
        The Win32 last error.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]:
        """
        The last NTSTATUS.
        """
    @property
    def peb(self, /) -> Diagnostic[int]:
        """
        The process's `_PEB32`.
        """
    @property
    def stack_base(self, /) -> Diagnostic[int]: ...
    @property
    def stack_limit(self, /) -> Diagnostic[int]: ...
    @property
    def tls_pointer(self, /) -> Diagnostic[int]:
        """
        The thread-local storage array.
        """

@final
class Thread:
    """
    One Windows thread, identified in a debugger by its ETHREAD address.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> ApcQueues:
        """
        Decode the APC lists of this thread (`!apc`).
        """
    def backtrace(self, /, limit: int = 64) -> list[Frame]:
        """
        Recover the stack of this thread from live registers or its parked context.
        If the processor of the thread is halted in the Windows hypervisor, the
        unwind starts from the VTL0 state that the hypervisor saved, where NT stopped.
        """
    @property
    def cpu(self, /) -> Cpu |None:
        """
        The processor that runs the thread, or `None` if the thread is not running.
        """
    @property
    def ethread(self, /) -> int:
        """
        The `_ETHREAD` address, which identifies the thread.
        """
    def inspect(self, /) -> ThreadSummary:
        """
        Get the thread summary and the saved scheduling details (`!thread`).
        """
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` address.
        """
    def last_error(self, /) -> LastError:
        """
        Decode the Win32 last-error and NTSTATUS values of the thread (`!gle`).
        """
    @property
    def object(self, /) -> Struct:
        """
        The typed `_ETHREAD` object.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The ID of the process that owns the thread.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process that owns the thread.
        """
    @property
    def state(self, /) -> int |None:
        """
        The scheduler state, as a `_KTHREAD_STATE` member (`IntEnum`).
        """
    @property
    def teb(self, /) -> Struct |None:
        """
        The `_TEB`, bound to the process, or `None` for kernel threads.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread ID, or `None` if the thread has no ID (for example, an idle
        thread).
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The thread as a plain `dict`, in the shape that MCP shows.
        """
    def trap_frame(self, /) -> TrapFrame:
        """
        Decode the saved `_KTRAP_FRAME` (`!trap`).
        """
    @property
    def wait_reason(self, /) -> int |None:
        """
        The reason the thread waits, as a `_KWAIT_REASON` member (`IntEnum`).
        """

@final
class ThreadIterator:
    """
    Iterator over `dbg.threads` / `proc.threads`.
    """
    def __iter__(self, /) -> ThreadIterator: ...
    def __next__(self, /) -> Thread: ...

@final
class ThreadStack(BaseRecord):
    """
    The state and walked stack of a thread (`!stacks`).
    """
    @property
    def error(self, /) -> str |None:
        """
        The error, if the stack walk failed.
        """
    @property
    def frames(self, /) -> list[StackFrame]:
        """
        The frames, innermost first. Level 0 has the top frame, level 1 has
        up to 32 frames, and level 2 has up to 64 frames.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...
    @property
    def top_symbol(self, /) -> Diagnostic[str |None]:
        """
        The symbol of the top frame.
        """
    @property
    def truncated(self, /) -> int:
        """
        The number of frames past the walk limit, which are not listed.
        """

@final
class ThreadStacks(BaseRecord):
    """
    Threads with their states and stacks (`!stacks`).
    """
    @property
    def displayed_threads(self, /) -> int: ...
    @property
    def filter(self, /) -> str |None:
        """
        The symbol or module filter, if you gave one.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt stopped the walk before it finished.
        """
    @property
    def level(self, /) -> int:
        """
        The detail level (0, 1, or 2), which sets the frame limit of the
        walk.
        """
    @property
    def scanned_threads(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ThreadStack]: ...

@final
class ThreadSummary(BaseRecord):
    """
    A Windows thread, as `threads`, `!thread`, and all scheduler listings
    show it. A field that the walk could not read is `None`.
    """
    @property
    def active(self, /) -> str |None:
        """
        The vCPU that runs the thread, if the listing resolves it. `None` if
        no vCPU runs it, and while the target runs.
        """
    @property
    def eprocess(self, /) -> int |None:
        """
        The owning `_EPROCESS`.
        """
    @property
    def ethread(self, /) -> int: ...
    @property
    def kthread(self, /) -> int: ...
    @property
    def pid(self, /) -> int |None: ...
    @property
    def priority(self, /) -> int |None:
        """
        The current scheduling priority.
        """
    @property
    def process_name(self, /) -> str |None:
        """
        The image name of the owning process.
        """
    @property
    def state(self, /) -> int |None:
        """
        `_KTHREAD.State`.
        """
    @property
    def state_name(self, /) -> str |None:
        """
        The name of the state (`Running`, `Waiting`, ...).
        """
    @property
    def tid(self, /) -> int |None: ...
    @property
    def wait_reason(self, /) -> int |None:
        """
        `_KTHREAD.WaitReason`.
        """
    @property
    def wait_reason_name(self, /) -> str |None:
        """
        The name of the wait reason (`Executive`, `UserRequest`, ...).
        """

@final
class Threads:
    """
    A collection of threads: `dbg.threads` (all threads) or `proc.threads`.
    """
    def __contains__(self, tid: int, /) -> bool: ...
    def __getitem__(self, tid: int, /) -> Thread:
        """
        Get the thread with a TID, or raise `KeyError` if no thread has that
        TID.
        """
    def __iter__(self, /) -> ThreadIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def at(self, /, address: int) -> Thread:
        """
        Get the thread at an ETHREAD or KTHREAD address.
        """
    def get(self, /, tid: int) -> Thread |None:
        """
        Get the thread with a TID, or `None` if no thread has that TID.
        """

@final
class TimerBucketEnd(BaseRecord):
    """
    A timer-table bucket whose list walk did not end at its head.
    """
    @property
    def bucket(self, /) -> int: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def termination(self, /) -> ListEnd: ...

@final
class TimerTable(BaseRecord):
    """
    The timer tables of all processors (`!timer`).
    """
    @property
    def entries(self, /) -> list[TimerTableEntry]: ...
    @property
    def errors(self, /) -> list[SchedulerError]: ...
    @property
    def interrupt_time(self, /) -> Diagnostic[int]:
        """
        The interrupt time (`KUSER_SHARED_DATA.InterruptTime`) when ntoseye
        read the tables. The `due_time` of each entry uses this time scale.
        """
    @property
    def terminations(self, /) -> list[TimerBucketEnd]:
        """
        The buckets whose walk did not end normally.
        """
    @property
    def total(self, /) -> int:
        """
        The number of timers in `entries`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry limit.
        """

@final
class TimerTableEntry(BaseRecord):
    """
    A timer in the timer table of a processor.
    """
    @property
    def bucket(self, /) -> int:
        """
        The index of the timer-table bucket.
        """
    @property
    def processor(self, /) -> int: ...
    @property
    def timer(self, /) -> KernelTimer: ...

@final
class Token(BaseRecord):
    """
    The primary token of a process (`!token`).
    """
    @property
    def authentication_id(self, /) -> Diagnostic[int]:
        """
        The LUID of the logon session.
        """
    @property
    def flags(self, /) -> Diagnostic[int]:
        """
        `TokenFlags`.
        """
    @property
    def groups(self, /) -> Diagnostic[list[SidAndAttributes]]: ...
    @property
    def impersonation_level(self, /) -> Diagnostic[int]:
        """
        `SECURITY_IMPERSONATION_LEVEL`.
        """
    @property
    def privileges(self, /) -> Diagnostic[list[TokenPrivilege]]: ...
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The process record.
        """
    @property
    def token(self, /) -> int:
        """
        The `_TOKEN`.
        """
    @property
    def token_id(self, /) -> Diagnostic[int]: ...
    @property
    def token_type(self, /) -> Diagnostic[int]:
        """
        `TOKEN_TYPE`: 1 is primary, 2 is impersonation.
        """
    @property
    def user(self, /) -> Diagnostic[SidAndAttributes |None]:
        """
        Its value is `None` if the token does not name a user.
        """

@final
class TokenPrivilege(BaseRecord):
    """
    A token privilege and its `SE_PRIVILEGE_*` attributes.
    """
    @property
    def attributes(self, /) -> int: ...
    @property
    def luid(self, /) -> int: ...

@final
class TrapFrame(BaseRecord):
    """
    A decoded `_KTRAP_FRAME` (`.trap`).
    """
    @property
    def address(self, /) -> int:
        """
        The address that ntoseye read the frame from.
        """
    @property
    def frame(self, /) -> Amd64TrapFrame |Arm64TrapFrame:
        """
        The saved registers, by architecture.
        """
    @property
    def rip_symbol(self, /) -> str |None:
        """
        The symbol at the interrupted instruction.
        """

@final
class TriagePrcb(BaseRecord):
    """
    The main `_KPRCB` data of the crashed processor, as a triage dump
    recorded it.
    """
    @property
    def cpu_type(self, /) -> int: ...
    @property
    def current_thread(self, /) -> int:
        """
        The `_KTHREAD` running on the processor.
        """
    @property
    def mhz(self, /) -> int:
        """
        The processor's clock speed in MHz.
        """
    @property
    def processor_number(self, /) -> int: ...
    @property
    def vendor_string(self, /) -> str:
        """
        The CPU vendor (`GenuineIntel`, `AuthenticAMD`, ...).
        """

@final
class TriageReport(BaseRecord):
    """
    The one-shot crash triage report (`!analyze`), with the run status, the
    bugcheck or exception, the backtrace, the modules, the dump records,
    and the findings.
    """
    @property
    def backtrace(self, /) -> list[StackFrame] |None:
        """
        The stack of the current thread. `None` while the target runs or
        if the unwind failed (see `warnings`).
        """
    @property
    def blackboxes(self, /) -> list[BlackboxStream]: ...
    @property
    def broken_driver(self, /) -> str |None:
        """
        The driver that the dump records as broken.
        """
    @property
    def bugcheck(self, /) -> Bugcheck |None:
        """
        The bugcheck, if the target is in a bugcheck.
        """
    @property
    def crash_context(self, /) -> CrashContext |None:
        """
        The process and thread that crashed, as a triage dump recorded them.
        """
    @property
    def culprit(self, /) -> Culprit |None:
        """
        The module that the evidence identifies as the cause. `None` if
        the evidence does not identify a non-kernel module.
        """
    @property
    def exception(self, /) -> DumpException |None:
        """
        The exception that a dump recorded.
        """
    @property
    def failure_signature(self, /) -> FailureSignature |None: ...
    @property
    def modules(self, /) -> list[LoadedModule]:
        """
        The loaded modules, up to a maximum that the caller sets (see
        `modules_total`).
        """
    @property
    def modules_total(self, /) -> int:
        """
        The number of loaded modules.
        """
    @property
    def prcb(self, /) -> TriagePrcb |None:
        """
        The processor that crashed, as a triage dump recorded it.
        """
    @property
    def status(self, /) -> RunStatus:
        """
        The target's run status.
        """
    @property
    def system_info(self, /) -> DumpSystemInfo |None:
        """
        The system information of the dump.
        """
    @property
    def triage_overflowed(self, /) -> bool |None:
        """
        `True` if the triage data of the dump overflowed. `None` if the
        target is not a dump.
        """
    @property
    def unloaded_drivers(self, /) -> list[UnloadedDriver]: ...
    @property
    def verifier(self, /) -> VerifierFinding |None:
        """
        The Driver Verifier violation of a verifier bugcheck.
        """
    @property
    def warnings(self, /) -> list[str]:
        """
        Failures in best-effort data collection that did not stop the
        report.
        """
    @property
    def whea(self, /) -> WheaFinding |None:
        """
        The hardware error record of a WHEA bugcheck.
        """

@final
class Trustlet:
    """
    An isolated user-mode process (trustlet) in VTL1, such as `LsaIso.exe`. Its
    read-only views go through the page tables of the trustlet, which map the
    user half of the trustlet and the secure kernel.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The address of the secure kernel's process object for this trustlet.
        """
    @property
    def dtb(self, /) -> int:
        """
        The trustlet's page-table root.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in this trustlet's address space.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory, read through the page tables of the trustlet.
        """
    @property
    def name(self, /) -> str:
        """
        The image name, from the NT process.
        """
    @property
    def pid(self, /) -> int:
        """
        The NT process ID of the trustlet's VTL0 counterpart.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The NT process (VTL0 side), or `None` after the process exits.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        The symbols of the secure kernel, resolved in the address space of this
        trustlet. The user-mode modules of the trustlet are not included.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Return the identity of the trustlet as a plain `dict` (`pid`, `name`,
        `trustlet_id`, `dtb`, `address`). `!trustlets` lists the same fields.
        """
    @property
    def trustlet_id(self, /) -> int:
        """
        The trustlet ID from its creation attributes (1 for `LsaIso.exe`).
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types, read through the memory of the trustlet (`nt!` types by
        name).
        """

@final
class Type:
    """
    A named PDB struct or union layout, or an enum definition.
    """
    def __repr__(self, /) -> str: ...
    def at(self, /, addr: int) -> Struct:
        """
        Bind this layout to an address as a reflective struct cursor.
        """
    @property
    def fields(self, /) -> dict[str, Field]:
        """
        Field layouts by name, in offset order. An enum has no fields.
        """
    @property
    def name(self, /) -> str:
        """
        The PDB type name (for example, `_EPROCESS`).
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes, which for an enum is the width of the underlying
        storage.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def values(self, /) -> dict[str, int]:
        """
        Enum members by name, in declaration order. For a struct or union, this
        raises an exception.
        """
    def walk(self, /, head: int, link_field: str) -> list[Struct]:
        """
        Walk an intrusive list whose head is at `head`, where `link_field` is
        the field that holds the links.
        """

@final
class TypeLayout(BaseRecord):
    """
    The field layout of a struct or union (`dt`).
    """
    @property
    def fields(self, /) -> list[Field]:
        """
        The fields, sorted by offset.
        """
    @property
    def name(self, /) -> str:
        """
        The PDB type name.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """

@final
class Types:
    """
    PDB types for one address space: `dbg.types`, `proc.types`.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Type:
        """
        Resolve a struct, union, or enum by PDB name, raising `KeyError` for an
        unknown name.
        """
    def __repr__(self, /) -> str: ...
    def get(self, /, name: str) -> Type |None:
        """
        Return the named type, or `None` if the name does not resolve.
        """

@final
class UniqStackGroup(BaseRecord):
    """
    Threads whose walked stacks have the same frames and truncation.
    """
    @property
    def frames(self, /) -> list[StackFrame]:
        """
        The frames of the first thread, innermost first. The other threads
        have the same instruction pointers, but their stack pointers can
        differ.
        """
    @property
    def thread_count(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ThreadSummary]: ...
    @property
    def truncated(self, /) -> int:
        """
        The number of frames past the walk limit, which ntoseye did not
        compare.
        """

@final
class UniqStackScope(BaseRecord):
    """
    The threads that `!uniqstack` grouped.
    """
    @property
    def kind(self, /) -> str:
        """
        `all` or `process`.
        """
    @property
    def name(self, /) -> str |None:
        """
        The image name of the process. `None` for `all`.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The process ID. `None` for `all`.
        """

@final
class UniqStacks(BaseRecord):
    """
    Threads grouped by identical call stacks (`!uniqstack`).
    """
    @property
    def groups(self, /) -> list[UniqStackGroup]:
        """
        The groups, in the order that ntoseye walked their first threads.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether an interrupt stopped the walk before it finished.
        """
    @property
    def scanned_threads(self, /) -> int: ...
    @property
    def scope(self, /) -> UniqStackScope: ...
    @property
    def unwalked(self, /) -> list[UnwalkedThread]: ...
    @property
    def walked_threads(self, /) -> int:
        """
        The number of threads whose stacks ntoseye walked and grouped.
        """

@final
class UnloadedDriver(BaseRecord):
    """
    A driver that the system unloaded recently, as the crash dump records
    it.
    """
    @property
    def end_address(self, /) -> int: ...
    @property
    def name(self, /) -> str: ...
    @property
    def start_address(self, /) -> int: ...

@final
class UnwalkedThread(BaseRecord):
    """
    A thread whose stack walk failed, so ntoseye could not search or group
    it.
    """
    @property
    def error(self, /) -> str:
        """
        The reason the walk failed.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...

@final
class UnwindHandler(BaseRecord):
    """
    The exception or termination handler of an unwind info.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def data(self, /) -> int:
        """
        The start address of the language-specific data of the handler.
        """
    @property
    def symbol(self, /) -> str: ...

@final
class VcpuStatus(BaseRecord):
    """
    A vCPU (backend execution context) and the guest code that it runs.
    """
    @property
    def context(self, /) -> str:
        """
        What the vCPU runs: `kernel`, a process name, `hypervisor`, `VTL1`,
        a guest partition's VP (`partition 0x3 VP 1`), or `unknown`; `no
        context` for a dump CPU whose context the dump lacks. Empty if
        ntoseye cannot read the register context.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that the register context is not available. None if it is
        available.
        """
    @property
    def id(self, /) -> str:
        """
        The backend thread/vCPU ID (`p1.1`).
        """
    @property
    def rip(self, /) -> int |None:
        """
        None if ntoseye cannot read the register context.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        For a vCPU halted in the Windows hypervisor, the VTL states that the
        hypervisor saved for the vCPU's virtual processor, VTL0 first.
        """
    @property
    def serving(self, /) -> ServedVp |None:
        """
        For a vCPU halted in the Windows hypervisor, the guest partition's
        virtual processor whose exit it handles or that it is about to
        enter, when it is not one of the root partition's.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to `rip`, if one resolves.
        """

@final
class Verifier(BaseRecord):
    """
    The Driver Verifier configuration, statistics, and drivers
    (`!verifier`). The drivers are the verified drivers and the configured
    suspect drivers that are not loaded.
    """
    @property
    def configured_but_unloaded(self, /) -> Diagnostic[list[VerifierSuspectDriver]]:
        """
        The suspect drivers that are configured for verification but are
        not loaded.
        """
    @property
    def drivers(self, /) -> Diagnostic[list[VerifierDriverSummary]]:
        """
        The verified drivers.
        """
    @property
    def drivers_truncated(self, /) -> bool:
        """
        Whether the driver table gives a smaller entry count than the
        number of linked entries, which means that the walk stopped before
        it reached all drivers.
        """
    @property
    def level(self, /) -> Diagnostic[int]:
        """
        The verification level (`MmVerifierData.Level`).
        """
    @property
    def level_options(self, /) -> Diagnostic[list[str]]:
        """
        The names of the checks that `level` enables.
        """
    @property
    def option_flags(self, /) -> Diagnostic[int]:
        """
        The option flags (`VerifierOptionFlags`).
        """
    @property
    def statistics(self, /) -> VerifierStatistics: ...
    @property
    def suspect_list_termination(self, /) -> ListEnd:
        """
        How the suspect-list walk ended.
        """
    @property
    def verify_mode(self, /) -> Diagnostic[int]: ...

@final
class VerifierDriver(BaseRecord):
    """
    The image, signing level, and counters of one verified driver
    (`!verifier <module>`).
    """
    @property
    def acquire_spin_locks(self, /) -> int: ...
    @property
    def allocations_failed(self, /) -> int: ...
    @property
    def allocations_failed_deliberately(self, /) -> int:
        """
        The number of allocations that the verifier failed on purpose
        (fault injection).
        """
    @property
    def allocations_with_no_tag(self, /) -> int: ...
    @property
    def contiguous_memory_bytes(self, /) -> int: ...
    @property
    def current_nonpaged_pool_allocations(self, /) -> int: ...
    @property
    def current_paged_pool_allocations(self, /) -> int: ...
    @property
    def driver_object(self, /) -> int:
        """
        The `_DRIVER_OBJECT` of the driver.
        """
    @property
    def image_base(self, /) -> int: ...
    @property
    def image_size(self, /) -> int:
        """
        The image size in bytes.
        """
    @property
    def locked_bytes(self, /) -> int: ...
    @property
    def mapped_io_space_bytes(self, /) -> int: ...
    @property
    def mapped_locked_bytes(self, /) -> int: ...
    @property
    def module(self, /) -> str: ...
    @property
    def nonpaged_bytes(self, /) -> int: ...
    @property
    def paged_bytes(self, /) -> int: ...
    @property
    def pages_for_mdl_bytes(self, /) -> int: ...
    @property
    def peak_contiguous_memory_bytes(self, /) -> int: ...
    @property
    def peak_locked_bytes(self, /) -> int: ...
    @property
    def peak_mapped_io_space_bytes(self, /) -> int: ...
    @property
    def peak_mapped_locked_bytes(self, /) -> int: ...
    @property
    def peak_nonpaged_bytes(self, /) -> int: ...
    @property
    def peak_nonpaged_pool_allocations(self, /) -> int: ...
    @property
    def peak_paged_bytes(self, /) -> int: ...
    @property
    def peak_paged_pool_allocations(self, /) -> int: ...
    @property
    def peak_pages_for_mdl_bytes(self, /) -> int: ...
    @property
    def raise_irqls(self, /) -> int: ...
    @property
    def se_signing_level(self, /) -> int:
        """
        The signing level of the image (`SE_SIGNING_LEVEL`).
        """
    @property
    def suspect(self, /) -> VerifierSuspectDriver |None:
        """
        The suspect-list entry of the driver, with its load history.
        `None` if the driver has no entry.
        """
    @property
    def synchronize_executions(self, /) -> int: ...

@final
class VerifierDriverSummary(BaseRecord):
    """
    A driver that Driver Verifier verifies, from the `!verifier` list.
    """
    @property
    def entry(self, /) -> int:
        """
        The verifier entry of the driver.
        """
    @property
    def module(self, /) -> str:
        """
        The module name of the driver.
        """
    @property
    def nonpaged_bytes(self, /) -> int:
        """
        The nonpaged pool that the driver holds, in bytes.
        """
    @property
    def paged_bytes(self, /) -> int:
        """
        The paged pool that the driver holds, in bytes.
        """
    @property
    def state(self, /) -> str:
        """
        The state of the entry (`Loaded`).
        """

@final
class VerifierFinding(BaseRecord):
    """
    A Driver Verifier bugcheck, decoded from its subcode.
    """
    @property
    def addresses(self, /) -> list[VerifierFindingAddress]:
        """
        The addresses in the parameters, with their roles.
        """
    @property
    def arguments(self, /) -> list[VerifierFindingArgument]:
        """
        The bugcheck parameters, with descriptions for the subcode.
        """
    @property
    def associated_driver(self, /) -> str |None:
        """
        The driver that ntoseye attributes the violation to.
        """
    @property
    def bugcheck_code(self, /) -> int: ...
    @property
    def bugcheck_name(self, /) -> str: ...
    @property
    def known_subcode(self, /) -> bool:
        """
        `True` if the decoder recognizes the subcode.
        """
    @property
    def subcode(self, /) -> int:
        """
        The verifier subcode (the first bugcheck parameter).
        """
    @property
    def subcode_description(self, /) -> str:
        """
        What the subcode means, or `unknown verifier subcode`.
        """

@final
class VerifierFindingAddress(BaseRecord):
    """
    An address in a verifier bugcheck, and its role.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def role(self, /) -> str: ...

@final
class VerifierFindingArgument(BaseRecord):
    """
    A verifier bugcheck parameter and what it means for the subcode.
    """
    @property
    def description(self, /) -> str: ...
    @property
    def value(self, /) -> int: ...

@final
class VerifierStatistics(BaseRecord):
    """
    The aggregate counters of Driver Verifier. ntoseye reads each counter
    separately, and each read can fail.
    """
    @property
    def acquire_spin_locks(self, /) -> Diagnostic[int]: ...
    @property
    def allocations_attempted(self, /) -> Diagnostic[int]: ...
    @property
    def allocations_failed(self, /) -> Diagnostic[int]: ...
    @property
    def allocations_succeeded(self, /) -> Diagnostic[int]: ...
    @property
    def allocations_succeeded_special_pool(self, /) -> Diagnostic[int]: ...
    @property
    def allocations_with_no_tag(self, /) -> Diagnostic[int]: ...
    @property
    def current_nonpaged_pool_allocations(self, /) -> Diagnostic[int]: ...
    @property
    def current_paged_pool_allocations(self, /) -> Diagnostic[int]: ...
    @property
    def loads(self, /) -> Diagnostic[int]: ...
    @property
    def nonpaged_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def paged_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def peak_nonpaged_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def peak_nonpaged_pool_allocations(self, /) -> Diagnostic[int]: ...
    @property
    def peak_paged_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def peak_paged_pool_allocations(self, /) -> Diagnostic[int]: ...
    @property
    def raise_irqls(self, /) -> Diagnostic[int]: ...
    @property
    def synchronize_executions(self, /) -> Diagnostic[int]: ...
    @property
    def trims(self, /) -> Diagnostic[int]: ...
    @property
    def unloads(self, /) -> Diagnostic[int]: ...

@final
class VerifierSuspectDriver(BaseRecord):
    """
    A driver that is configured for verification, from the verifier
    suspect list.
    """
    @property
    def address(self, /) -> int:
        """
        The suspect-list entry.
        """
    @property
    def base_name(self, /) -> str: ...
    @property
    def full_name(self, /) -> str: ...
    @property
    def loads(self, /) -> int:
        """
        The number of times that the driver loaded.
        """
    @property
    def unloads(self, /) -> int:
        """
        The number of times that the driver unloaded.
        """

@final
class VirtualProcessor:
    """
    A virtual processor of a Windows hypervisor partition.
    """
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The address of the hypervisor's VP object.
        """
    def ept_differences(self, /) -> list[EptDifference]:
        """
        The guest physical ranges that VTL0's and VTL1's EPTs map differently,
        in order, as `!hveptdiff` lists them. Raises `NtoseyeError` unless both
        VTLs have eVMCS state and readable EPTs.
        """
    @property
    def index(self, /) -> int:
        """
        The VP index in its partition.
        """
    @property
    def processors(self, /) -> list[HypervisorProcessor]:
        """
        The processors whose current VP this is (the one that runs it, or ran
        it last).
        """
    def registers(self, /, vtl: int |None = None) -> VpRegisters:
        """
        The registers of VTL `vtl` of this VP, by default the VTL it runs
        in, as `!hvr` shows them, whether or not a processor runs it: those
        of a vCPU that runs it now, those of the exit a vCPU in the
        hypervisor handles for it, or those it saved at its last exit, which
        it resumes with but for the exit's result, such as a hypercall's
        status in RAX (`source` says which). The general-purpose registers
        are shared by a VP's VTLs and belong to the one it runs in; another
        VTL's are its eVMCS state alone, and `missing` says why. Reads the
        target now, so it must be halted. This feature is experimental.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        Return the VP as a plain `dict` (`index`, `address`, `processors`,
        `vtl`, and `vtls`, a dict from each VTL to its dict).
        """
    @property
    def vtl(self, /) -> int:
        """
        The VTL that the VP runs, or last ran, in.
        """
    @property
    def vtls(self, /) -> dict[int, HypervisorVtl]:
        """
        Each VTL enabled on the VP, keyed by VTL (`{0: ..., 1: ...}` under
        VBS).
        """

@final
class VmCounter(BaseRecord):
    """
    A named memory-manager counter (`!vm`).
    """
    @property
    def name(self, /) -> str: ...
    @property
    def unit(self, /) -> str:
        """
        The unit of `value`: `pages`, `bytes`, or empty for a plain count.
        """
    @property
    def value(self, /) -> Diagnostic[int]: ...

@final
class VmPool(BaseRecord):
    """
    Pool counters and the pool fields of `MiState` (`!vm`).
    """
    @property
    def fields(self, /) -> list[VmCounter]:
        """
        The symbol-backed pool fields of `MiState`.
        """
    @property
    def nonpaged_pool_bytes(self, /) -> Diagnostic[int]: ...
    @property
    def nonpaged_pool_maximum(self, /) -> Diagnostic[int]: ...
    @property
    def paged_pool_pages(self, /) -> Diagnostic[int]: ...

@final
class VmPte(BaseRecord):
    """
    System PTE counters (`!vm`).
    """
    @property
    def counters(self, /) -> list[VmCounter]: ...

@final
class VmStatistics(BaseRecord):
    """
    Virtual-memory statistics (`!vm`).
    """
    @property
    def include_processes(self, /) -> bool:
        """
        Whether per-process usage was requested.
        """
    @property
    def page_files(self, /) -> list[VmCounter]:
        """
        Paging-file counters.
        """
    @property
    def pool(self, /) -> VmPool: ...
    @property
    def pte(self, /) -> VmPte: ...
    @property
    def system(self, /) -> SystemMemoryUsage: ...

@final
class VpRegisters(BaseRecord):
    """
    The registers of one VTL of a Windows hypervisor VP (`!hvr`).
    """
    @property
    def missing(self, /) -> str |None:
        """
        Why the general-purpose registers are missing, when they are.
        """
    @property
    def registers(self, /) -> Record:
        """
        RIP, RSP, flags, control and segment registers, and the
        general-purpose ones when they are known.
        """
    @property
    def source(self, /) -> str:
        """
        Where they are from: a vCPU that runs the VP now, the exit a vCPU
        in the hypervisor handles for it, or its last exit.
        """

@final
class Vpb(BaseRecord):
    """
    A volume parameter block (`!vpb`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def device_name(self, /) -> str |None: ...
    @property
    def device_object(self, /) -> int:
        """
        The mounted file system's volume device object.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `VPB_*` bits set in `flags`.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def real_device(self, /) -> int:
        """
        The storage device that holds the volume.
        """
    @property
    def real_device_name(self, /) -> str |None: ...
    @property
    def reference_count(self, /) -> int: ...
    @property
    def serial_number(self, /) -> int: ...
    @property
    def volume_label(self, /) -> str: ...

@final
class VsChunk(BaseRecord):
    """
    A segment-heap VS chunk, decoded from its header.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def flags(self, /) -> int |None:
        """
        Always None, because VS chunk headers have no flags.
        """
    @property
    def granule(self, /) -> int:
        """
        The header size in bytes (see `SegmentHeap.granule`).
        """
    @property
    def kind(self, /) -> str:
        """
        Always `vs-chunk`.
        """
    @property
    def previous_size(self, /) -> int:
        """
        The size in bytes of the previous chunk.
        """
    @property
    def size(self, /) -> int:
        """
        The size in bytes, with the header.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int |None:
        """
        The number of unused bytes, as recorded in the last word of the
        chunk. None if the header records no unused bytes.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int:
        """
        The number of bytes that the caller can use.
        """

@final
class VsSubsegment(BaseRecord):
    """
    A segment-heap variable-size subsegment (`_HEAP_VS_SUBSEGMENT`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def chunk_count(self, /) -> int:
        """
        The number of chunks that the walk found.
        """
    @property
    def chunks(self, /) -> list[HeapBlock]:
        """
        The chunks of the subsegment. Empty unless the entries were listed.
        """
    @property
    def signature_ok(self, /) -> bool:
        """
        Whether the signature of the subsegment matches the expected value.
        """

@final
class Watchpoint(Breakpoint):
    """
    A hardware data watchpoint.
    """
    @property
    def access(self, /) -> str:
        """
        The data access type (`"write"` or `"read_write"`).
        """
    @property
    def length(self, /) -> int:
        """
        The width of the watched memory access, in bytes.
        """

@final
class WdfCallback(BaseRecord):
    """
    A queue event callback.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        `EvtIoRead`, ...
        """
    @property
    def symbol(self, /) -> str |None: ...

@final
class WdfClient(BaseRecord):
    """
    A KMDF client driver (`_FX_DRIVER_GLOBALS`).
    """
    @property
    def driver(self, /) -> int |None:
        """
        The `FxDriver`. `None` before the driver calls `WdfDriverCreate`.
        """
    @property
    def driver_object(self, /) -> int: ...
    @property
    def driver_object_name(self, /) -> str |None:
        """
        The `DRIVER_OBJECT`'s name (`\\Driver\\kdnic`).
        """
    @property
    def globals(self, /) -> int:
        """
        The `_FX_DRIVER_GLOBALS`.
        """
    @property
    def image_base(self, /) -> int: ...
    @property
    def image_size(self, /) -> int:
        """
        Bytes.
        """
    @property
    def log_header(self, /) -> int |None:
        """
        The `_WDF_IFR_HEADER` of the IFR log (`WdfLogHeader`). `None` if the
        driver has no IFR log.
        """
    @property
    def name(self, /) -> str |None:
        """
        `Public.DriverName`. `None` if it is empty or not printable.
        """
    @property
    def problems(self, /) -> list[str]:
        """
        The parts of the globals that failed validation, whose related
        fields are `None`.
        """
    @property
    def registry_path(self, /) -> str |None:
        """
        The `FxDriver`'s registry path.
        """
    @property
    def verifier_on(self, /) -> bool:
        """
        `FxVerifierOn`.
        """
    @property
    def version(self, /) -> WdfVersion |None:
        """
        The KMDF version that the driver bound to (`WdfBindInfo->Version`).
        """
    @property
    def wdf_driver(self, /) -> int |None:
        """
        The WDFDRIVER handle (`Public.Driver`).
        """

@final
class WdfContext(BaseRecord):
    """
    An object's context (`FxContextHeader`).
    """
    @property
    def context(self, /) -> int:
        """
        The context itself.
        """
    @property
    def header(self, /) -> int:
        """
        The `FxContextHeader`.
        """
    @property
    def name(self, /) -> str |None:
        """
        The context type's name.
        """
    @property
    def size(self, /) -> int |None:
        """
        Bytes.
        """
    @property
    def type_info(self, /) -> int |None:
        """
        The `_WDF_OBJECT_CONTEXT_TYPE_INFO`. `None` for a header that has no
        context type.
        """

@final
class WdfDevice(BaseRecord):
    """
    A WDFDEVICE with its device objects, state machines, and queues
    (`!wdfkd.wdfdevice`).
    """
    @property
    def address(self, /) -> int:
        """
        The `FxDevice`.
        """
    @property
    def attached_device(self, /) -> int:
        """
        The device object this one is attached to.
        """
    @property
    def default_child_list(self, /) -> int |None:
        """
        An FDO's default child list (WDFCHILDLIST).
        """
    @property
    def default_queue(self, /) -> int |None:
        """
        The default queue's WDFQUEUE handle.
        """
    @property
    def device_name(self, /) -> str |None: ...
    @property
    def device_object(self, /) -> int: ...
    @property
    def device_power_state(self, /) -> WdfState |None:
        """
        `_DEVICE_POWER_STATE`.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The owning driver's name, when it has one.
        """
    @property
    def globals(self, /) -> int:
        """
        The owning driver's `_FX_DRIVER_GLOBALS`.
        """
    @property
    def handle(self, /) -> int: ...
    @property
    def kind(self, /) -> str:
        """
        `FDO`, `filter`, `PDO`, or `control`.
        """
    @property
    def parent(self, /) -> WdfObjectRef |None:
        """
        A PDO's parent WDFDEVICE.
        """
    @property
    def physical_device(self, /) -> int:
        """
        The device stack's PDO.
        """
    @property
    def pkg_io(self, /) -> int:
        """
        The `FxPkgIo`.
        """
    @property
    def pkg_pnp(self, /) -> int:
        """
        The `FxPkgPnp`. Null for a control device.
        """
    @property
    def pnp_state(self, /) -> WdfState:
        """
        `_WDF_DEVICE_PNP_STATE`.
        """
    @property
    def power_policy_state(self, /) -> WdfState:
        """
        `_WDF_DEVICE_POWER_POLICY_STATE`.
        """
    @property
    def power_state(self, /) -> WdfState:
        """
        `_WDF_DEVICE_POWER_STATE`.
        """
    @property
    def queues(self, /) -> list[WdfQueueSummary]: ...
    @property
    def queues_stopped(self, /) -> str |None:
        """
        Why the walk of the queue list stopped before the list head. `None`
        if the walk completed.
        """
    @property
    def static_child_list(self, /) -> int |None:
        """
        An FDO's static child list (WDFCHILDLIST).
        """
    @property
    def system_power_state(self, /) -> WdfState |None:
        """
        `_SYSTEM_POWER_STATE`.
        """

@final
class WdfDriverDevice(BaseRecord):
    """
    A device object of a driver, and its related WDFDEVICE.
    """
    @property
    def device(self, /) -> int |None:
        """
        The `FxDevice`. `None` if the device object is not a WDFDEVICE of
        this driver.
        """
    @property
    def device_object(self, /) -> int: ...
    @property
    def handle(self, /) -> int |None:
        """
        The WDFDEVICE handle.
        """
    @property
    def kind(self, /) -> str |None:
        """
        `FDO`, `filter`, `PDO`, or `control`.
        """
    @property
    def pnp_state(self, /) -> WdfState |None:
        """
        `m_CurrentPnpState` (`_WDF_DEVICE_PNP_STATE`).
        """
    @property
    def unlinked(self, /) -> str |None:
        """
        Why the device object does not link to a WDFDEVICE of this driver.
        """

@final
class WdfDriverInfo(BaseRecord):
    """
    A KMDF client driver and its device objects (`!wdfkd.wdfdriverinfo`).
    """
    @property
    def client(self, /) -> WdfClient: ...
    @property
    def devices(self, /) -> list[WdfDriverDevice]:
        """
        The driver object's `DeviceObject`/`NextDevice` chain.
        """
    @property
    def devices_stopped(self, /) -> str |None:
        """
        Why the walk of the device chain stopped before a null link. `None`
        if the walk got to a null link.
        """

@final
class WdfHandle(BaseRecord):
    """
    A WDF handle and the object it names (`!wdfkd.wdfhandle`).
    """
    @property
    def address(self, /) -> int:
        """
        The `FxObject`.
        """
    @property
    def contexts(self, /) -> list[WdfContext]: ...
    @property
    def contexts_stopped(self, /) -> str |None:
        """
        Why the walk of the context header chain stopped before a null
        `NextHeader`. `None` if the walk got to a null `NextHeader`.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The owning driver's name, when it has one.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `FXOBJECT_FLAGS` set in `flags`.
        """
    @property
    def flags(self, /) -> int:
        """
        `m_ObjectFlags`.
        """
    @property
    def globals(self, /) -> int:
        """
        The owning driver's `_FX_DRIVER_GLOBALS`.
        """
    @property
    def handle(self, /) -> int: ...
    @property
    def object_size(self, /) -> int:
        """
        `m_ObjectSize`: the size of the object and its extra bytes.
        """
    @property
    def offset(self, /) -> int |None:
        """
        For an offset handle, the `WDFOBJECT_OFFSET` value to subtract from
        the address that the handle points to.
        """
    @property
    def parent(self, /) -> WdfObjectRef |None: ...
    @property
    def refcount(self, /) -> int: ...
    @property
    def state(self, /) -> WdfState:
        """
        `m_ObjectState` (`FxObjectState`).
        """
    @property
    def type_name(self, /) -> str:
        """
        Its `FX_OBJECT_TYPES` name.
        """
    @property
    def type_value(self, /) -> int:
        """
        `m_Type`.
        """

@final
class WdfLoader(BaseRecord):
    """
    The KMDF client drivers on `FxLibraryGlobals.FxDriverGlobalsList`
    (`!wdfkd.wdfldr`).
    """
    @property
    def clients(self, /) -> list[WdfClient]: ...
    @property
    def library_globals(self, /) -> int:
        """
        `Wdf01000!FxLibraryGlobals`.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the client list stopped before the list head. `None`
        if the walk completed.
        """

@final
class WdfLog(BaseRecord):
    """
    The In-Flight Recorder log of a client driver, oldest record first
    (`!wdfkd.wdflogdump`).
    """
    @property
    def base(self, /) -> int:
        """
        The record area.
        """
    @property
    def corruption(self, /) -> str |None:
        """
        The item that failed validation, when `end` is `corrupt`.
        """
    @property
    def current(self, /) -> int:
        """
        The offset where KMDF writes the next record.
        """
    @property
    def driver(self, /) -> str: ...
    @property
    def end(self, /) -> str:
        """
        Why the walk ended: `empty`, `first_record`, `overwritten`, or
        `corrupt`.
        """
    @property
    def globals(self, /) -> int:
        """
        The `_FX_DRIVER_GLOBALS`.
        """
    @property
    def header(self, /) -> int:
        """
        The `_WDF_IFR_HEADER`.
        """
    @property
    def previous(self, /) -> int:
        """
        The newest record's offset.
        """
    @property
    def records(self, /) -> list[WdfLogRecord]: ...
    @property
    def sequence(self, /) -> int:
        """
        The header's sequence number.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the record area, in bytes.
        """
    @property
    def use_timestamps(self, /) -> bool:
        """
        Whether the records have timestamps ('L2').
        """

@final
class WdfLogRecord(BaseRecord):
    """
    An In-Flight Recorder record.
    """
    @property
    def args(self, /) -> str:
        """
        The argument bytes, as hex.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the message is not formatted.
        """
    @property
    def flags(self, /) -> str |None:
        """
        Its `FLAGS=`.
        """
    @property
    def function(self, /) -> str |None:
        """
        Its `FUNC=`.
        """
    @property
    def level(self, /) -> str |None:
        """
        Its `LEVEL=`.
        """
    @property
    def message_guid(self, /) -> str: ...
    @property
    def message_number(self, /) -> int: ...
    @property
    def offset(self, /) -> int:
        """
        Its offset in the log.
        """
    @property
    def provider(self, /) -> str |None:
        """
        The TMF message's provider, when a loaded PDB declares it.
        """
    @property
    def sequence(self, /) -> int: ...
    @property
    def text(self, /) -> str |None:
        """
        The formatted message.
        """
    @property
    def timestamp(self, /) -> int |None:
        """
        The FILETIME. `None` for an 'LR' record, because it has no
        timestamp.
        """
    @property
    def timestamp_utc(self, /) -> str |None:
        """
        `timestamp` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        """

@final
class WdfObjectRef(BaseRecord):
    """
    The address, handle, and type of a KMDF object, as far as ntoseye can
    read them.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def handle(self, /) -> int |None:
        """
        `None` for an object that has no handle or that ntoseye cannot read.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The `FX_OBJECT_TYPES` name of its `m_Type`.
        """

@final
class WdfQueue(BaseRecord):
    """
    A WDFQUEUE with its configuration, state, and requests
    (`!wdfkd.wdfqueue`).
    """
    @property
    def address(self, /) -> int:
        """
        The `FxIoQueue`.
        """
    @property
    def allow_zero_length_requests(self, /) -> bool: ...
    @property
    def callbacks(self, /) -> list[WdfCallback]:
        """
        The callbacks the driver set.
        """
    @property
    def deleted(self, /) -> bool: ...
    @property
    def device(self, /) -> WdfObjectRef |None: ...
    @property
    def dispatch_type(self, /) -> WdfState:
        """
        `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The owning driver's name, when it has one.
        """
    @property
    def driver_cancelable(self, /) -> list[WdfRequest]:
        """
        Requests the driver marked cancelable.
        """
    @property
    def driver_cancelable_count(self, /) -> int:
        """
        Requests the driver marked cancelable.
        """
    @property
    def driver_cancelable_stopped(self, /) -> str |None:
        """
        Why the walk stopped early. `None` if the walk completed.
        """
    @property
    def driver_owned(self, /) -> list[WdfRequest]:
        """
        Requests presented to the driver.
        """
    @property
    def driver_owned_count(self, /) -> int:
        """
        Requests the driver owns.
        """
    @property
    def driver_owned_stopped(self, /) -> str |None:
        """
        Why the walk stopped early. `None` if the walk completed.
        """
    @property
    def execution_level(self, /) -> WdfState:
        """
        `_WDF_EXECUTION_LEVEL`.
        """
    @property
    def handle(self, /) -> int: ...
    @property
    def max_parallel_requests(self, /) -> int:
        """
        `m_MaxParallelQueuePresentedRequests`.
        """
    @property
    def pending(self, /) -> list[WdfRequest]:
        """
        Requests waiting in the queue.
        """
    @property
    def pending_count(self, /) -> int:
        """
        Requests waiting in the queue.
        """
    @property
    def pending_stopped(self, /) -> str |None:
        """
        Why the walk stopped early. `None` if the walk completed.
        """
    @property
    def power_managed(self, /) -> bool: ...
    @property
    def power_state(self, /) -> WdfState:
        """
        `FxIoQueuePowerState`.
        """
    @property
    def state(self, /) -> int:
        """
        `m_QueueState`.
        """
    @property
    def state_names(self, /) -> list[str]:
        """
        The `_FX_IO_QUEUE_STATE` bits set in `state`.
        """
    @property
    def synchronization_scope(self, /) -> WdfState:
        """
        `_WDF_SYNCHRONIZATION_SCOPE`.
        """
    @property
    def two_phase_completions(self, /) -> int: ...

@final
class WdfQueueSummary(BaseRecord):
    """
    A device's queue.
    """
    @property
    def address(self, /) -> int:
        """
        The `FxIoQueue`.
        """
    @property
    def dispatch_type(self, /) -> WdfState:
        """
        `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        """
    @property
    def driver_owned(self, /) -> int:
        """
        Requests the driver owns.
        """
    @property
    def handle(self, /) -> int:
        """
        The WDFQUEUE handle.
        """
    @property
    def is_default(self, /) -> bool:
        """
        Whether it is the default queue of the device.
        """
    @property
    def pending(self, /) -> int:
        """
        Requests waiting in the queue.
        """
    @property
    def power_managed(self, /) -> bool: ...

@final
class WdfRequest(BaseRecord):
    """
    A request on a queue's list.
    """
    @property
    def address(self, /) -> int:
        """
        The `FxRequest`.
        """
    @property
    def handle(self, /) -> int:
        """
        The WDFREQUEST handle.
        """
    @property
    def irp(self, /) -> int: ...

@final
class WdfState(BaseRecord):
    """
    A PDB enum value and its name.
    """
    @property
    def name(self, /) -> str |None:
        """
        `None` when the enum has no name for `value`.
        """
    @property
    def value(self, /) -> int: ...

@final
class WdfVersion(BaseRecord):
    """
    A KMDF version.
    """
    @property
    def build(self, /) -> int: ...
    @property
    def major(self, /) -> int: ...
    @property
    def minor(self, /) -> int: ...

@final
class WheaFinding(BaseRecord):
    """
    The WHEA error record of a hardware-error bugcheck.
    """
    @property
    def record(self, /) -> Diagnostic[WheaRecord]:
        """
        The decoded record, or the reason that decoding failed.
        """
    @property
    def record_address(self, /) -> int |None:
        """
        The address of the record. `None` if the bugcheck does not give
        one.
        """

@final
class WheaRecord(BaseRecord):
    """
    A decoded WHEA error record.
    """
    @property
    def length(self, /) -> int:
        """
        The record's length in bytes.
        """
    @property
    def revision(self, /) -> int: ...
    @property
    def sections(self, /) -> list[WheaSection]: ...
    @property
    def sections_total(self, /) -> int:
        """
        The number of sections in the record. `sections` holds at most 64.
        """
    @property
    def severity(self, /) -> int:
        """
        The record's error severity (`WHEA_ERROR_SEVERITY`).
        """

@final
class WheaSection(BaseRecord):
    """
    One section of a WHEA error record.
    """
    @property
    def kind(self, /) -> str:
        """
        `processor_generic`, `memory`, `pci_express`, `x64_processor`, or
        `unknown`.
        """
    @property
    def length(self, /) -> int:
        """
        The section's length in bytes.
        """
    @property
    def offset(self, /) -> int:
        """
        The section's offset in the record, in bytes.
        """
    @property
    def section_type(self, /) -> str:
        """
        The section type GUID.
        """
    @property
    def severity(self, /) -> int:
        """
        The section's error severity.
        """

@final
class WorkItem(BaseRecord):
    """
    A pending `_WORK_QUEUE_ITEM`.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def io_work_item(self, /) -> IoWorkItem |None:
        """
        The I/O work item that owns this item, if `IoQueueWorkItem` queued
        it.
        """
    @property
    def parameter(self, /) -> int: ...
    @property
    def routine(self, /) -> int:
        """
        `WorkerRoutine`.
        """
    @property
    def routine_symbol(self, /) -> str |None:
        """
        `routine` as a symbol, when one resolves.
        """

@final
class WorkQueue(BaseRecord):
    """
    An `_EX_WORK_QUEUE`.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def concurrency(self, /) -> int:
        """
        `_KPRIQUEUE.MaximumCount`, the maximum number of threads that can run
        items at the same time.
        """
    @property
    def items_processed(self, /) -> int: ...
    @property
    def items_processed_last_pass(self, /) -> int: ...
    @property
    def max_threads(self, /) -> int: ...
    @property
    def min_threads(self, /) -> int: ...
    @property
    def node(self, /) -> int:
        """
        The NUMA node.
        """
    @property
    def partition(self, /) -> int:
        """
        The `_EPARTITION` it belongs to.
        """
    @property
    def pending(self, /) -> int:
        """
        The number of items on all 32 priority lists, including items that
        are not listed.
        """
    @property
    def priorities(self, /) -> list[WorkQueuePriority]:
        """
        The priority lists that hold items or have running threads, limited
        to the requested priorities.
        """
    @property
    def queue_index(self, /) -> int: ...
    @property
    def queue_index_name(self, /) -> str |None:
        """
        The name of `queue_index`, if it is a known index.
        """
    @property
    def thread_count(self, /) -> int: ...
    @property
    def threads(self, /) -> list[WorkerThread]: ...
    @property
    def threads_termination(self, /) -> ListEnd:
        """
        How the worker-thread list walk ended.
        """

@final
class WorkQueuePriority(BaseRecord):
    """
    One of the 32 priority lists of a work queue.
    """
    @property
    def current_count(self, /) -> int:
        """
        `CurrentCount[priority]`, the number of threads that run an item of
        this priority.
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def queue_types(self, /) -> list[str]:
        """
        The `WORK_QUEUE_TYPE`s that `ExQueueWorkItem` maps to this priority.
        """
    @property
    def termination(self, /) -> ListEnd:
        """
        How the list walk ended.
        """
    @property
    def work_items(self, /) -> list[WorkItem]:
        """
        The pending work items (key `items`).
        """

@final
class WorkQueues(BaseRecord):
    """
    All executive worker queues (`!exqueue`).
    """
    @property
    def errors(self, /) -> list[str]:
        """
        The partitions or queues that ntoseye could not decode.
        """
    @property
    def flags(self, /) -> int:
        """
        The `!exqueue` flags.
        """
    @property
    def priority_filter(self, /) -> list[int] |None:
        """
        The priorities that flags 0x10, 0x20, and 0x40 selected. `None` means
        all priorities.
        """
    @property
    def queues(self, /) -> list[WorkQueue]: ...

@final
class WorkerThread(BaseRecord):
    """
    A thread that serves a work queue.
    """
    @property
    def kthread(self, /) -> int: ...
    @property
    def stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The stack of the thread. `None` if stacks were not requested or the
        thread did not decode.
        """
    @property
    def thread(self, /) -> Diagnostic[ThreadSummary]: ...

@final
class ZombieProcess(BaseRecord):
    """
    An exited process whose object still has references.
    """
    @property
    def eprocess(self, /) -> int: ...
    @property
    def exit_status(self, /) -> int:
        """
        The exit NTSTATUS.
        """
    @property
    def exit_time(self, /) -> int:
        """
        `_EPROCESS.ExitTime`, a FILETIME.
        """
    @property
    def handle_count(self, /) -> int:
        """
        Open handles to the object.
        """
    @property
    def image(self, /) -> str:
        """
        The image name.
        """
    @property
    def pid(self, /) -> int: ...
    @property
    def pointer_count(self, /) -> int:
        """
        References to the object.
        """

@final
class ZombieThread(BaseRecord):
    """
    A terminated thread whose object still has references.
    """
    @property
    def ethread(self, /) -> int: ...
    @property
    def exit_status(self, /) -> int:
        """
        The exit NTSTATUS.
        """
    @property
    def handle_count(self, /) -> int:
        """
        Open handles to the object.
        """
    @property
    def image(self, /) -> str |None:
        """
        The image name of the owning process. `None` if ntoseye cannot read it.
        """
    @property
    def pid(self, /) -> int: ...
    @property
    def pointer_count(self, /) -> int:
        """
        References to the object.
        """
    @property
    def process(self, /) -> int:
        """
        The owning `_EPROCESS`.
        """
    @property
    def tid(self, /) -> int: ...

@final
class Zombies(BaseRecord):
    """
    The exited processes and terminated threads that still have references
    (`!zombies`), which ntoseye finds with a scan of nonpaged pool.
    """
    @property
    def interrupted(self, /) -> bool:
        """
        True if the scan was interrupted before it finished.
        """
    @property
    def live_processes(self, /) -> int:
        """
        The number of live processes that the scan found.
        """
    @property
    def live_threads(self, /) -> int:
        """
        The number of live threads that the scan found.
        """
    @property
    def processes(self, /) -> list[ZombieProcess] |None:
        """
        `None` if the flags did not ask for processes.
        """
    @property
    def region_end(self, /) -> int:
        """
        The end of the scanned pool region.
        """
    @property
    def region_start(self, /) -> int:
        """
        The start of the scanned pool region.
        """
    @property
    def scanned_pages(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ZombieThread] |None:
        """
        `None` if the flags did not ask for threads.
        """
    @property
    def truncated(self, /) -> bool:
        """
        True if a result list reached its limit.
        """

@final
class _StopContext:
    """
    Rust-only snapshot backing the shared properties of a typed stop.
    """

def _cli_main() -> int:
    """
    Run the `ntoseye` command line on `sys.argv` and return its exit status, as
    the `ntoseye` script of the wheel does. The function releases the GIL for
    the full session, and custom commands get the GIL again while they run.
    """

def attach(backend: Literal["kd", "kdnet", "gdb", "memory", "dmp"] = ..., connect: str |None = None, key: str |None = None, memory_source: Literal["auto", "host", "kd"] = ...) -> Debugger:
    """
    Attach to a guest and return a `Debugger`.
    
    `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
    `"dmp"`. `connect` is the backend target: a socket path or address for
    kd/kdnet/gdb, or the dump file path for dmp. Without `connect`, the function
    uses the default of the backend, but dmp has no default and needs a path.
    kdnet needs `key`. `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
    
    For kd/kdnet/gdb, the function takes an instance lock for the target before
    it makes the backend, so a second live attach to the same target fails
    immediately without interfering with the handshake that the first session
    owns. The memory and dmp backends are passive.
    """

def decode_error(code: int) -> ErrorCode:
    """
    Decode an NTSTATUS, Win32, or HRESULT code into its name and description
    (`!error`). This function does not need a target.
    """
