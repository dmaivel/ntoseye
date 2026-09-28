"""
The ntoseye SDK's native module. Import from `ntoseye`, which re-exports
all of it.
"""

from collections.abc import Callable, Sequence
from ntoseye import Diagnostic
from typing import Any, Final, Literal, final

__version__: Final[str]
"""
The ntoseye release this extension was built as.
"""

build: Final[str]
"""
The git commit this extension was built from (`<commit>`,
`<commit>-dirty`, or `unknown`), to detect a stale extension in a
long-lived interpreter.
"""

@final
class Ace(BaseRecord):
    """
    An ACE in an ACL. The mask and SID read on their own, so a damaged
    body does not hide the header's type and flags.
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
        Its position in the ACL.
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
        Whether `ace_count` exceeds the decoder's bound, so only the
        first ACEs are listed.
        """
    @property
    def revision(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        Bytes.
        """
    @property
    def unknown_revision(self, /) -> bool:
        """
        Whether `revision` is not one this decoder knows; `aces` is then
        empty.
        """

@final
class AddressDescription(BaseRecord):
    """
    What an address belongs to: a loaded module (and section), a process
    VAD region, a kernel region, or nothing recognized.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int:
        """
        The address space it was looked up in.
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
    The loaded module an address lies in.
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
        The address's offset from `base`.
        """
    @property
    def size(self, /) -> int:
        """
        The module's image size.
        """

@final
class AddressTranslation(BaseRecord):
    """
    A virtual address translated through a DTB's page tables (`!vtop`).
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
        Whether nothing maps the page here and `physical` is the frame its section
        PTE holds (a page of a shared image or file view not yet touched).
        """
    @property
    def transition(self, /) -> bool:
        """
        Whether the leaf is a transition PTE: `physical` is a frame the guest still
        holds, but nothing maps it here and it cannot be written.
        """

@final
class AlpcClientPort(BaseRecord):
    """
    A client communication port a process holds: what it is connected to.
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
        Messages queued on the port; None when unreadable.
        """
    @property
    def server_owner(self, /) -> int |None:
        """
        The server's `_EPROCESS`; None when unreadable.
        """
    @property
    def server_owner_name(self, /) -> str |None: ...
    @property
    def server_port(self, /) -> int: ...
    @property
    def server_queued(self, /) -> int |None:
        """
        Messages queued on the server port; None when unreadable.
        """

@final
class AlpcConnection(BaseRecord):
    """
    A connection to an ALPC connection port: its communication info and
    the two ports it joins.
    """
    @property
    def client_owner(self, /) -> int:
        """
        The client's `_EPROCESS`.
        """
    @property
    def client_owner_name(self, /) -> str |None: ...
    @property
    def client_port(self, /) -> int: ...
    @property
    def client_queued(self, /) -> int |None:
        """
        Messages queued on the client port; None when unreadable.
        """
    @property
    def communication_info(self, /) -> int: ...
    @property
    def server_port(self, /) -> int: ...
    @property
    def server_queued(self, /) -> int |None:
        """
        Messages queued on the server port (main, large, and pending);
        None when unreadable.
        """

@final
class AlpcMessage(BaseRecord):
    """
    A `_KALPC_MESSAGE` (`!alpc /m`). A field is None when this build
    lacks it or it cannot be read.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def attributes(self, /) -> Record:
        """
        The `_KALPC_MESSAGE_ATTRIBUTES` fields this build has, by
        snake_case name.
        """
    @property
    def callback_id(self, /) -> int |None: ...
    @property
    def cancel_sequence_no(self, /) -> int |None: ...
    @property
    def client_process_id(self, /) -> int |None:
        """
        `PortMessage.ClientId`: the sender.
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
        The `LPC_*` name of the message type's low byte.
        """
    @property
    def owner_port(self, /) -> int: ...
    @property
    def owner_port_kind(self, /) -> str |None:
        """
        WinDbg's port type name of the owner port.
        """
    @property
    def pointers(self, /) -> Record:
        """
        The message's pointer fields this build has, by snake_case name.
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
        The queue port's owning `_EPROCESS`.
        """
    @property
    def port_queue_owner_name(self, /) -> str |None: ...
    @property
    def queue_port_type(self, /) -> int |None:
        """
        `u1.State`'s `QueuePortType` bits.
        """
    @property
    def queue_type(self, /) -> int |None:
        """
        `u1.State`'s `QueueType` bits.
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
        The one-bit `u1.s1` state flags set, by their PDB names.
        """
    @property
    def total_length(self, /) -> int |None: ...

@final
class AlpcOwnedPort(BaseRecord):
    """
    A connection port a process owns, and its connections.
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
    An `_ALPC_PORT` (`!alpc /p`). A field is None when this build lacks
    it or it cannot be read.
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
        How the connection-list walk ended; None when there was none.
        """
    @property
    def connections(self, /) -> list[AlpcConnection]:
        """
        A connection port's connections.
        """
    @property
    def direct_queue_length(self, /) -> int |None: ...
    @property
    def handle_count(self, /) -> int: ...
    @property
    def kind(self, /) -> str |None:
        """
        WinDbg's port type name (`ALPC_CONNECTION_PORT`, ...).
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
        The owning `_EPROCESS`.
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
        `u1.State`'s `Type` bits.
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
        The one-bit `u1.s1` state flags set, by their PDB names.
        """

@final
class AlpcProcessPorts(BaseRecord):
    """
    The ALPC ports a process holds handles to (`!alpc /lpp`).
    """
    @property
    def advertised_handles(self, /) -> int:
        """
        The handle count the table reports.
        """
    @property
    def connected(self, /) -> list[AlpcClientPort]:
        """
        Client ports the process holds.
        """
    @property
    def created(self, /) -> list[AlpcOwnedPort]:
        """
        Connection ports the process owns.
        """
    @property
    def process(self, /) -> ProcessIdentity: ...
    @property
    def scanned_handles(self, /) -> int: ...
    @property
    def server_ports(self, /) -> int:
        """
        Server communication ports it holds (its ends of connections to
        its own ports).
        """
    @property
    def skipped_entries(self, /) -> int:
        """
        Handle-table entries that could not be read.
        """

@final
class AlpcQueue(BaseRecord):
    """
    One of an ALPC port's message queues, or its wait queue.
    """
    @property
    def entries(self, /) -> list[int]:
        """
        The queued `_KALPC_MESSAGE`s, or for the wait queue the waiting
        `_ETHREAD`s.
        """
    @property
    def field(self, /) -> str:
        """
        The `_ALPC_PORT` list head, e.g. `PendingQueue`.
        """
    @property
    def key(self, /) -> str:
        """
        The queue's snake_case name.
        """
    @property
    def length(self, /) -> int |None:
        """
        The port's count for the queue; None when it keeps none.
        """
    @property
    def termination(self, /) -> ListEnd: ...

@final
class Amd64TrapFrame(BaseRecord):
    """
    The x64 registers a `_KTRAP_FRAME` saved. A register the frame's entry
    does not write is `None`; the nonvolatile r12-r15 live in the
    `_KEXCEPTION_FRAME`, not here.
    """
    @property
    def cs(self, /) -> int: ...
    @property
    def eflags(self, /) -> int: ...
    @property
    def error_code(self, /) -> int |None:
        """
        The exception's error code; stale for a vector that carries none.
        """
    @property
    def kind(self, /) -> str |None:
        """
        The entry that built the frame: `interrupt`, `exception`,
        `system call` or `Zw call`; `None` when unknown, and then only
        the machine frame and rbp are trusted.
        """
    @property
    def previous_irql(self, /) -> int |None:
        """
        The IRQL before the trap; only interrupts record it.
        """
    @property
    def previous_mode(self, /) -> int:
        """
        The mode the trap came from: 0 kernel, 1 user.
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
        Offset in the prolog of the end of the instruction it undoes.
        """
    @property
    def description(self, /) -> str:
        """
        The operation and its operands, e.g. `UWOP_SAVE_NONVOL rbx at +0x30`.
        """
    @property
    def op(self, /) -> int:
        """
        The `UWOP_*` operation.
        """
    @property
    def op_info(self, /) -> int:
        """
        The operation's info nibble.
        """
    @property
    def slot(self, /) -> int:
        """
        Index of the code's first slot.
        """

@final
class Amd64UnwindInfo(BaseRecord):
    """
    AMD64 `UNWIND_INFO`.
    """
    @property
    def code_count(self, /) -> int:
        """
        Unwind-code slots.
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
        The frame pointer register, when the function establishes one.
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
        Bytes of the prolog.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes of the structure: header, codes, and the handler RVA or the
        chained entry, without the handler's own data.
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
        `kernel_routine` as a symbol, when one resolves.
        """
    @property
    def normal_routine(self, /) -> Diagnostic[int |None]:
        """
        `NormalRoutine`; `None` inside for a special kernel APC.
        """
    @property
    def normal_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `normal_routine` as a symbol, when one resolves.
        """

@final
class ApcQueues(BaseRecord):
    """
    APC queues of every thread, a process's, or one thread's (`!apc`).
    """
    @property
    def layout_error(self, /) -> str |None:
        """
        Why the APC layout could not be resolved, if it could not.
        """
    @property
    def selector(self, /) -> str |ApcSelection:
        """
        `all`, `current_thread`, or the thread or process selected.
        """
    @property
    def threads(self, /) -> list[ApcThread]: ...
    @property
    def total(self, /) -> int:
        """
        APCs listed across `threads`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry bound.
        """

@final
class ApcSelection(BaseRecord):
    """
    The thread or process `!apc` was pointed at.
    """
    @property
    def kind(self, /) -> str:
        """
        `thread`, `process`, or `number` (not yet resolved to either).
        """
    @property
    def value(self, /) -> int:
        """
        The ETHREAD/KTHREAD/TID, or PID/EPROCESS, given.
        """

@final
class ApcThread(BaseRecord):
    """
    A thread's kernel-mode and user-mode APC queues.
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
        Why the thread's APC state could not be read, if it could not.
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
        The index of the epilog's first unwind code.
        """
    @property
    def start_offset(self, /) -> int:
        """
        The epilog's start, in bytes from the function's.
        """

@final
class Arm64PackedUnwind(BaseRecord):
    """
    ARM64 unwind data packed into the `.pdata` entry (flag 1 or 2): a
    canonical prolog, listed as the codes it stands for.
    """
    @property
    def codes(self, /) -> list[Arm64UnwindCode]: ...
    @property
    def cr(self, /) -> int:
        """
        The `CR` field: whether and how the frame chain and link register
        are saved.
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
        The frame's size, in bytes.
        """
    @property
    def homes_arguments(self, /) -> bool:
        """
        Whether the prolog homes the argument registers.
        """
    @property
    def reg_f(self, /) -> int:
        """
        The `RegF` field: saved non-volatile floating-point registers.
        """
    @property
    def reg_i(self, /) -> int:
        """
        The `RegI` field: saved non-volatile integer registers.
        """

@final
class Arm64TrapFrame(BaseRecord):
    """
    The ARM64 registers a `_KTRAP_FRAME` saved. The frame holds x0-x18,
    fp (x29) and lr (x30); x19-x28 are `None`.
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
        The mode the trap came from: 0 kernel, 1 user.
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
        Its name and the prolog instruction it stands for.
        """
    @property
    def index(self, /) -> int:
        """
        Its first byte's index in the code bytes.
        """

@final
class Arm64XdataUnwind(BaseRecord):
    """
    An ARM64 `.xdata` unwind record.
    """
    @property
    def code_words(self, /) -> int:
        """
        32-bit words of unwind codes.
        """
    @property
    def codes(self, /) -> list[Arm64UnwindCode]: ...
    @property
    def epilog_count(self, /) -> int: ...
    @property
    def epilog_in_header(self, /) -> bool:
        """
        The `E` bit: a single epilog described in the header.
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
        Bytes of the record, the handler's RVA included.
        """
    @property
    def version(self, /) -> int: ...

@final
class AttachedDevice(BaseRecord):
    """
    A device on a device's `AttachedDevice` stack.
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
    A row of the backend's capability matrix.
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
    An immutable, ordered set of named fields with dict access: the base of
    `Record` and of every typed result class (`PciFunction`, ...), whose
    properties type each field.
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
        The field, or `default` when the record has no such field.
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
        A plain nested `dict` (records and diagnostics converted throughout),
        the shape the MCP `format=json` surface returns.
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
        The `PoolBigPageTable` entry's address.
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
        The requested address's offset into the allocation.
        """
    @property
    def pattern(self, /) -> int: ...
    @property
    def pool_flags(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        Allocation size in bytes.
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
    A blackbox stream (pnp, ntfs, bsd, winlogon) of a crash dump. Its
    payload is never parsed.
    """
    @property
    def available(self, /) -> bool:
        """
        Whether the payload is available; always `False`.
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
        Whether the payload was parsed; always `False`.
        """
    @property
    def present(self, /) -> bool |None:
        """
        Whether the stream is recorded; `None` when the dump exposes
        no stream directory to tell.
        """
    @property
    def reason(self, /) -> str:
        """
        Why the payload is not available.
        """
    @property
    def size(self, /) -> int |None:
        """
        The stream's size in bytes, when recorded.
        """

class Breakpoint:
    """
    A breakpoint handle. Breakpoints outlive target rebuilds (symbolic ones
    re-resolve after a reboot), so the handle is not generation-stamped; it
    goes invalid only when the breakpoint is deleted.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def action(self, /) -> str |None:
        """
        Optional command action (`do` in WinDbg).
        """
    @property
    def address(self, /) -> int:
        """
        Address of the latest resolution.
        """
    @property
    def condition(self, /) -> str |None:
        """
        Optional expression condition.
        """
    @condition.setter
    def condition(self, /, condition: str |None) -> None:
        """
        Assigning an expression while a `when=` callback is attached raises
        `ValueError`, as passing both to `add()` does.
        """
    def delete(self, /) -> None:
        """
        Remove this breakpoint.
        """
    @property
    def enabled(self, /) -> bool:
        """
        Whether this breakpoint is enabled.
        """
    @enabled.setter
    def enabled(self, /, enabled: bool) -> None: ...
    @property
    def hit_count(self, /) -> int:
        """
        Number of physical hits.
        """
    @property
    def id(self, /) -> int:
        """
        Stable breakpoint id.
        """
    @property
    def one_shot(self, /) -> bool:
        """
        Whether the breakpoint is removed after its first surfaced hit.
        """
    @one_shot.setter
    def one_shot(self, /, one_shot: bool) -> None: ...
    @property
    def pass_count(self, /) -> int:
        """
        Requested hit count before surfacing.
        """
    @pass_count.setter
    def pass_count(self, /, pass_count: int) -> None: ...
    @property
    def process(self, /) -> Process |None:
        """
        Process restriction, if the breakpoint is process-scoped.
        """
    @property
    def processor(self, /) -> int |None:
        """
        Processor filter, if any.
        """
    @property
    def remaining_pass_count(self, /) -> int:
        """
        Hits remaining before this breakpoint surfaces.
        """
    @property
    def resolved(self, /) -> bool:
        """
        Whether the site is armed at an address. A symbolic breakpoint whose
        module is not loaded yet stays unresolved until it loads.
        """
    @property
    def specification(self, /) -> str |None:
        """
        Symbol or source identity used to create this breakpoint.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        Resolved display symbol, if known.
        """
    @property
    def temporary(self, /) -> bool:
        """
        Whether this is a temporary run-to breakpoint.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        Windows thread restriction, if present.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The breakpoint's state as a plain `dict`, the shape MCP renders.
        """
    @property
    def valid(self, /) -> bool:
        """
        Whether the breakpoint is still present in this session.
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
        Commands run when it breaks.
        """
    @property
    def address(self, /) -> int |None:
        """
        None while a symbolic or source breakpoint is deferred.
        """
    @property
    def condition(self, /) -> str |None:
        """
        The condition expression a hit must satisfy.
        """
    @property
    def deferred(self, /) -> bool:
        """
        Whether a symbolic or source specification awaits resolution.
        """
    @property
    def enabled(self, /) -> bool: ...
    @property
    def hit_count(self, /) -> int: ...
    @property
    def id(self, /) -> int: ...
    @property
    def one_shot(self, /) -> bool:
        """
        Whether the breakpoint is removed after its first break.
        """
    @property
    def pass_count(self, /) -> int:
        """
        The requested hit number; 0 and 1 both break on the first hit.
        """
    @property
    def processor(self, /) -> int |None:
        """
        The processor that may surface a hit (`/c`), if restricted.
        """
    @property
    def remaining_pass_count(self, /) -> int:
        """
        Hits left before the breakpoint breaks.
        """
    @property
    def resolved(self, /) -> bool:
        """
        Whether the breakpoint resolved to an address; tells a deferred
        breakpoint from a disabled one.
        """
    @property
    def scope(self, /) -> str:
        """
        `global`, or the process it is limited to (`name (pid)`).
        """
    @property
    def specification(self, /) -> str |None:
        """
        The symbolic or source specification (`bu`/`bm`), kept across
        re-resolution.
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
        The thread that may surface a hit (`/t`: `tid N` or `ethread
        0x...`), if restricted.
        """
    @property
    def watch_access(self, /) -> str |None:
        """
        `write` or `read_write` for a data watchpoint, None for a code
        breakpoint.
        """
    @property
    def watch_length(self, /) -> int |None:
        """
        The watched width in bytes, None for a code breakpoint.
        """

@final
class Breakpoints:
    """
    Code breakpoints and data watchpoints, keyed by id (`dbg.breakpoints`).
    """
    def __contains__(self, id: int, /) -> bool: ...
    def __getitem__(self, id: int, /) -> Breakpoint:
        """
        Look up a breakpoint id, raising `KeyError` when it is absent.
        """
    def __iter__(self, /) -> BreakpointIterator:
        """
        Iterate a fresh snapshot of breakpoint handles.
        """
    def __len__(self, /) -> int:
        """
        Number of live breakpoints.
        """
    def add(self, /, target: int |str, condition: str |None = None, *, hardware: bool = False, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a code breakpoint at an address or symbolic spec.
        
        `hardware=True` arms a debug-register execute breakpoint instead of
        patching code: the target resolves to an address once, now, and the
        site does not re-resolve after a module reload or reboot. It is the
        only kind the secure kernel (VTL1) accepts, e.g.
        `add(dbg.secure_kernel.symbols["securekernel!Func"], hardware=True)`.
        """
    def add_pattern(self, /, pattern: str, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None, limit: int = 256) -> list[Breakpoint]:
        """
        Add symbol-identity breakpoints for matching glob names (`bm`).
        """
    def add_source(self, /, file: str, line: int, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> list[Breakpoint]:
        """
        Add source breakpoints for every address matching `file:line`.
        """
    def get(self, /, id: int) -> Breakpoint |None:
        """
        Look up a breakpoint id, returning `None` when it is absent.
        """
    def watch(self, /, target: int |str, *, access: Literal["write", "read_write"] = ..., length: int = 1, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Watchpoint:
        """
        Add a hardware data watchpoint.
        """

@final
class Bugcheck(BaseRecord):
    """
    A decoded bugcheck (BSOD): its code, the four parameters, and the
    faulting instruction when one was identified.
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
        What the bugcheck means; `None` for a code without a description.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The driver responsible, from the dump's record or the fault site.
        """
    @property
    def fault(self, /) -> BugcheckFault |None:
        """
        The faulting instruction; `None` when none was identified.
        """
    @property
    def name(self, /) -> str:
        """
        The symbolic name (`IRQL_NOT_LESS_OR_EQUAL`).
        """
    @property
    def source(self, /) -> str |None:
        """
        Where the data was found instead of its usual place (a pointer in
        `nt!KiBugCheckData` to the real slots); `None` normally.
        """
    @property
    def trap_frames(self, /) -> list[BugcheckTrapFrame]:
        """
        Trap frames the parameters point to.
        """

@final
class BugcheckArgument(BaseRecord):
    """
    One bugcheck parameter and what it means for the code.
    """
    @property
    def description(self, /) -> str:
        """
        What this parameter holds for the bugcheck code; empty when the
        code documents none.
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
        The driver containing `ip`; `None` outside every loaded driver.
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
    A trap frame a bugcheck parameter points to: either its decoded
    registers or why decoding failed.
    """
    @property
    def address(self, /) -> int:
        """
        Where the frame was read from.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why decoding failed; `None` when it succeeded.
        """
    @property
    def frame(self, /) -> Amd64TrapFrame |Arm64TrapFrame |None:
        """
        The saved registers; `None` when decoding failed.
        """
    @property
    def rip_symbol(self, /) -> str |None:
        """
        The symbol at the interrupted instruction.
        """

@final
class CacheAttribute(BaseRecord):
    """
    A PFN's `CacheAttribute`.
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
    A file the cache manager maps a view of.
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
        Present bytes in the mapped views.
        """
    @property
    def valid_data_length(self, /) -> Diagnostic[int]:
        """
        Bytes.
        """

@final
class CallTrace(BaseRecord):
    """
    A `wt` call trace: why it stopped, the instructions it stepped, and
    the call tree.
    """
    @property
    def end(self, /) -> str:
        """
        `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
        `failed`; anything but `returned` leaves a partial tree.
        """
    @property
    def error(self, /) -> str |None:
        """
        What failed, for `failed`.
        """
    @property
    def instructions(self, /) -> int:
        """
        Instructions single-stepped.
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
        The calls it made.
        """
    @property
    def instructions(self, /) -> int:
        """
        Instructions stepped in the function itself.
        """
    @property
    def name(self, /) -> str:
        """
        The called function.
        """

@final
class CodeViewRecord(BaseRecord):
    """
    A CodeView debug record: the PDB an image was built with.
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
        The PDB path the linker recorded.
        """
    @property
    def signature(self, /) -> int |None:
        """
        The PDB timestamp signature, for `NB10`.
        """

@final
class ControlArea(BaseRecord):
    """
    A section's `_CONTROL_AREA`, its segment, and its subsections (`!ca`).
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
        Why the subsection walk stopped before a null `NextSubsection`;
        `None` when it reached it.
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
        `None` for a data file's segment, whose prototype PTEs are in its
        subsections.
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
    One processor, identified by its backend vCPU id (such as `"p1.1"`).
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def gdt(self, /) -> Gdt:
        """
        Decode this processor's GDT (`!gdt`).
        """
    @property
    def id(self, /) -> str:
        """
        The backend vCPU id.
        """
    def idt(self, /, vector: int |None = None) -> Idt:
        """
        Decode one IDT vector, or the bounded full table (`!idt`).
        """
    def info(self, /) -> CpuInfo:
        """
        Read processor vendor, family, model, speed, and feature bits (`!cpuinfo`).
        """
    def irql(self, /) -> Irql:
        """
        Read this processor's current IRQL (`!irql`).
        """
    @property
    def memory(self, /) -> Memory:
        """
        Memory through the page tables this processor has loaded (its CR3)
        when read: the kernel's or a process's, a VTL1 root (read-only), or a
        root outside NT, such as the Windows hypervisor's at a vCPU halted in
        it (read-only).
        """
    @property
    def msr(self, /) -> Msrs:
        """
        Model-specific registers: `cpu.msr[0xC0000082]`, `cpu.msr["IA32_LSTAR"]`.
        """
    def pcr(self, /) -> Pcr:
        """
        Decode this processor's KPCR and KPRCB essentials (`!pcr`).
        """
    def prcb(self, /) -> Prcb:
        """
        Decode this processor's `_KPRCB` (`!prcb`).
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process whose page tables are loaded on this processor.
        """
    @property
    def registers(self, /) -> Registers:
        """
        This processor's live register file (writable while halted in NT;
        read-only at a recognized VTL1 stop).
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer (needs a halted target).
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        For a vCPU halted in the Windows hypervisor (VBS), the VTL states the
        hypervisor saved for its virtual processor (`.vtlcxr`), VTL0's first:
        where each left off, its control and segment registers, and the exit
        it last took. Needs the VM's `hv-evmcs`; empty otherwise, or when the
        saved state fails validation.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `rip`, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread running on this processor.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The processor as a plain `dict`, the shape MCP renders.
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
    A processor's vendor, family, model, speed, and feature bits
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
        Where the values came from: `_KPRCB` or `triage-dump PRCB metadata`.
        """
    @property
    def stepping(self, /) -> Diagnostic[int]: ...
    @property
    def triage_fallback(self, /) -> CpuTriageFallback |None:
        """
        Triage metadata, present when the KPRCB could not be found.
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
    The dump's triage PRCB metadata, used when the KPRCB is unreadable.
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
    The target's processors, in backend vCPU order (`dbg.cpus`); listing
    them needs a halted target.
    """
    def __getitem__(self, index: int, /) -> Cpu: ...
    def __iter__(self, /) -> CpuIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, index: int) -> Cpu |None: ...

@final
class CrashContext(BaseRecord):
    """
    The process and thread a triage dump recorded as crashing; a field
    the dump does not record is `None`.
    """
    @property
    def create_time(self, /) -> str |None:
        """
        When the process was created (ISO 8601 UTC); also `None` when the
        recorded time does not convert.
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
    The module the available evidence blames for the crash.
    """
    @property
    def confidence(self, /) -> str:
        """
        `low`, `medium`, or `high`.
        """
    @property
    def evidence(self, /) -> list[CulpritEvidence]:
        """
        What points at the module.
        """
    @property
    def module(self, /) -> str: ...

@final
class CulpritEvidence(BaseRecord):
    """
    One piece of evidence behind a culprit attribution.
    """
    @property
    def address(self, /) -> int |None:
        """
        The address the evidence rests on, when it is one.
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
        Whether lines the caller had not read were evicted from the
        bounded ring.
        """
    @property
    def lines(self, /) -> list[DebugLogLine]: ...
    @property
    def next_seq(self, /) -> int:
        """
        The cursor to pass next time to resume after the last line.
        """

@final
class DebugLogLine(BaseRecord):
    """
    A captured line of guest debug output (DbgPrint, kernel printf).
    """
    @property
    def seq(self, /) -> int:
        """
        Monotonic sequence number, the read cursor.
        """
    @property
    def text(self, /) -> str: ...
    @property
    def timestamp_ms(self, /) -> int:
        """
        Host wall-clock time the line completed, in milliseconds since
        the Unix epoch.
        """

@final
class Debugger:
    """
    A live debugging session. As a context manager, leaving the `with` block
    closes it (`close()`): every breakpoint is removed, the target resumes, and
    the session ends.
    
    Usable from any Python thread: calls are serialized on the session's own
    thread, and a call that waits (`run()`, `wait()`) releases the GIL. Ctrl+C
    (`KeyboardInterrupt`) during a call ends a wait, step, or trace early and
    raises; during a resuming `command()` it breaks in, as in the REPL. Between
    calls the session keeps servicing the guest, resuming wrong-process and
    false-condition breakpoint hits so the guest never sits frozen. A debugger
    handed to a REPL custom command is valid only on the REPL's thread, for
    that command.
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
        The backend's capability matrix: which operations the transport
        supports.
        """
    def close(self, /) -> None:
        """
        Remove every breakpoint, leave the target running, and end the
        session: the connection and the target's single-instance lock are
        released, so the target can be attached again, and this debugger and
        its handles raise from then on. Closing again does nothing. On failure
        the target is left halted, the session stays open, and the error is
        raised. A borrowed (REPL command) debugger does not own the session
        and leaves it alone.
        """
    @property
    def coherent(self, /) -> bool:
        """
        False after a reboot until the kernel's module list exists: kernel
        symbols and breakpoints work, process/module enumeration does not yet.
        """
    def command(self, /, line: str, timeout: float |None = None) -> str:
        """
        Run a REPL command line and return its text output (styling stripped).
        Commands that resume the target wait for the next stop, up to
        `timeout` seconds; the stop is then `dbg.stop`. Command loops and
        `.sleep` end when `timeout` elapses too.
        """
    def cont(self, /, disposition: Literal["handled", "not_handled"] = ...) -> None:
        """
        Resume without waiting, acknowledging the current exception as
        `handled` or `not_handled` (KD only).
        """
    @property
    def cpus(self, /) -> Cpus:
        """
        The target's processors (vCPUs): `cpus[0].registers.rip`.
        """
    def crash(self, /) -> None:
        """
        Crash the target on purpose (`.crash`), producing a bugcheck stop.
        """
    def debug_log(self, /, since: int = 0) -> DebugLog:
        """
        Captured guest debug output (DbgPrint) since sequence `since`. Pass
        the previous `next_seq` to poll only new lines.
        """
    @property
    def drivers(self, /) -> Drivers:
        """
        Driver objects from the object manager's `Driver` directory:
        `drivers["Disk"]`, `.at(addr)`.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger (MASM) expression in kernel scope to an integer;
        registers are the stopped vCPU's.
        """
    @property
    def exceptions(self, /) -> Exceptions:
        """
        Exception stop policies (`sx*`): `.set(code, mode)`, iteration, `.reset()`.
        """
    @property
    def generation(self, /) -> int:
        """
        How many times the guest has been rebuilt (reboots). Handles from an
        older generation raise `StaleHandleError`; cache this beside raw
        addresses to know when they went stale.
        """
    @property
    def inspect(self, /) -> Inspect:
        """
        System-wide reports and decode-by-address helpers (`!vm`, `!pool`, ...).
        """
    def interrupt(self, /) -> Stop:
        """
        Break into the running target and return the resulting stop.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Kernel virtual memory: the kernel's own page tables. User addresses
        are not mapped here; read them through `process.memory`.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Loaded kernel modules: `modules["nt"]`, iteration, `.at(addr)`.
        """
    def notices(self, /) -> list[str]:
        """
        Drain the diagnostics the debugger raised since the last call (a
        breakpoint that failed to re-arm, a reclaimed breakpoint slot, host
        memory that stopped matching after a reload).
        """
    @property
    def physical(self, /) -> Memory:
        """
        Guest-physical memory, untranslated.
        """
    @property
    def processes(self, /) -> Processes:
        """
        Running processes keyed by PID: `processes[4]`, `.find(name)`.
        """
    def reboot(self, /) -> None:
        """
        Reboot the target (`.reboot`). The next stop is a `Stop.Reboot`.
        """
    def reload(self, /) -> None:
        """
        Rebuild guest state now (rediscover the kernel). Stops already do this
        when the backend reports a reload; this forces it.
        """
    def run(self, /, timeout: float |None = None, *, disposition: Literal["handled", "not_handled"] = ...) -> Stop |None:
        """
        Resume and wait for the next stop, auto-resuming past wrong-process and
        false-conditional hits. Returns the `Stop`, or `None` if the target is
        still running after `timeout` seconds.
        """
    def run_to(self, /, target: int |str, timeout: float |None = None, *, step: Literal["over", "into"] |None = None) -> Stop |None:
        """
        Run until `target` (an address, or a symbolic `module!name[+off]`) is
        reached (`g <addr>`), or with `step="over"`/`"into"` single-step there
        (`pa`/`ta`). Other stops en route are returned as they are; with
        `timeout`, an unreached target is interrupted where it is.
        """
    @property
    def secure_kernel(self, /) -> SecureKernel:
        """
        The VBS secure kernel (VTL1): read-only `memory`, `symbols`, `types`,
        `modules`, and `trustlets`. Discovered on first use from host memory;
        raises `NtoseyeError` when VBS is not running or the backend cannot
        read host memory. Experimental.
        """
    def step(self, /, until: Literal["call", "ret", "branch"] |None = None) -> Stop:
        """
        Single-step one instruction, or with `until` ("call", "ret", "branch")
        step into until the next such instruction (`tc`/`tt`/`th`).
        """
    def step_out(self, /) -> Stop:
        """
        Run until the current function returns (`gu`).
        """
    def step_over(self, /, until: Literal["call", "ret", "branch"] |None = None) -> Stop:
        """
        Step over the current instruction, or with `until` step over until the
        next call/ret/branch (`pc`/`pt`/`ph`).
        """
    @property
    def stop(self, /) -> Stop |None:
        """
        The current stop while the target is halted, `None` while it runs.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
        `search(query)`, the symbol and source paths.
        """
    @property
    def threads(self, /) -> Threads:
        """
        Every Windows thread keyed by TID: `threads[tid]`, `.at(ethread)`.
        """
    def trace_calls(self, /, limit: int = 10000) -> CallTrace:
        """
        Trace calls until the current function returns (`wt`), single-stepping
        at most `limit` instructions: `{end, error, instructions, root}`, where
        `root` is the call tree and `end` says why tracing stopped.
        """
    @property
    def types(self, /) -> Types:
        """
        Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`.
        """
    def wait(self, /, timeout: float |None = None) -> Stop |None:
        """
        Wait for the next stop without resuming. Returns the current stop at
        once when already halted, `None` if still running after `timeout`.
        """
    def write_dump(self, /, path: str) -> int:
        """
        Write a full `PAGEDU64` kernel dump of the halted target to `path`
        (`.dump /f`). Returns the number of unreadable pages zero-filled.
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
        The table's limit: its size in bytes, minus one.
        """

@final
class DevNode(BaseRecord):
    """
    A decoded `_DEVICE_NODE`, optionally with its flat subtree
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
        The IRP PnP is waiting on; 0 for none.
        """
    @property
    def previous_state(self, /) -> int: ...
    @property
    def previous_state_name(self, /) -> str: ...
    @property
    def problem(self, /) -> int:
        """
        The `CM_PROB_*` problem code; 0 for none.
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
        `StateHistoryEntry`: the ring's next slot.
        """
    @property
    def state_name(self, /) -> str: ...
    @property
    def subtree(self, /) -> list[DevNodeSummary]:
        """
        The nodes below it, depth first; empty unless recursion was
        requested.
        """
    @property
    def subtree_truncated(self, /) -> bool:
        """
        Whether the subtree walk stopped at its bound.
        """
    @property
    def user_flags(self, /) -> int: ...

@final
class DevNodeHistoryState(BaseRecord):
    """
    A nonzero entry of a device node's `StateHistory` ring.
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
    A device node's identity and state, as subtree and triage listings
    show it.
    """
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_NODE`.
        """
    @property
    def depth(self, /) -> int:
        """
        `Level`: its depth in the device tree.
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
        The IRP PnP is waiting on; 0 for none.
        """
    @property
    def problem(self, /) -> int:
        """
        The `CM_PROB_*` problem code; 0 for none.
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
        The device layered directly above; 0 when none.
        """
    @property
    def attached_stack(self, /) -> list[AttachedDevice]:
        """
        The `AttachedDevice` chain, bottom up.
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
        The driver's next device; 0 at the end.
        """
    @property
    def object(self, /) -> int: ...
    @property
    def via_pointer(self, /) -> bool:
        """
        Whether the argument pointed at a pointer to the device object.
        """

@final
class DeviceStack(BaseRecord):
    """
    A device stack, top filter to PDO, and the PDO's device node
    (`!devstack`).
    """
    @property
    def argument(self, /) -> int:
        """
        The address given: a device object (or a pointer to one) or a
        device node.
        """
    @property
    def entries(self, /) -> list[DeviceStackLayer]:
        """
        The stack, top filter first.
        """
    @property
    def pdo_devnode(self, /) -> DevNodeSummary |None:
        """
        `None` when the PDO has no device node or it could not be read
        (`pdo_devnode_error` says why).
        """
    @property
    def pdo_devnode_error(self, /) -> str |None: ...
    @property
    def requested_device(self, /) -> int:
        """
        The device object the stack was walked from.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the stack walk stopped at its bound.
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
        Whether this is the device the stack was requested for.
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
        The resolved branch or rip-relative target, when there is one.
        """
    @property
    def hex(self, /) -> str:
        """
        The instruction's bytes, in hex.
        """
    @property
    def ip(self, /) -> int: ...

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
        `deferred_routine` as a symbol, when one resolves.
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
        0 for the normal queue, 1 for the threaded one.
        """
    @property
    def termination(self, /) -> ListEnd:
        """
        How the list walk ended.
        """

@final
class DpcQueues(BaseRecord):
    """
    Every processor's queued DPCs (`!dpcs`).
    """
    @property
    def errors(self, /) -> list[SchedulerError]: ...
    @property
    def queues(self, /) -> list[DpcQueue]:
        """
        Non-empty queues.
        """
    @property
    def total(self, /) -> int:
        """
        DPCs listed across `queues`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry bound.
        """

@final
class Driver:
    """
    One `_DRIVER_OBJECT`, with the device objects it created.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def devices(self, /) -> list[Device]:
        """
        The device objects this driver created.
        """
    def inspect(self, /) -> DriverObject:
        """
        Inspect the `_DRIVER_OBJECT`, its devices, and dispatch table.
        """
    @property
    def name(self, /) -> str:
        """
        The driver object's name.
        """
    @property
    def object(self, /) -> int:
        """
        The `_DRIVER_OBJECT` address.
        """
    @property
    def size(self, /) -> int:
        """
        The driver image's size.
        """
    @property
    def start(self, /) -> int:
        """
        The driver image's base address.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The driver object as a plain `dict`, the shape MCP renders.
        """

@final
class DriverDeviceLink(BaseRecord):
    """
    A device on a driver's `DeviceObject`/`NextDevice` chain.
    """
    @property
    def attached(self, /) -> int:
        """
        `AttachedDevice`: the device layered above it; 0 when none.
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
        `NextDevice`: the driver's next device; 0 at the end.
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
        The 28 `IRP_MJ_*` dispatch routines, by code.
        """
    @property
    def driver_section(self, /) -> int: ...
    @property
    def driver_size(self, /) -> int:
        """
        The driver image's size in bytes.
        """
    @property
    def driver_start(self, /) -> int: ...
    @property
    def driver_unload(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        `DriverName`; None when unreadable.
        """
    @property
    def object(self, /) -> int: ...
    @property
    def via_pointer(self, /) -> bool:
        """
        Whether the argument pointed at a pointer to the driver object.
        """

@final
class DriverObjectSummary(BaseRecord):
    """
    A `_DRIVER_OBJECT` as listed in the object manager's Driver and
    FileSystem directories (`drivers`).
    """
    @property
    def device_object(self, /) -> int:
        """
        The first device on its chain; 0 when none.
        """
    @property
    def driver_size(self, /) -> int:
        """
        The driver image's size in bytes.
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
    Driver objects from the object manager's `Driver` directory, keyed by
    name (`dbg.drivers`).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Driver: ...
    def __iter__(self, /) -> DriverIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Driver |None:
        """
        Find the driver object or image containing `addr`.
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
        The same code, as hex.
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
    The system a crash dump was taken from, from its system-info stream.
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
        When the dump was taken (ISO 8601 UTC); `None` when unrecorded.
        """
    @property
    def system_up_time_secs(self, /) -> int |None:
        """
        Seconds the system had been up; `None` when unrecorded.
        """

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
        The facility the code encodes.
        """
    @property
    def kind(self, /) -> str:
        """
        `NTSTATUS`, `HRESULT`, `Win32`, or `unknown`.
        """
    @property
    def name(self, /) -> str:
        """
        The code's symbolic name.
        """
    @property
    def severity(self, /) -> str |None:
        """
        `success`, `informational`, `warning`, or `error`; `None` for a
        Win32 code.
        """
    @property
    def win32_code(self, /) -> int |None:
        """
        The Win32 error: the code itself, or the one a
        `HRESULT_FROM_WIN32` code wraps.
        """
    @property
    def win32_name(self, /) -> str |None:
        """
        That Win32 error's name.
        """

@final
class EtwBuffer(BaseRecord):
    """
    A logger's trace buffer (`_WMI_BUFFER_HEADER`).
    """
    @property
    def address(self, /) -> int: ...
    @property
    def current_offset(self, /) -> int: ...
    @property
    def data_end(self, /) -> int:
        """
        Bytes of the buffer holding the header and complete events.
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
        Raw timestamp in the logger's clock.
        """

@final
class EtwEvent(BaseRecord):
    """
    An event record decoded out of a trace buffer. Fields its header
    kind lacks are `None`.
    """
    @property
    def activity_id(self, /) -> str |None: ...
    @property
    def buffer(self, /) -> int:
        """
        The buffer it came from.
        """
    @property
    def descriptor(self, /) -> EtwEventDescriptor |None: ...
    @property
    def event_class(self, /) -> EtwEventClass |None:
        """
        A classic event's class; the JSON key is `class`.
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
        The hook id's `EVENT_TRACE_GROUP_*` name, when it is a known one.
        """
    @property
    def guid(self, /) -> str |None:
        """
        Provider (`EVENT_HEADER`), event class (`EVENT_TRACE_HEADER`) or
        message (`MESSAGE_TRACE_HEADER`) GUID.
        """
    @property
    def header(self, /) -> str:
        """
        The trace header it starts with (`EVENT_HEADER`, ...).
        """
    @property
    def header_type(self, /) -> int: ...
    @property
    def hook_id(self, /) -> int |None:
        """
        Kernel hook id (group << 8 | type) of system and perfinfo events.
        """
    @property
    def message(self, /) -> EtwEventMessage |None: ...
    @property
    def offset(self, /) -> int:
        """
        Offset of the record in its buffer.
        """
    @property
    def payload(self, /) -> str:
        """
        The event's user data, as hex.
        """
    @property
    def process_id(self, /) -> int |None: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        Record size, header included (unaligned).
        """
    @property
    def system_time(self, /) -> int |None:
        """
        FILETIME, when the logger's clock converts to one.
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
        Raw timestamp in the logger's clock; a WPP message without
        `TRACE_MESSAGE_TIMESTAMP` has none.
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
    A logger's in-memory events, oldest first (`!wmitrace.logdump`).
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
        Buffers skipped whole (compressed) and walks that stopped early.
        """
    @property
    def list_stop(self, /) -> str |None:
        """
        Why the `GlobalList` walk ended before returning to its head;
        `None` when it completed.
        """
    @property
    def logger(self, /) -> EtwLogger: ...
    @property
    def message_format_note(self, /) -> str |None:
        """
        Why some WPP messages have no `text`; `None` when every one has.
        """
    @property
    def qpc_frequency(self, /) -> int |None:
        """
        QPC frequency used for PerfCounter timestamps.
        """
    @property
    def total_events(self, /) -> int:
        """
        Events found before a count kept the most recent.
        """

@final
class EtwEventIssue(BaseRecord):
    """
    A buffer whose events could not all be decoded.
    """
    @property
    def buffer(self, /) -> int: ...
    @property
    def offset(self, /) -> int:
        """
        Where in the buffer the walk stopped.
        """
    @property
    def reason(self, /) -> str: ...

@final
class EtwEventMessage(BaseRecord):
    """
    The fields a `MESSAGE_TRACE_HEADER` carries after itself, as its
    `TRACE_MESSAGE_*` option flags select; each `None` when not selected.
    The TMF fields are `None` when no loaded PDB declares the message's
    trace message format (TMF).
    """
    @property
    def component_id(self, /) -> int |None: ...
    @property
    def flags(self, /) -> str |None:
        """
        The TMF's trace flag name.
        """
    @property
    def format_error(self, /) -> str |None:
        """
        Why the payload does not fit the TMF's argument types.
        """
    @property
    def function(self, /) -> str |None:
        """
        The function that traced it.
        """
    @property
    def guid(self, /) -> str |None: ...
    @property
    def level(self, /) -> str |None:
        """
        The TMF's trace level (`TRACE_LEVEL_ERROR`, or a number).
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
        The TMF's provider (component) name.
        """
    @property
    def sequence(self, /) -> int |None: ...
    @property
    def text(self, /) -> str |None:
        """
        The message rendered from its TMF and the payload.
        """

@final
class EtwExtendedData(BaseRecord):
    """
    An `EVENT_HEADER` extended data item.
    """
    @property
    def data(self, /) -> str:
        """
        The item's bytes, as hex.
        """
    @property
    def type(self, /) -> int:
        """
        `EVENT_HEADER_EXT_TYPE_*`.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The type's name, when it is a known one.
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
        Buffers taken from the free pool (`number_of_buffers -
        buffers_available`): current on a processor, full, or being
        flushed.
        """
    @property
    def buffers_written(self, /) -> int: ...
    @property
    def clock(self, /) -> str:
        """
        What event timestamps count, named.
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
        `LogFileName`; `None` when its buffer is unreadable.
        """
    @property
    def logger_id(self, /) -> int: ...
    @property
    def logger_mode(self, /) -> int: ...
    @property
    def logger_mode_names(self, /) -> list[str]:
        """
        The `EVENT_TRACE_*_MODE` bits set in `logger_mode`.
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
        `LoggerName`; `None` when its buffer is unreadable (pool freed or
        paged out while a session stops).
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
        `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`); `None` when
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
        Why the `GlobalList` walk ended before returning to its head;
        `None` when it completed.
        """
    @property
    def logger(self, /) -> EtwLogger: ...

@final
class EtwLoggerTable(BaseRecord):
    """
    Every active ETW logger of the host silo (`!wmitrace.strdump`).
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
        The code's WinDbg alias (`av`, `bp`, ...), when it has one.
        """
    @property
    def code(self, /) -> int:
        """
        The exception code.
        """
    @property
    def command(self, /) -> str |None:
        """
        Commands run when the exception arrives.
        """
    @property
    def disposition(self, /) -> str |None:
        """
        An explicit final action: `break`, or continue as `handled` or
        `not_handled`; None for the mode's default.
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
        Where the record was read from; `None` for the current event's
        record, reconstructed from the stop rather than read from memory.
        """

@final
class Exceptions:
    """
    Per-exception stop policies (`dbg.exceptions`, `sx*`).
    """
    def __iter__(self, /) -> ExceptionPolicyIterator:
        """
        Iterate configured exception-policy records.
        """
    def __len__(self, /) -> int:
        """
        Number of configured policies.
        """
    def __repr__(self, /) -> str: ...
    def reset(self, /) -> None:
        """
        Remove all configured policies; ordinary exceptions break by default.
        """
    def set(self, /, code: int |str, mode: Literal["break", "second_chance", "notify", "ignore"], *, disposition: Literal["handled", "not_handled"] |None = None) -> None:
        """
        Configure an exception's stop policy (`sxe`/`sxd`/`sxn`/`sxi`).
        """

@final
class ExecutiveObject(BaseRecord):
    """
    An executive object: its `_OBJECT_HEADER`, type, and name, and a
    directory's entries (`!object`).
    """
    @property
    def body(self, /) -> int: ...
    @property
    def entries(self, /) -> list[ObjectDirectoryEntry] |None:
        """
        A directory's entries; None for any other object.
        """
    @property
    def handle_count(self, /) -> int: ...
    @property
    def header(self, /) -> int: ...
    @property
    def info_mask(self, /) -> int |None:
        """
        The header's `InfoMask` (which optional headers precede it).
        """
    @property
    def input(self, /) -> int:
        """
        The address given.
        """
    @property
    def mode(self, /) -> str:
        """
        `body` when the input pointed at the object body, `header` when
        at its header.
        """
    @property
    def name(self, /) -> str |None:
        """
        None for an unnamed object.
        """
    @property
    def name_info(self, /) -> int |None:
        """
        The `_OBJECT_HEADER_NAME_INFO`; None when the object has none.
        """
    @property
    def pointer_count(self, /) -> int: ...
    @property
    def type_index(self, /) -> int |None:
        """
        The header's (decoded) `TypeIndex`; None when unreadable.
        """
    @property
    def type_name(self, /) -> str |None: ...
    @property
    def type_object(self, /) -> int |None:
        """
        The `_OBJECT_TYPE`; None when unresolved.
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
        Threads waiting for exclusive access.
        """
    @property
    def flags(self, /) -> Diagnostic[int]: ...
    @property
    def owners(self, /) -> Diagnostic[list[ResourceOwner]]:
        """
        The owning threads.
        """
    @property
    def shared_waiters(self, /) -> Diagnostic[int]:
        """
        Threads waiting for shared access.
        """

@final
class Export(BaseRecord):
    """
    One PE export (`Module.exports`, `!dh -e`), by name or ordinal only;
    a forwarder has no address.
    """
    @property
    def address(self, /) -> int |None:
        """
        The mapped address, `None` for a forwarder.
        """
    @property
    def forwarder(self, /) -> str |None:
        """
        The forwarding target (`OTHER.Function`), for a forwarder.
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
    A deterministic, address-independent identity for comparing failures.
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
        The ordered parts `bucket` is formed from.
        """
    @property
    def module(self, /) -> str |None:
        """
        The module at the failing location.
        """
    @property
    def source(self, /) -> str:
        """
        Where the failing location came from: `bugcheck_fault`,
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
    A PDB field layout: name, byte offset, byte size, and type spelling.
    """
    @property
    def name(self, /) -> str: ...
    @property
    def offset(self, /) -> int:
        """
        Byte offset within the containing type.
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes.
        """
    @property
    def type(self, /) -> str:
        """
        The PDB type spelling.
        """

@final
class FileCache(BaseRecord):
    """
    The cache manager's mapped views, from its VACB arrays (`!filecache`).
    """
    @property
    def active_vacbs(self, /) -> int:
        """
        VACBs mapping a view.
        """
    @property
    def file_count(self, /) -> int:
        """
        The shared cache maps with a mapped view, listed or not.
        """
    @property
    def files(self, /) -> list[CachedFile]:
        """
        One per shared cache map with a mapped view, most valid bytes
        first, up to 1,024.
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
        Present bytes in the mapped views.
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
        The device's object name; the value is None for an unnamed device.
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
        `Type` (`IO_TYPE_FILE`, 5, for a valid file object).
        """
    @property
    def final_status(self, /) -> Diagnostic[int]:
        """
        The NTSTATUS the file object completed with.
        """
    @property
    def flags(self, /) -> Diagnostic[int]: ...
    @property
    def fs_context(self, /) -> Diagnostic[int]:
        """
        The file system's `FsContext` (its FCB).
        """
    @property
    def fs_context2(self, /) -> Diagnostic[int]:
        """
        The file system's `FsContext2` (its CCB).
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
    Threads whose stack has a frame matching a symbol or module
    (`!findstack`).
    """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether the walk was interrupted before it finished.
        """
    @property
    def level(self, /) -> int:
        """
        Detail level: 0 counts matches, 1 lists them, 2 adds whole stacks.
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
    A thread whose stack has a frame matching `!findstack`'s pattern.
    """
    @property
    def frames(self, /) -> list[StackFrame] |None:
        """
        The whole walked stack, innermost first; `None` below level 2.
        """
    @property
    def match_count(self, /) -> int:
        """
        Frames that matched.
        """
    @property
    def matching_frames(self, /) -> list[StackFrame] |None:
        """
        The frames that matched; `None` at level 0.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...
    @property
    def truncated(self, /) -> int |None:
        """
        Frames past the walk bound, not searched; `None` below level 2.
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
        Why the instance walk stopped short of its head; `None` when it
        completed.
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
        Why the frame's list walk stopped short of its head; `None` when it
        completed.
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
        Why the frame walk stopped short of its head; `None` when it
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
        Why the frame's list walk stopped short of its head; `None` when it
        completed.
        """

@final
class FltInstances(BaseRecord):
    """
    Minifilter instances per filter manager frame (`!fltkd.instances`).
    """
    @property
    def frames(self, /) -> list[FltInstanceFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the frame walk stopped short of its head; `None` when it
        completed.
        """

@final
class FltVolume(BaseRecord):
    """
    A volume the filter manager attached to (`_FLT_VOLUME`) and the
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
        Why the instance walk stopped short of its head; `None` when it
        completed.
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
        Why the frame's list walk stopped short of its head; `None` when it
        completed.
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
        Why the frame walk stopped short of its head; `None` when it
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
        Resolve a local variable by name.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def index(self, /) -> int:
        """
        The frame's position, 0 being the innermost.
        """
    @property
    def ip(self, /) -> int:
        """
        The frame's instruction pointer.
        """
    @property
    def locals(self, /) -> dict[str, int |None]:
        """
        Local variables evaluated in this frame's recovered context.
        """
    @property
    def registers(self, /) -> Registers:
        """
        The frame's registers: the live file for the innermost frame of a running
        thread (writable), otherwise the recovered subset (read-only).
        """
    @property
    def source(self, /) -> str |None:
        """
        How the frame was recovered (unwind data, frame pointer, ...).
        """
    @property
    def sp(self, /) -> int:
        """
        The frame's stack pointer.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `ip`, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The thread this stack belongs to.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class FunctionEntry(BaseRecord):
    """
    The function-table entry covering an address and each chained parent's
    (`.fnent`).
    """
    @property
    def entries(self, /) -> list[RuntimeFunction]:
        """
        The entry covering the address, then each parent its chained unwind
        info names, in order.
        """
    @property
    def image_base(self, /) -> int: ...
    @property
    def incomplete(self, /) -> str |None:
        """
        Why the chain ends before its last parent, when it does.
        """
    @property
    def module(self, /) -> str:
        """
        The module containing the function.
        """

@final
class Gdt(BaseRecord):
    """
    A processor's GDT and its bounded descriptors (`!gdt`).
    """
    @property
    def base(self, /) -> int:
        """
        The table's address.
        """
    @property
    def entries(self, /) -> list[GdtDescriptor]: ...
    @property
    def entry_count(self, /) -> int:
        """
        Slots the limit describes, which can exceed the entries decoded.
        """
    @property
    def limit(self, /) -> int:
        """
        The table's limit: its size in bytes, minus one.
        """
    @property
    def processor(self, /) -> int:
        """
        The processor number.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the table exceeds the 256-slot bound.
        """

@final
class GdtDescriptor(BaseRecord):
    """
    One decoded GDT descriptor. A system descriptor spans two slots.
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
        The G bit: the limit counts 4 KiB pages.
        """
    @property
    def high_raw(self, /) -> Diagnostic[int |None]:
        """
        A system descriptor's second slot; the diagnostic's value is None
        for other descriptors.
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
        The descriptor's raw 8 bytes.
        """
    @property
    def type_code(self, /) -> Diagnostic[int]:
        """
        The raw type field.
        """

@final
class GlobalFlag(BaseRecord):
    """
    One GFlags flag set.
    """
    @property
    def abbreviation(self, /) -> str:
        """
        The GFlags abbreviation (`hpa`, `ust`, ...).
        """
    @property
    def bit(self, /) -> int:
        """
        The flag's bit mask.
        """
    @property
    def description(self, /) -> str: ...

@final
class GlobalFlags(BaseRecord):
    """
    `nt!NtGlobalFlag` and the current process's `_PEB.NtGlobalFlag`
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
        `nt!NtGlobalFlag`'s address.
        """
    @property
    def kernel_flags(self, /) -> list[GlobalFlag]: ...
    @property
    def process(self, /) -> ProcessIdentity |None:
        """
        The current process; `None` with no process selected.
        """
    @property
    def process_flags(self, /) -> Diagnostic[ProcessGlobalFlags]:
        """
        The current process's flags, read from its PEB.
        """

@final
class HandleEntry(BaseRecord):
    """
    A handle-table entry (`!handle <handle>`).
    """
    @property
    def attributes(self, /) -> Diagnostic[int]:
        """
        The entry's attribute bits (inherit, protect-from-close, audit).
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
        The object's name; the value is None for an unnamed object.
        """
    @property
    def object(self, /) -> Diagnostic[int]:
        """
        The object's body.
        """
    @property
    def type_name(self, /) -> Diagnostic[str |None]: ...

@final
class HandleTable(BaseRecord):
    """
    A process's handle table (`!handle`).
    """
    @property
    def advertised_handles(self, /) -> int:
        """
        The handle count the table reports.
        """
    @property
    def entries(self, /) -> list[HandleEntry]: ...
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The process whose table it is.
        """
    @property
    def scanned_handles(self, /) -> int: ...
    @property
    def skipped_entries(self, /) -> int:
        """
        Entries that could not be read.
        """
    @property
    def table(self, /) -> int:
        """
        The `_HANDLE_TABLE`.
        """
    @property
    def table_level(self, /) -> int:
        """
        The table's level (0-2: how many pointer levels lead to entries).
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
    A return address on a handle trace's stack.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol it resolves to in the traced process; None when none
        does.
        """

@final
class HandleTraces(BaseRecord):
    """
    A process's handle traces (`!htrace`).
    """
    @property
    def debug_info(self, /) -> int |None:
        """
        The `_HANDLE_TRACE_DEBUG_INFO`; None when handle tracing is off.
        """
    @property
    def object_table(self, /) -> int: ...
    @property
    def parsed(self, /) -> int:
        """
        Ring slots read.
        """
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The traced process.
        """
    @property
    def recorded(self, /) -> int:
        """
        Traces ever recorded; the ring keeps the last `table_size`.
        """
    @property
    def table_size(self, /) -> int:
        """
        The ring's capacity.
        """
    @property
    def traces(self, /) -> list[HandleTrace]:
        """
        The matching traces, newest first.
        """
    @property
    def unreadable(self, /) -> int:
        """
        Ring slots that could not be read.
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
        The heap's index in the PEB list.
        """
    def inspect(self, /, list_entries: bool = False) -> HeapDetail:
        """
        Decode this heap (`!heap -h`); `list_entries` materializes entries.
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
        Whether the header checksum held; None where there is no checksum.
        """
    @property
    def flags(self, /) -> int |None:
        """
        Header flags; None where blocks have no header of their own.
        """
    @property
    def index(self, /) -> int |None:
        """
        Position in its region or subsegment; None for VS chunks.
        """
    @property
    def kind(self, /) -> str:
        """
        `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
        """
    @property
    def previous_size(self, /) -> int |None:
        """
        Bytes of the block before it; None where blocks do not record it.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes, header included.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int |None:
        """
        Slack at the end of the block, in bytes; None when not recorded.
        """
    @property
    def user(self, /) -> int |None:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int |None:
        """
        Bytes available to the caller.
        """

@final
class HeapBlockSearch(BaseRecord):
    """
    Which heap block holds an address (`!heap -x <addr>`,
    `Heaps.find_block()`).
    """
    @property
    def address(self, /) -> int:
        """
        The address searched for.
        """
    @property
    def block(self, /) -> HeapMatchNtEntry |HeapMatchNtLfhBlock |HeapMatchNtVirtual |HeapMatchNtSegment |HeapMatchPage |HeapMatchVsChunk |HeapMatchLfhBlock |HeapMatchRange |HeapMatchLarge |None:
        """
        Where in the heap the address lands; None when not found.
        """
    @property
    def errors(self, /) -> list[str]:
        """
        Heaps that could not be searched, and why.
        """
    @property
    def found(self, /) -> bool:
        """
        Whether a heap holds the address.
        """
    @property
    def heap(self, /) -> HeapIdentity |None:
        """
        The heap holding the address; None when not found.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether a heap list or walk was cut at its limit, so the search may have
        missed the block.
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
        Why the heap could not be decoded.
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
        Whether entries, chunks, and blocks were walked and listed.
        """
    @property
    def nt(self, /) -> NtHeap |None:
        """
        The NT (`_HEAP`) decoding; None for other heaps or when it failed.
        """
    @property
    def segment(self, /) -> SegmentHeap |None:
        """
        The segment-heap decoding; None for other heaps or when it failed.
        """

@final
class HeapIdentity(BaseRecord):
    """
    A heap named by its PEB-list position, address, and kind.
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
        The allocation's metadata record.
        """
    @property
    def pages(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        Bytes: `pages` pages.
        """
    @property
    def unused_bytes(self, /) -> int:
        """
        Slack at the end of the allocation, in bytes.
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
        The block's position in the subsegment.
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
        The subsegment holding the block (its `blocks` left empty).
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
        The `_HEAP_SEGMENT` holding the entry.
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
        The busy entry holding the region.
        """
    @property
    def index(self, /) -> int:
        """
        The block's position in the region.
        """
    @property
    def kind(self, /) -> str:
        """
        Always `nt-lfh-block`.
        """
    @property
    def region(self, /) -> NtLfhUserBlocks:
        """
        The user block region (its `blocks` left empty).
        """
    @property
    def segment(self, /) -> int:
        """
        The `_HEAP_SEGMENT` holding the region.
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
    An address inside an NT-heap segment but on no entry: the heap header,
    an uncommitted range, or past where the walk had to stop.
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
        Where and why the entry walk stopped; None when it did not.
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
        The block's header.
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
        Bytes: the larger of the reserve and commit sizes.
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
    An address inside a segment-heap range allocated straight from its
    segment.
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
        Bytes in the range.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """

@final
class HeapMatchRange(BaseRecord):
    """
    An address inside a segment-heap page range but outside its
    subsegment's blocks (header, bitmap, or trailing slack).
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
        The `_HEAP_VS_SUBSEGMENT` holding the chunk.
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
        Unavailable when the heap's signature, layout, memory, or symbols
        cannot be read.
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
        Byte past the range.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the subsegment could not be read.
        """
    @property
    def flags(self, /) -> int:
        """
        The descriptor's `RangeFlags`.
        """
    @property
    def kind(self, /) -> str:
        """
        `unused`, `free`, `page` (allocated straight from the segment),
        `vs`, or `lfh`.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes: `units * unit_size`.
        """
    @property
    def subsegment(self, /) -> VsSubsegment |LfhSubsegment |None:
        """
        The VS or LFH subsegment the range holds, with its blocks; `None`
        for other kinds or when it could not be read, and in a
        `Heaps.find_block()` result, which does not decode it.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the subsegment held more blocks than the walk limit.
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
        Slack at the end of the range, in bytes.
        """

@final
class HeapStats(BaseRecord):
    """
    Usage totals of one heap.
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
        Free bytes: free NT-heap blocks, or free committed segment-heap pages.
        """
    @property
    def front_end(self, /) -> int |None:
        """
        NT-heap front-end (LFH) address; None when there is none or for a
        segment heap.
        """
    @property
    def front_end_type(self, /) -> int:
        """
        NT-heap `FrontEndHeapType`; 0 for a segment heap.
        """
    @property
    def large_allocations(self, /) -> int:
        """
        Segment-heap large allocations; 0 for an NT heap.
        """
    @property
    def lfh_subsegments(self, /) -> int:
        """
        Segment-heap LFH page ranges; 0 for an NT heap.
        """
    @property
    def page_allocations(self, /) -> int:
        """
        Segment-heap ranges allocated straight from a segment; 0 for an NT heap.
        """
    @property
    def reserved(self, /) -> int:
        """
        Reserved bytes.
        """
    @property
    def segments(self, /) -> int:
        """
        NT-heap segments, or segment-heap page segments.
        """
    @property
    def virtual_blocks(self, /) -> int:
        """
        NT-heap virtually allocated blocks; 0 for a segment heap.
        """
    @property
    def vs_subsegments(self, /) -> int:
        """
        Segment-heap VS page ranges; 0 for an NT heap.
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
        The process environment block the list was read from.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the list was longer than the walk limit and was cut short.
        """

@final
class HeapWalkStop(BaseRecord):
    """
    Where a heap walk had to stop, and why.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def reason(self, /) -> str: ...

@final
class Heaps:
    """
    A process's PEB heap list.
    """
    def __contains__(self, index: int, /) -> bool: ...
    def __getitem__(self, index: int, /) -> Heap: ...
    def __iter__(self, /) -> HeapIterator: ...
    def __len__(self, /) -> int: ...
    def find_block(self, /, addr: int) -> HeapBlockSearch:
        """
        Find the heap block containing `addr` (`!heap -x`).
        """
    def get(self, /, index: int) -> Heap |None: ...

@final
class Idt(BaseRecord):
    """
    A processor's IDT: one vector, or the bounded full table (`!idt`).
    """
    @property
    def base(self, /) -> int:
        """
        The table's address.
        """
    @property
    def entries(self, /) -> list[IdtGate]: ...
    @property
    def limit(self, /) -> int:
        """
        The table's limit: its size in bytes, minus one.
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
        The one vector asked for, or None for the full table.
        """

@final
class IdtGate(BaseRecord):
    """
    One decoded AMD64 IDT gate.
    """
    @property
    def address(self, /) -> int:
        """
        The gate's address in the table.
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
        The interrupt handler the gate points at.
        """
    @property
    def ist(self, /) -> Diagnostic[int]:
        """
        The interrupt stack table index (0: none).
        """
    @property
    def ki_isr_thunk(self, /) -> Diagnostic[str |None]:
        """
        For a handler inside `KiIsrThunk` (a chained interrupt), its offset
        there and where `_KINTERRUPT.DispatchCode` sits; the diagnostic's
        value is None for other handlers.
        """
    @property
    def non_nt_hook(self, /) -> Diagnostic[bool]:
        """
        Whether the handler lies in a module other than NT's.
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
        The handler's symbol; the diagnostic's value is None when none
        resolved.
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
        The cached image's byte.
        """
    @property
    def kind(self, /) -> str |None:
        """
        The self-patch kind it belongs to; `None` for a genuine mismatch.
        """
    @property
    def rva(self, /) -> int: ...

@final
class ImageCheck(BaseRecord):
    """
    A module's in-memory code compared against its cached image
    (`!chkimg`). Range lists are capped; the `*_overflow` flags say when
    more existed.
    """
    @property
    def all_mismatch_range_overflow(self, /) -> bool: ...
    @property
    def all_mismatch_ranges(self, /) -> list[ImageMismatchRange]:
        """
        Mismatch ranges, self-patches included.
        """
    @property
    def base_address(self, /) -> int: ...
    @property
    def byte_diffs(self, /) -> list[ImageByteDiff]:
        """
        Byte-level differences; empty unless requested (`-d`).
        """
    @property
    def byte_diffs_truncated(self, /) -> bool: ...
    @property
    def genuine_mismatched_bytes(self, /) -> int:
        """
        Mismatched bytes, known self-patches excluded.
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
        Mismatched bytes, known self-patches included.
        """

@final
class ImageDataDirectory(BaseRecord):
    """
    One `IMAGE_DATA_DIRECTORY` entry.
    """
    @property
    def index(self, /) -> int:
        """
        Its slot in the directory table.
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
        The decoded CodeView record, `None` for other entry types.
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
        `IMAGE_DEBUG_TYPE_*` value.
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
        The DLL name the directory records.
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
    An image's export directory and its exports (`!dh -e`).
    """
    @property
    def directory(self, /) -> ImageExportDirectory |None:
        """
        `None` when the image exports nothing.
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
        The `IMAGE_FILE_*` flags set in `characteristics`.
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
    A mapped image's headers (`!dh`).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def data_directories(self, /) -> list[ImageDataDirectory]: ...
    @property
    def debug_directory(self, /) -> Diagnostic[list[ImageDebugEntry]] |None:
        """
        The debug directory; `None` unless asked for.
        """
    @property
    def exports(self, /) -> Diagnostic[ImageExports] |None:
        """
        The export directory; `None` unless asked for.
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
        The import descriptors; `None` unless asked for.
        """
    @property
    def module(self, /) -> str |None:
        """
        The loaded module at `base`, when there is one.
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
        The bound address the import address table holds.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the import's name did not read.
        """
    @property
    def hint(self, /) -> int |None:
        """
        The export-name-table hint, for a named import.
        """
    @property
    def name(self, /) -> str |None:
        """
        The imported name, `None` for an ordinal or unreadable import.
        """
    @property
    def ordinal(self, /) -> int |None:
        """
        The ordinal, for an import by ordinal.
        """

@final
class ImageImportDescriptor(BaseRecord):
    """
    One `IMAGE_IMPORT_DESCRIPTOR`: a DLL an image imports from.
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
        Why the thunk walk stopped early, when it did.
        """
    @property
    def name(self, /) -> str |None:
        """
        The DLL name, `None` when it did not read.
        """
    @property
    def name_error(self, /) -> str |None:
        """
        Why the DLL name did not read.
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
        Exclusive.
        """
    @property
    def size(self, /) -> int:
        """
        In bytes.
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
        PE32 only; `None` for PE32+.
        """
    @property
    def checksum(self, /) -> int: ...
    @property
    def dll_characteristics(self, /) -> int: ...
    @property
    def dll_characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_DLLCHARACTERISTICS_*` flags set.
        """
    @property
    def entry_point(self, /) -> int |None:
        """
        The mapped entry point, `None` when the image has none.
        """
    @property
    def entry_point_rva(self, /) -> int: ...
    @property
    def file_alignment(self, /) -> int: ...
    @property
    def image_base(self, /) -> int:
        """
        The preferred base the image was linked for.
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
    One executable section's comparison against the cached image.
    """
    @property
    def genuine_mismatches(self, /) -> int:
        """
        Mismatched bytes, known self-patches excluded.
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
        Why it was skipped; `None` when compared.
        """
    @property
    def skipped(self, /) -> bool:
        """
        Whether the section was skipped, not compared.
        """
    @property
    def total_mismatches(self, /) -> int:
        """
        Mismatched bytes, known self-patches included.
        """
    @property
    def unavailable(self, /) -> str |None:
        """
        Why its memory could not be read; `None` when read.
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
        The `IMAGE_SCN_*` flags set.
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
        The section's RVA.
        """
    @property
    def virtual_size(self, /) -> int: ...

@final
class ImageSelfPatchCounts(BaseRecord):
    """
    Bytes recognized as known kernel self-patches, by kind.
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
        Relocated addresses of kernel VA regions moved at boot.
        """
    @property
    def retpoline(self, /) -> int: ...
    @property
    def total(self, /) -> int: ...

@final
class ImageSelfPatchRange(BaseRecord):
    """
    A contiguous RVA range recognized as one kernel self-patch kind.
    """
    @property
    def end(self, /) -> int:
        """
        Exclusive.
        """
    @property
    def function(self, /) -> str |None:
        """
        The function containing the patch, when a symbol covers it.
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
        In bytes.
        """
    @property
    def start(self, /) -> int: ...

@final
class InFlightIrp(BaseRecord):
    """
    An in-flight IRP found on a thread's `IrpList` or as a device's
    `CurrentIrp` (`irps`).
    """
    @property
    def current_location(self, /) -> int: ...
    @property
    def device(self, /) -> int |None:
        """
        The current stack location's device; None when unresolved.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The driver owning the current stack location's device; None when
        unresolved.
        """
    @property
    def ethread(self, /) -> int |None: ...
    @property
    def irp(self, /) -> int: ...
    @property
    def pid(self, /) -> int |None:
        """
        The issuing process; None when found on a device.
        """
    @property
    def source(self, /) -> str:
        """
        `thread` or `device`: where it was found.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def state(self, /) -> str |None:
        """
        The thread's state name; None when found on a device.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The issuing thread; None when found on a device.
        """
    @property
    def wait_reason(self, /) -> str |None:
        """
        The thread's wait-reason name; None when found on a device.
        """

@final
class Inspect:
    """
    System-wide reports and decode-by-address helpers (`dbg.inspect`); the
    results are `Record`s shaped like the MCP JSON output.
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
        Decode an ALPC port (`!alpc /p`): its kind, owner, connection, state,
        queues, and a connection port's connections. `address` is the port
        object's body or header.
        """
    def alpc_process_ports(self, /, process: Process |None = None) -> AlpcProcessPorts:
        """
        The ALPC ports a process holds handles to (`!alpc /lpp`): the
        connection ports it owns with their connections, and the client ports
        it is connected through. `process` defaults to the current process.
        """
    def apcs(self, /, target: Process |Thread |int |None = None) -> ApcQueues:
        """
        Decode kernel and user APC queues for all threads, a process, or a thread (`!apc`).
        """
    def bugcheck(self, /) -> Bugcheck |None:
        """
        Analyze the current bugcheck, or return `None` when the target is not bugchecking.
        """
    def callbacks(self, /) -> list[NotifyCallback]:
        """
        Enumerate process, thread, and image notification callbacks.
        """
    def context_record(self, /, address: int) -> Frame:
        """
        Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
        """
    def control_area(self, /, address: int) -> ControlArea:
        """
        Decode a section's `_CONTROL_AREA`, its segment, and its subsections
        (`!ca`).
        """
    def device(self, /, address: int) -> Device:
        """
        Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
        """
    def device_stack(self, /, device_or_node: Device |int) -> DeviceStack:
        """
        Decode the device stack containing a device object or devnode (`!devstack`).
        """
    def devnode(self, /, node: int |None = None, recurse: bool = False) -> DevNode:
        """
        Decode a PnP device node and optionally its bounded subtree (`!devnode`).
        """
    def dpcs(self, /) -> DpcQueues:
        """
        Report DPCs queued on each processor (`!dpcs`).
        """
    def etw_buffers(self, /, logger: int |str) -> EtwLoggerBuffers:
        """
        List the trace buffers on an ETW trace session's GlobalList
        (`!wmitrace.strdump logger`).
        """
    def etw_events(self, /, logger: int |str, count: int |None = None) -> EtwEventDump:
        """
        Decode the events still in an ETW trace session's buffers, oldest
        first (`!wmitrace.logdump`); `count` keeps only the most recent.
        A WPP message's `message.text` is its rendering from the TMF a loaded
        PDB declares; the raw `payload` is kept either way.
        """
    def etw_logger(self, /, logger: int |str) -> EtwLogger:
        """
        Decode one ETW trace session's `_WMI_LOGGER_CONTEXT`
        (`!wmitrace.logger`). `logger` is its logger id or context address,
        or its session name.
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
        The cache manager's mapped views per file, from its VACB arrays
        (`!filecache`).
        """
    def file_object(self, /, address: int) -> FileObject:
        """
        Decode a `_FILE_OBJECT` (`!fileobj`).
        """
    def findstack(self, /, symbol: str, level: int = 1) -> FindStack:
        """
        List the threads whose stack has a frame matching a symbol or module
        (`!findstack`): `module!prefix`, a bare module or function prefix, or
        globs with `*`/`?`. `level` 0 counts the matching frames, 1 lists
        them, 2 adds the whole stack.
        """
    def flt_filters(self, /) -> FltFilters:
        """
        The registered minifilters of each filter manager frame, with their
        instances (`!fltkd.filters`).
        """
    def flt_instances(self, /, filter: int |str |None = None) -> FltInstances:
        """
        Minifilter instances with their filter and volume, all or those of
        one filter named by name or `_FLT_FILTER` address
        (`!fltkd.instances`).
        """
    def flt_volumes(self, /) -> FltVolumes:
        """
        The volumes of each filter manager frame, with the instances on them
        (`!fltkd.volumes`).
        """
    def global_flags(self, /) -> GlobalFlags:
        """
        Decode `nt!NtGlobalFlag` and the current process's
        `_PEB.NtGlobalFlag` by the GFlags names (`!gflag`).
        """
    def ipi(self, /, processor: int |None = None) -> IpiState:
        """
        Report interprocessor-interrupt state for every processor or one
        (`!ipi`).
        """
    def irp(self, /, address: int) -> Irp:
        """
        Decode an in-flight `_IRP` and its current I/O stack location (`!irp`).
        """
    def irp_find(self, /, pool_type: str = "nonpaged", restart: int |None = None, criteria: str |None = None, value: int = 0) -> IrpFindResult:
        """
        Find IRPs by scanning pool for `IoAllocateIrp`'s allocations
        (`!irpfind`). `pool_type` is `"nonpaged"` or `"paged"`; `restart`
        resumes from an address; `criteria` is one of WinDbg's (`"arg"`,
        `"device"`, `"fileobject"`, `"mdlprocess"`, `"thread"`, `"userevent"`)
        matched against `value`.
        """
    def irps(self, /, filter: str |None = None) -> list[InFlightIrp]:
        """
        Find in-flight IRPs, optionally filtered by process or driver (`irps`).
        """
    def job(self, /, address: int |None = None) -> Job:
        """
        Decode a job object: its accounting, limits, flags, nesting, and the
        processes assigned to it (`!job`). `address` is the job, or a process
        or thread whose job to decode; `None` is the current process's job.
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
        `pfn_count` overrides the count `ByteCount` spans from `ByteOffset`.
        """
    def memusage(self, /, process_limit: int = 64) -> SystemMemoryUsage:
        """
        Return bounded system and per-process memory-use counters (`!memusage`).
        """
    def object(self, /, object: int |str) -> ExecutiveObject:
        """
        Decode an executive object header and resolve its type and name, and
        list a directory's entries (`!object`). `object` is the object's
        address, or its path in the object namespace (`"\\Driver\\ACPI"`).
        """
    def object_security(self, /, object: int) -> ObjectSecurity:
        """
        Decode the security descriptor referenced by an object's header (`!objsd`).
        """
    def pci(self, /, bus: int = 0, device: int |None = None, function: int |None = None, *, last_bus: int |None = None, raw: bool = False) -> PciScan:
        """
        Read and decode PCI configuration space (`!pci`): the functions on
        `bus` (through `last_bus`), or one `device` and `function`. Each
        function's 4 KiB is read, extended capabilities included; `raw` adds
        it as hex. Needs a backend that reaches configuration space (kd/kdnet,
        or gdb on QEMU) and a halted target.
        """
    def pci_tree(self, /) -> PciTree:
        """
        Report the PCI bus hierarchy pci.sys tracks (`!pcitree`).
        """
    def peb(self, /, process: Process, address: int |None = None) -> Peb:
        """
        Decode a process PEB and its parameters and loader-list heads (`!peb`).
        """
    def pfn(self, /, value: int, physical_address: bool = False) -> Pfn:
        """
        Decode an `_MMPFN` by page-frame number or physical address (`!pfn`).
        """
    def pnp_triage(self, /) -> PnpTriage:
        """
        Report device nodes with PnP problems (`!pnptriage`).
        """
    def pool(self, /, address: int) -> PoolPage:
        """
        Decode the pool page or big-pool allocation containing `address` (`!pool`).
        """
    def pool_find(self, /, tag: str, pool_type: str |None = None) -> PoolSearch:
        """
        Find pool allocations by tag, optionally restricted to a pool type (`!poolfind`).
        """
    def pool_usage(self, /, tag: str |None = None, *, sort: str = "tag", include_counts: bool = False) -> PoolUsage:
        """
        Aggregate pool tracker usage by tag (`!poolused`).
        """
    def pool_validate(self, /, address: int) -> PoolValidation:
        """
        Check the block headers of the pool page containing `address` and
        report the first inconsistency (`!poolval`).
        """
    def queued_locks(self, /) -> QueuedLocks:
        """
        Report which processors own or wait for each numbered queued spinlock
        (`!qlocks`).
        """
    def ready(self, /, processor: int |None = None) -> ReadyQueues:
        """
        Read bounded dispatcher-ready queues for every processor or one (`!ready`).
        """
    def resource(self, /, address: int) -> ExecutiveResource:
        """
        Decode an executive resource (`!locks address`).
        """
    def resources(self, /, limit: int = 256) -> ResourceList:
        """
        Enumerate the symbol-backed executive-resource list (`!locks`).
        """
    def running(self, /, include_idle: bool = False, include_stacks: bool = False) -> RunningProcessors:
        """
        Report current, next, and idle threads on each processor (`!running`).
        """
    def security_descriptor(self, /, address: int, annotate_well_known: bool = False) -> SecurityDescriptor:
        """
        Decode a security descriptor, including owner/group SIDs and ACLs (`!sd`).
        """
    def sessions(self, /, session: int |None = None) -> Sessions:
        """
        List sessions and their processes, optionally selecting one (`!session`).
        """
    def sid(self, /, address: int) -> Sid:
        """
        Decode a SID to its string form, authority, and well-known name (`!sid`).
        """
    def ssdt(self, /) -> list[SsdtTable]:
        """
        Dump the kernel SSDT and initialized win32k shadow table (`!ssdt`).
        """
    def stacks(self, /, level: int = 0, filter: str |None = None) -> ThreadStacks:
        """
        Report thread states, wait reasons, and bounded stacks (`!stacks`).
        """
    def system_ptes(self, /, free_runs: bool = False) -> SystemPtes:
        """
        Report system PTE usage from each `_MI_SYSTEM_PTE_TYPE` bitmap
        allocator (`!sysptes`); `free_runs` lists each allocator's free blocks.
        """
    def teb(self, /, thread: Thread, address: int |None = None) -> Teb:
        """
        Decode a thread TEB and its WOW64 companion (`!teb`).
        """
    def time(self, /) -> TargetTime:
        """
        Report target system time and uptime (`.time`).
        """
    def timer(self, /, address: int) -> KernelTimer:
        """
        Decode a `_KTIMER` and its DPC (`!timer address`).
        """
    def timers(self, /) -> TimerTable:
        """
        Read bounded kernel timer-table entries and their DPCs (`!timer`).
        """
    def trap_frame(self, /, address: int) -> TrapFrame:
        """
        Decode a `_KTRAP_FRAME` at `address` (`.trap`).
        """
    def triage(self, /) -> TriageReport:
        """
        Build the structured one-shot crash/debug report (`!analyze`).
        """
    def uniqstack(self, /, process: Process |None = None) -> UniqStacks:
        """
        Group threads by identical call stacks, one process's or, by
        default, every thread's (`!uniqstack`).
        """
    def verifier(self, /) -> Verifier:
        """
        Report Driver Verifier configuration and statistics (`!verifier`).
        """
    def version(self, /) -> TargetVersion:
        """
        Target, kernel, symbol, processor, and debugger version information (`vertarget`).
        """
    def vm(self, /, include_processes: bool = True) -> VmStatistics:
        """
        Report system memory, pool, PTE, and page-file counters (`!vm`).
        """
    def vpb(self, /, address: int) -> Vpb:
        """
        Decode a volume parameter block (`!vpb`).
        """
    def wdf_device(self, /, handle: int) -> WdfDevice:
        """
        A WDFDEVICE's device objects, state machines, and queues
        (`!wdfkd.wdfdevice`).
        """
    def wdf_driver_info(self, /, driver: str) -> WdfDriverInfo:
        """
        A KMDF client driver, named as `wdf_loader` lists it (without case,
        `.sys` optional), and its device objects with the WDFDEVICEs behind
        them (`!wdfkd.wdfdriverinfo`).
        """
    def wdf_handle(self, /, handle: int) -> WdfHandle:
        """
        Decode a WDF handle and the object it names; a value that is not a
        live KMDF object's handle raises (`!wdfkd.wdfhandle`).
        """
    def wdf_loader(self, /) -> WdfLoader:
        """
        The KMDF client drivers on `Wdf01000!FxLibraryGlobals`'s driver
        list (`!wdfkd.wdfldr`).
        """
    def wdf_log(self, /, driver: str) -> WdfLog:
        """
        A KMDF client driver's In-Flight Recorder log, oldest record first,
        each record formatted from its TMF message when a loaded PDB declares
        it (`!wdfkd.wdflogdump`).
        """
    def wdf_queue(self, /, handle: int) -> WdfQueue:
        """
        A WDFQUEUE's configuration, state, callbacks, and requests
        (`!wdfkd.wdfqueue`).
        """
    def work_queues(self, /, include_stacks: bool = False, queue_types: Sequence[str] |None = None) -> WorkQueues:
        """
        Report the executive worker queues, their pending work items, and
        worker threads (`!exqueue`). `include_stacks` adds each worker's stack;
        `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`) restricts
        the listed items to those types' priorities.
        """
    def zombies(self, /, flags: int = 1) -> Zombies:
        """
        Exited processes and terminated threads whose objects are still
        referenced, found by scanning nonpaged pool (`!zombies`). `flags`: 1
        processes, 2 threads, 3 both.
        """

@final
class IoStackLocation(BaseRecord):
    """
    An `_IO_STACK_LOCATION`: one driver's part of an IRP.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def completion_routine(self, /) -> int: ...
    @property
    def context(self, /) -> int:
        """
        The completion routine's context argument.
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
        The major function's name (`IRP_MJ_READ`, ...).
        """
    @property
    def minor_function(self, /) -> int: ...

@final
class IoWorkItem(BaseRecord):
    """
    An `_IO_WORKITEM` queued through `IoQueueWorkItem`, whose work item
    runs `nt!IopProcessWorkItem` to call `routine`.
    """
    @property
    def address(self, /) -> int:
        """
        The `_IO_WORKITEM` holding the queued `_WORK_QUEUE_ITEM`.
        """
    @property
    def context(self, /) -> int: ...
    @property
    def io_object(self, /) -> int:
        """
        The device or driver object it was allocated for.
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
    One processor's IPI state.
    """
    @property
    def awaiting(self, /) -> list[int]:
        """
        Processors whose pending list holds a request from this one.
        """
    @property
    def fields(self, /) -> Record:
        """
        The `_KPRCB` IPI fields this build has, by name, each a
        `Diagnostic` of its value.
        """
    @property
    def frozen_state(self, /) -> Diagnostic[str] |None:
        """
        `IpiFrozen` decoded (`Running`, `Frozen`, ...); `None` when the
        build lacks the field.
        """
    @property
    def kprcb(self, /) -> int: ...
    @property
    def pending(self, /) -> Diagnostic[list[IpiRequest]]:
        """
        Requests queued to this processor and not yet taken, in list
        order; unavailable on builds without per-sender mailboxes or when
        the list cannot be read.
        """
    @property
    def pending_truncated(self, /) -> bool:
        """
        Whether the pending walk stopped at its bound or a repeated
        mailbox.
        """
    @property
    def processor(self, /) -> int: ...

@final
class IpiRequest(BaseRecord):
    """
    A request a sender posted in a processor's IPI mailbox list.
    """
    @property
    def mailbox(self, /) -> int:
        """
        The sender's `_REQUEST_MAILBOX` slot in the receiver's array.
        """
    @property
    def parameters(self, /) -> Diagnostic[list[int]]:
        """
        `RequestPacket.CurrentPacket`: the worker's three parameters.
        """
    @property
    def request_summary(self, /) -> Diagnostic[int]: ...
    @property
    def request_type(self, /) -> Diagnostic[str |None]:
        """
        The request summary's type, when it is a known one.
        """
    @property
    def sender(self, /) -> int |None:
        """
        The sending processor; `None` when the mailbox lies outside the
        receiver's array.
        """
    @property
    def worker_routine(self, /) -> Diagnostic[int]: ...
    @property
    def worker_symbol(self, /) -> str |None:
        """
        The worker routine's symbol, when it resolves.
        """

@final
class IpiState(BaseRecord):
    """
    Interprocessor-interrupt state per processor (`!ipi`).
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
        `CurrentLocation`; above `stack_count` once the IRP completes.
        """
    @property
    def current_stack(self, /) -> IoStackLocation |None:
        """
        None when the current location is out of range or unreadable.
        """
    @property
    def io_status(self, /) -> int |None:
        """
        `IoStatus.Status`, as an NTSTATUS; None when unreadable.
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
        `Size` in bytes, stack locations included.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def thread(self, /) -> int:
        """
        `Tail.Overlay.Thread`: the thread that issued it.
        """
    @property
    def type(self, /) -> int:
        """
        `Type` (`IO_TYPE_IRP`, 6, for a valid IRP).
        """
    @property
    def user_buffer(self, /) -> int: ...
    @property
    def user_event(self, /) -> int: ...

@final
class IrpDispatchRoutine(BaseRecord):
    """
    One `MajorFunction` dispatch-table slot.
    """
    @property
    def index(self, /) -> int:
        """
        The `IRP_MJ_*` code.
        """
    @property
    def name(self, /) -> str:
        """
        The major function's name (`IRP_MJ_CREATE`, ...).
        """
    @property
    def routine(self, /) -> int: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The routine's nearest symbol; None when none resolves.
        """

@final
class IrpFindCriteria(BaseRecord):
    """
    The criteria an `!irpfind` search matched IRPs against.
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
        How the big-pool table scan went.
        """
    @property
    def criteria(self, /) -> IrpFindCriteria |None:
        """
        None when unfiltered.
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
        Where to resume the page scan; None when it finished.
        """
    @property
    def scan_start(self, /) -> int:
        """
        Where the page scan began: the region start or the restart
        address.
        """
    @property
    def scanned_pages(self, /) -> int: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the result bound left IRPs out: the page scan stopped at
        `restart`, or big-pool allocations went unchecked.
        """

@final
class Irql(BaseRecord):
    """
    A processor's current IRQL (`!irql`).
    """
    @property
    def level_name(self, /) -> Diagnostic[str]:
        """
        The Windows name of the level (`DISPATCH_LEVEL`, ...).
        """
    @property
    def note(self, /) -> str:
        """
        At a KD break-in, the IRQL the debugger observes, which can differ
        from the level active just before the break-in.
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
    A job object (`!job`): its accounting, limits, flags, nesting, and
    the processes assigned to it. A field this build lacks is `None`.
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
        The `JobFlags` bits set, by their PDB names.
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
        The `JOB_OBJECT_LIMIT_*` names of the limit flags set; an
        unnamed bit is its hex value.
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
        Whether the job is a silo.
        """
    @property
    def unreadable_processes(self, /) -> list[int]:
        """
        `_EPROCESS` addresses on the job's list that could not be decoded.
        """

@final
class JobAccounting(BaseRecord):
    """
    A job's `_EJOB` accounting; a field this build lacks is `None`.
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
        Processes ever assigned.
        """
    @property
    def total_terminated_processes(self, /) -> int |None:
        """
        Processes terminated by a job limit violation.
        """
    @property
    def total_user_time(self, /) -> int |None:
        """
        In 100 ns units.
        """

@final
class JobLimits(BaseRecord):
    """
    A job's `_EJOB` limit settings; a field this build lacks is `None`.
    """
    @property
    def active_process_limit(self, /) -> int |None: ...
    @property
    def effective_limit_flags(self, /) -> int |None:
        """
        Limit bits in effect, nesting included.
        """
    @property
    def job_memory_limit(self, /) -> int |None:
        """
        In pages.
        """
    @property
    def limit_flags(self, /) -> int |None:
        """
        `JOB_OBJECT_LIMIT_*` bits set.
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
        `JOB_OBJECT_UILIMIT_*` bits set.
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
        The decoded `_KDPC` address; `None` inside when the timer has none.
        """
    @property
    def dpc_encoded(self, /) -> Diagnostic[int |None]:
        """
        `Dpc` as stored, encoded by the kernel.
        """
    @property
    def dpc_routine(self, /) -> Diagnostic[int |None]:
        """
        The DPC's `DeferredRoutine`.
        """
    @property
    def dpc_routine_symbol(self, /) -> Diagnostic[str |None]:
        """
        `dpc_routine` as a symbol, when one resolves.
        """
    @property
    def due_time(self, /) -> Diagnostic[int]:
        """
        `DueTime`: the interrupt time it expires at (see
        `TargetTime.interrupt_time`).
        """
    @property
    def period(self, /) -> Diagnostic[int]:
        """
        `Period` in milliseconds; 0 for a one-shot timer.
        """

@final
class LastError(BaseRecord):
    """
    A thread's Win32 last error and last NTSTATUS (`!gle`).
    """
    @property
    def last_error_name(self, /) -> Diagnostic[str |None]:
        """
        The error's symbolic name; value `None` when unknown.
        """
    @property
    def last_error_value(self, /) -> Diagnostic[int]: ...
    @property
    def last_status_name(self, /) -> Diagnostic[str |None]:
        """
        The status's symbolic name; value `None` when unknown.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]: ...
    @property
    def teb(self, /) -> int:
        """
        The `_TEB` read.
        """
    @property
    def teb32(self, /) -> LastError32 |None:
        """
        The WOW64 `_TEB32`'s values; `None` for a native thread.
        """

@final
class LastError32(BaseRecord):
    """
    A WOW64 thread's 32-bit last error and last NTSTATUS.
    """
    @property
    def last_error_name(self, /) -> Diagnostic[str |None]:
        """
        The error's symbolic name; value `None` when unknown.
        """
    @property
    def last_error_value(self, /) -> Diagnostic[int]: ...
    @property
    def last_status_name(self, /) -> Diagnostic[str |None]:
        """
        The status's symbolic name; value `None` when unknown.
        """
    @property
    def last_status_value(self, /) -> Diagnostic[int]: ...
    @property
    def teb(self, /) -> int:
        """
        The `_TEB32` read.
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
        `BlockBitmap` words (a qword on x64, a dword on x86); a block's low
        bit is set while it is busy.
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
        The subsegment's blocks; empty unless entries were listed.
        """
    @property
    def blocks_per_word(self, /) -> int:
        """
        Blocks per `bitmap` word.
        """
    @property
    def bucket(self, /) -> int:
        """
        The LFH bucket the subsegment serves.
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
    How a guest linked-list walk ended.
    """
    @property
    def address(self, /) -> int |None:
        """
        Where a cycle closed.
        """
    @property
    def error(self, /) -> str |None:
        """
        What was wrong, for a corrupt (or, in some walks, null) link.
        """
    @property
    def kind(self, /) -> str:
        """
        `head` (back at the list head), `null`, `cycle` (a loop not
        through the head), `bound` (the walk's limit), or `corrupt`.
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
        PE checksum; `None` when the loader record lacks one.
        """
    @property
    def end(self, /) -> int:
        """
        One past the image's last byte.
        """
    @property
    def file_version(self, /) -> str |None:
        """
        File version from the version resource; `None` when unread.
        """
    @property
    def name(self, /) -> str:
        """
        The image file name (`ntoskrnl.exe`).
        """
    @property
    def path(self, /) -> str |None:
        """
        Full image path, when the loader recorded one.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        Product version from the version resource; `None` when unread.
        """
    @property
    def short_name(self, /) -> str:
        """
        The name `module!symbol` uses (`nt`).
        """
    @property
    def size(self, /) -> int:
        """
        Mapped image size in bytes.
        """
    @property
    def symbols(self, /) -> ModuleSymbols |None:
        """
        Symbol status; `None` except on a kernel module's `inspect()`.
        """
    @property
    def time_date_stamp(self, /) -> int |None:
        """
        PE timestamp; `None` when the loader record lacks one.
        """

@final
class LoaderListHead(BaseRecord):
    """
    A `_PEB_LDR_DATA` list head.
    """
    @property
    def address(self, /) -> int:
        """
        The `LIST_ENTRY` head itself.
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
    The three `_PEB_LDR_DATA` module lists' heads.
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
        The PE header's checksum; `None` when the header is unreadable.
        """
    @property
    def entry_point(self, /) -> int |None:
        """
        `None` when the loader entry has none (or it is unreadable).
        """
    @property
    def file_version(self, /) -> str |None:
        """
        The version resource's file version; `None` when unreadable.
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
        The version resource's product version; `None` when unreadable.
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
        The PE header's link timestamp; `None` when the header is
        unreadable.
        """

@final
class LoaderModules(BaseRecord):
    """
    A process's loader-list modules (`!dlls`) and how the walks ended.
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
        How the WOW64 loader-list walk ended; `None` for a native process.
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
    Where a local variable lives.
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
        Why the location is unknown, for `unavailable`.
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
        Position in the list walk.
        """
    @property
    def size(self, /) -> Diagnostic[int]:
        """
        Allocation size in bytes.
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
        Whether the walk stopped at its bound before the end.
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
        PFN slots `size` leaves after the header.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        `MDL_*` names of the set `flags` bits, low bit first.
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
        Where the PFN array starts (just past the header).
        """
    @property
    def pfns(self, /) -> list[int]: ...
    @property
    def process(self, /) -> int: ...
    @property
    def size(self, /) -> int:
        """
        Bytes of header plus PFN array the allocation holds.
        """
    @property
    def spanned_pages(self, /) -> int:
        """
        Pages the described buffer spans.
        """
    @property
    def start_va(self, /) -> int: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether fewer PFNs are listed than the buffer spans: a smaller count was
        requested.
        """

@final
class Memory:
    """
    A guest address space: `dbg.memory` (kernel), `proc.memory`, `cpu.memory`,
    `dbg.physical`.
    """
    def describe(self, /, addr: int) -> AddressDescription:
        """
        Describe the loaded module, kernel region, or process VAD containing `addr`.
        """
    def disassemble(self, /, addr: int, count: int) -> list[DisassembledInstruction]:
        """
        Disassemble `count` instructions at `addr` (`u`).
        """
    def disassemble_back(self, /, addr: int, count: int) -> list[DisassembledInstruction]:
        """
        Disassemble the `count` instructions ending at `addr` (`ub`).
        """
    def disassemble_function(self, /, addr: int) -> list[DisassembledInstruction]:
        """
        Disassemble the runtime function containing `addr` (`uf`).
        """
    @property
    def dtb(self, /) -> int:
        """
        The directory-table base used by this space.
        """
    def function_entry(self, /, addr: int) -> FunctionEntry:
        """
        The function-table entry and unwind info (AMD64 or ARM64) of the
        function containing `addr`, chained parents included (`.fnent`).
        """
    def page_in(self, /, addr: int) -> bool:
        """
        Make `addr` resident with the guest debugger worker (`.pagein`). The
        worker resumes the guest and returns with it stopped at its completion;
        that stop is reflected by `dbg.stop`.
        """
    @property
    def pointer_size(self, /) -> int:
        """
        The guest pointer width in bytes (`$ptrsize`).
        """
    def ptov(self, /, physical: int) -> ReverseTranslation:
        """
        Reverse-map a physical address through this space's page tables (`!ptov`).
        """
    def read(self, /, addr: int, n: int) -> bytes:
        """
        Read `n` bytes; virtual reads mask this debugger's breakpoint opcodes.
        """
    def read_ansi_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`). `bits`
        selects the layout as for `read_unicode_string`.
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
        Read one little-endian byte.
        """
    def read_unicode_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`). `bits`
        selects the layout: 32 for a WOW64 process's x86 descriptors, 64 for
        native ones; by default the `.effmach` setting decides.
        """
    def read_wstring(self, /, addr: int, max_len: int = 256) -> str:
        """
        Read a NUL-terminated UTF-16 string at `addr` (`du`).
        """
    def search(self, /, pattern: bytes, start: int, length: int) -> list[MemorySearchMatch]:
        """
        Find overlapping matches and include symbol/module/VAD context. In a
        virtual space unreadable pages are skipped, this session's own
        breakpoints read as the code they replaced, and at most 4096 matches
        are returned.
        """
    def translate(self, /, addr: int) -> int |None:
        """
        Translate a virtual address through this space's page tables (`!vtop`).
        """
    def translation(self, /, addr: int) -> AddressTranslation:
        """
        The full page-table walk and final translation (`!pte` + `!vtop`).
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
    What `VirtualQuery` reports for an address (`!vprot`), each
    `MEM_*`/`PAGE_*` value beside its name.
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
        Bytes from `base_address` to the first page whose state or
        protection differs, or the end of the VAD.
        """
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the scan stopped at its bound or an unreadable page table before
        the region ended, so `region_size` is a lower bound.
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
        Committed pages charged to the region.
        """
    @property
    def details(self, /) -> str |None:
        """
        A description: the mapped file, or the kernel region kind.
        """
    @property
    def end(self, /) -> int:
        """
        End of the region (exclusive).
        """
    @property
    def private_memory(self, /) -> bool |None:
        """
        Whether the region is private (not shared or mapped).
        """
    @property
    def protection(self, /) -> int |None:
        """
        The VAD protection value (an index into the memory manager's
        protection table, not a `PAGE_*` mask), when known.
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes.
        """
    @property
    def start(self, /) -> int:
        """
        First address of the region.
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
    A memory-search hit with symbol and location context.
    """
    @property
    def address(self, /) -> int:
        """
        Where the pattern matched.
        """
    @property
    def kind(self, /) -> str:
        """
        What the address is: `kernel-module`, `user-image`,
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
        The match's offset from the search start.
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
        The nearest symbol, if one resolved.
        """
    @property
    def va_type(self, /) -> str |None:
        """
        The `_MI_SYSTEM_VA_TYPE` name, for a kernel-region match.
        """

@final
class Module:
    """
    One loaded image in the kernel or a process address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, name: str, /) -> int:
        """
        Resolve a symbol from this module to its address.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        Base address of the loaded image.
        """
    def check_image(self, /, include_diffs: bool = False) -> ImageCheck:
        """
        Compare executable sections against the cached image (`!chkimg`).
        """
    @property
    def exports(self, /) -> list[Export]:
        """
        Exports from the mapped PE export directory.
        """
    def fetch_image(self, /) -> str:
        """
        Fetch the matching image from the symbol server cache (`.fetchimage`).
        """
    @property
    def file_version(self, /) -> str |None:
        """
        File version from the image's version resource.
        """
    def headers(self, /, exports: bool = False, imports: bool = False) -> ImageHeaders:
        """
        The mapped image's PE headers (`!dh`): file and optional headers,
        data directories, sections, and the debug directory with its PDB
        identity; `exports` and `imports` add those directories.
        """
    def image(self, /, zero_fill: bool = False) -> bytes:
        """
        The mapped image in memory layout, for pefile/LIEF. Raises
        `MemoryAccessError` on an unreadable page unless `zero_fill` is set,
        which zeroes such pages instead (a kernel's discarded INIT section).
        """
    def image_info(self, /) -> ModuleImageInfo:
        """
        The module's image identity (`!lmi`): machine, time stamp, size,
        checksum, and characteristics from its headers, the debug directory
        with the CodeView PDB name, GUID, and age, and its symbol state and
        local PDB file.
        """
    def inspect(self, /) -> LoadedModule |LoaderModule:
        """
        Symbol status, load diagnostics and PDB identity (`lmv`).
        """
    @property
    def name(self, /) -> str:
        """
        Image name.
        """
    @property
    def path(self, /) -> str |None:
        """
        Full image path, when the loader recorded one.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        Product version from the image's version resource.
        """
    def reload_symbols(self, /) -> SymbolReloadReport:
        """
        Select, fetch, and index symbols for this module (`ld`, `.reload`).
        """
    @property
    def sections(self, /) -> list[Section]:
        """
        PE sections and their mapped permissions.
        """
    @property
    def size(self, /) -> int:
        """
        Size of the mapped image.
        """
    @property
    def symbols(self, /) -> ModuleSymbols:
        """
        Module symbol and PDB identity (`lmv`).
        """
    @property
    def timestamp(self, /) -> int |None:
        """
        PE timestamp, when present in the loader record.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The module as a plain `dict`, the shape MCP renders.
        """
    def verifier(self, /) -> VerifierDriver:
        """
        Return verifier data for this driver module.
        """

@final
class ModuleImageInfo(BaseRecord):
    """
    A module's image identity (`!lmi`): its file-header identity, debug
    directory (with the CodeView PDB name, GUID, and age), and symbol
    state.
    """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_FILE_*` flags set in `characteristics`.
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
        The local PDB file, when one is loaded.
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
    A module's symbol status and PDB identity (`lmv`).
    """
    @property
    def error(self, /) -> str |None:
        """
        Why loading failed, for status `failed`.
        """
    @property
    def pdb_age(self, /) -> int |None:
        """
        The loaded PDB's age, `None` without a PDB.
        """
    @property
    def pdb_guid(self, /) -> str |None:
        """
        The loaded PDB's GUID as 32 hex digits, `None` without a PDB.
        """
    @property
    def source(self, /) -> str |None:
        """
        Where the PDB came from, when known.
        """
    @property
    def status(self, /) -> str:
        """
        `loaded`, `deferred`, `failed`, `unknown`, ...
        """

@final
class Modules:
    """
    A module collection: `dbg.modules` (kernel), `proc.modules` (loader
    lists), or `dbg.secure_kernel.modules` (the secure kernel's).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Module: ...
    def __iter__(self, /) -> ModuleIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Module |None:
        """
        The module containing `addr`, or `None` when no module contains it.
        """
    def get(self, /, name: str) -> Module |None:
        """
        Look up a module by short name, case-insensitively (`"nt"` names ntoskrnl).
        """
    @property
    def termination(self, /) -> LoaderTerminations |None:
        """
        How a process's loader lists ended (`termination` and
        `wow64_termination`, each `{kind, address, error}`), to tell a complete
        list from a corrupt or truncated one; `None` for kernel modules.
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
    Iterator over names: a record's fields, a register file's registers.
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
        Its slot in the kernel's callback array.
        """
    @property
    def kind(self, /) -> str:
        """
        `process`, `thread`, or `image`.
        """
    @property
    def raw(self, /) -> int:
        """
        The slot's raw `_EX_FAST_REF` value.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The function's nearest symbol; None when none resolves.
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
        XOR mask over every entry header's metadata; None when headers are
        not encoded.
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
        The front-end (LFH) heap; None when there is none.
        """
    @property
    def front_end_type(self, /) -> int:
        """
        `_HEAP.FrontEndHeapType`.
        """
    @property
    def granule(self, /) -> int:
        """
        Size of `_HEAP_ENTRY` in bytes: 16 on x64, 8 on x86; every block
        starts with one.
        """
    @property
    def segments(self, /) -> list[NtHeapSegment]: ...
    @property
    def total_free_units(self, /) -> int:
        """
        Free space, in granules.
        """
    @property
    def virtual_blocks(self, /) -> list[NtVirtualBlock]:
        """
        Blocks too large for a segment, allocated on their own.
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
        Whether the header's XOR checksum held (always true when headers are not
        encoded).
        """
    @property
    def flags(self, /) -> int:
        """
        The header's flags byte.
        """
    @property
    def granule(self, /) -> int:
        """
        Header size in bytes (see `NtHeap.granule`).
        """
    @property
    def kind(self, /) -> str:
        """
        Always `entry`.
        """
    @property
    def lfh(self, /) -> NtLfhUserBlocks |None:
        """
        The legacy-LFH user block region inside this busy entry; `None`
        when there is none or it could not be read, and in a
        `Heaps.find_block()` result, which does not decode it.
        """
    @property
    def lfh_error(self, /) -> str |None:
        """
        Why the entry's LFH region could not be read.
        """
    @property
    def lfh_truncated(self, /) -> bool:
        """
        Whether the region's `blocks` were cut at the walk limit.
        """
    @property
    def previous_size(self, /) -> int:
        """
        Bytes of the entry before it.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes, header included.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int:
        """
        Slack at the end of the block, in bytes.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int:
        """
        Bytes the caller asked for: the block less its header and slack.
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
        First byte the segment spans.
        """
    @property
    def end(self, /) -> int:
        """
        Byte past the segment's last page.
        """
    @property
    def entries(self, /) -> list[NtHeapEntry]:
        """
        The segment's entry chain; empty unless entries were listed.
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
        Where and why the chain walk ended before `last_valid_entry`; None
        when it did not.
        """
    @property
    def uncommitted(self, /) -> list[NtUncommittedRange]:
        """
        Uncommitted ranges the entry chain skips over.
        """
    @property
    def uncommitted_pages(self, /) -> int: ...

@final
class NtLfhUserBlocks(BaseRecord):
    """
    A legacy-LFH user block region living inside one busy NT-heap entry.
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
        The region's blocks; empty unless entries were listed.
        """
    @property
    def busy_bitmap(self, /) -> list[int]:
        """
        One bit per block, set when busy: block `i` is byte `i / 8`, bit
        `i % 8`.
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
        Bytes between consecutive blocks.
        """
    @property
    def subsegment(self, /) -> int:
        """
        The owning `_HEAP_SUBSEGMENT`.
        """

@final
class NtUncommittedRange(BaseRecord):
    """
    An uncommitted range of an NT-heap segment.
    """
    @property
    def end(self, /) -> int:
        """
        Byte past the range.
        """
    @property
    def start(self, /) -> int: ...

@final
class NtVirtualBlock(BaseRecord):
    """
    An NT-heap block allocated on its own (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
    """
    @property
    def commit_size(self, /) -> int:
        """
        Committed bytes.
        """
    @property
    def entry(self, /) -> int:
        """
        The block's header.
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
        The object's type (`Directory`, `Driver`, `SymbolicLink`, ...);
        None when its header cannot be decoded.
        """

@final
class ObjectSecurity(BaseRecord):
    """
    An object's security descriptor, from its header (`!objsd`).
    """
    @property
    def descriptor(self, /) -> SecurityDescriptor |None:
        """
        `None` when the object has no descriptor.
        """
    @property
    def descriptor_address(self, /) -> int:
        """
        `fast_reference` without its count bits.
        """
    @property
    def fast_reference(self, /) -> int:
        """
        `SecurityDescriptor`, a fast reference (reference count in the
        low bits).
        """
    @property
    def header(self, /) -> int:
        """
        The `_OBJECT_HEADER`.
        """
    @property
    def object(self, /) -> int: ...

@final
class PageLocation(BaseRecord):
    """
    A PFN's `PageLocation`: the list the page is on.
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
    One page-table level of a walk, its entry decoded with WinDbg-style
    flags. For an entry pointing at a lower table, `writable`, `user`,
    and `nx` are the restrictions it places on what lies below.
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
        Whether the entry maps a large page rather than a lower table.
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
        Which BAR (0-5).
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
        The register as read (both halves for a 64-bit BAR).
        """

@final
class PciBus(BaseRecord):
    """
    A bus pci.sys enumerated, with the devices on it and the buses behind
    its bridges.
    """
    @property
    def bridge_pdo(self, /) -> int:
        """
        The bridge's physical device object; 0 for a root bus.
        """
    @property
    def child_buses(self, /) -> list[PciBus]: ...
    @property
    def devices(self, /) -> list[PciTreeDevice]: ...
    @property
    def extension(self, /) -> int:
        """
        pci.sys's bus extension.
        """
    @property
    def number(self, /) -> int: ...
    @property
    def subordinate(self, /) -> int:
        """
        The highest bus number behind this one.
        """

@final
class PciBuses(BaseRecord):
    """
    A type 1 or 2 header's bus numbers.
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
    A capability-list entry.
    """
    @property
    def id(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        The capability's name, when it is a known one.
        """
    @property
    def offset(self, /) -> int:
        """
        Its offset in configuration space.
        """
    @property
    def version(self, /) -> int |None:
        """
        The version of an extended capability; `None` for a standard one.
        """

@final
class PciConfigBytes(BaseRecord):
    """
    Requested raw configuration bytes.
    """
    @property
    def bytes(self, /) -> str:
        """
        The bytes, as hex.
        """
    @property
    def offset(self, /) -> int:
        """
        Offset of the first byte.
        """

@final
class PciFunction(BaseRecord):
    """
    One function's decoded configuration space.
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
        The class code's name, when it is a known one.
        """
    @property
    def command(self, /) -> int: ...
    @property
    def command_flags(self, /) -> list[str]:
        """
        The names of the command register's set bits.
        """
    @property
    def config(self, /) -> PciConfigBytes |None:
        """
        The requested raw range (`raw=True`), else `None`.
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
        PCI Express extended capabilities; empty for a conventional
        function, or when only 256 bytes were read.
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
        The names of the status register's set bits.
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
    The functions a `!pci` scan found.
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
        pci.sys's segment record.
        """
    @property
    def root_buses(self, /) -> list[PciBus]: ...
    @property
    def segment(self, /) -> int: ...

@final
class PciTree(BaseRecord):
    """
    The PCI hierarchy pci.sys tracks (`!pcitree`).
    """
    @property
    def errors(self, /) -> list[str]:
        """
        Each unreadable bus or function, whose list the walk left.
        """
    @property
    def segments(self, /) -> list[PciSegment]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its bound before the end.
        """

@final
class PciTreeDevice(BaseRecord):
    """
    A device pci.sys enumerated (`!pcitree`).
    """
    @property
    def base_class(self, /) -> int: ...
    @property
    def bus(self, /) -> int: ...
    @property
    def class_name(self, /) -> str |None:
        """
        The class code's name, when it is a known one.
        """
    @property
    def device(self, /) -> int: ...
    @property
    def device_id(self, /) -> int: ...
    @property
    def extension(self, /) -> int:
        """
        pci.sys's device extension.
        """
    @property
    def function(self, /) -> int: ...
    @property
    def header_type(self, /) -> int: ...
    @property
    def instance_path(self, /) -> str |None:
        """
        The device's PnP instance path, when pci.sys recorded one.
        """
    @property
    def pdo(self, /) -> int:
        """
        The device's physical device object.
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
    A processor's KPCR and KPRCB essentials (`!pcr`). Fields that can fail
    to read on their own are diagnostics.
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
        The processor's idle `_KTHREAD`.
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
        The task state segment's address.
        """

@final
class Peb(BaseRecord):
    """
    A process's `_PEB` (`!peb`), each field read on its own.
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
        The WOW64 `_PEB32`; `None` for a native process.
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
    A WOW64 process's 32-bit `_PEB32`, each field read on its own.
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
    A decoded `_MMPFN` record (`!pfn`). Union members the page's state
    does not use are `None`: the list links unless the page is on a list,
    `share_count` and `ws_index` unless it is active, `event` unless it
    is in transition.
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
        Unavailable when this build's `_MMPFN` has no `PageColor`.
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
        The PFN of the page table holding the page's PTE.
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
    What `!pfn` was asked for.
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
    PnP triage buckets from one bounded walk of the device tree
    (`!pnptriage`).
    """
    @property
    def not_started(self, /) -> list[DevNodeSummary]:
        """
        Nodes neither started nor removed or deleted.
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
        Nodes walked.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its 4096-node bound.
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
        The allocation's address, just past the header.
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
        Block size in bytes, header included.
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
        The requested address's offset into the block, when it holds it.
        """

@final
class PoolIrp(BaseRecord):
    """
    An IRP `!irpfind` found in pool.
    """
    @property
    def completed(self, /) -> bool:
        """
        Whether every stack location is used up: the IRP is being (or
        was) completed.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The driver owning the current stack location's device; None when
        unresolved.
        """
    @property
    def irp(self, /) -> Irp: ...
    @property
    def mdl_process(self, /) -> int |None:
        """
        `MdlAddress->Process`; None without an MDL.
        """
    @property
    def original_file_object(self, /) -> int:
        """
        `Tail.Overlay.OriginalFileObject`.
        """
    @property
    def pool_header(self, /) -> int |None:
        """
        The `_POOL_HEADER` before it; None for a big-pool allocation.
        """
    @property
    def tag(self, /) -> str:
        """
        The allocation's pool tag.
        """

@final
class PoolMatch(BaseRecord):
    """
    A pool allocation carrying the searched tag (`!poolfind`).
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
        Where it was found: a pool range scan or the big-pool table.
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
        The large allocation holding the address, when it is one.
        """
    @property
    def blocks(self, /) -> list[PoolBlock]: ...
    @property
    def message(self, /) -> str |None:
        """
        Why no blocks were decoded, when none were.
        """
    @property
    def near_symbol(self, /) -> str |None:
        """
        The symbol nearest the address, when one resolved.
        """
    @property
    def page(self, /) -> int:
        """
        The page's address.
        """
    @property
    def page_kind(self, /) -> str:
        """
        How the page is laid out: its pool kind, or why it could not be
        decoded.
        """
    @property
    def region(self, /) -> PoolRegion |None:
        """
        The pool range holding the page, when known.
        """
    @property
    def segment_heap_hint(self, /) -> str |None:
        """
        Set when the page belongs to the segment heap, whose blocks have no
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
        Index in `blocks` of the block holding the requested address.
        """

@final
class PoolProblem(BaseRecord):
    """
    A pool header inconsistency.
    """
    @property
    def header(self, /) -> int:
        """
        The header it is found at.
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
        End of the range (exclusive).
        """
    @property
    def name(self, /) -> str: ...
    @property
    def pages(self, /) -> int:
        """
        Pages the range spans, mapped or not.
        """
    @property
    def scanned_pages(self, /) -> int:
        """
        Mapped pages read.
        """
    @property
    def start(self, /) -> int: ...
    @property
    def stopped_at(self, /) -> int |None:
        """
        The mapped page the scan stopped at, unread, when the match bound
        or an interrupt ended it early.
        """

@final
class PoolRegion(BaseRecord):
    """
    A virtual pool range.
    """
    @property
    def end(self, /) -> int:
        """
        End of the range (exclusive).
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
        How the big-pool table read, when it was searched.
        """
    @property
    def found(self, /) -> int:
        """
        Matches found, including those past the listing bound.
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
        The pool the search was limited to, if any.
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
    One tag's pool usage (`!poolused`), in bytes. `None` when the tracker
    has no entry for that pool.
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
        How the big-pool table read.
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
        The tag pattern rows were filtered by, if any.
        """
    @property
    def tracker_status(self, /) -> str:
        """
        How the pool tracker table read.
        """

@final
class PoolValidation(BaseRecord):
    """
    The blocks of the pool page holding an address, checked for header
    consistency (`!poolval`).
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
        The processor's idle `_KTHREAD`.
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
        `None` when the type's size is unknown.
        """
    @property
    def location(self, /) -> LocalVariableLocation: ...
    @property
    def name(self, /) -> str: ...
    @property
    def parameter(self, /) -> bool:
        """
        Whether it is a parameter rather than a local.
        """
    @property
    def type_name(self, /) -> str:
        """
        The PDB type spelling.
        """

@final
class Process:
    """
    One process: identity fields plus views bound to its address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> ApcQueues:
        """
        Decode kernel and user APC queues for this process (`!apc`).
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
        Evaluate a debugger expression in this process's symbol scope.
        """
    def handle(self, /, value: int) -> HandleEntry:
        """
        Decode a handle in this process's handle table.
        """
    def handle_traces(self, /, handle: int |None = None, max_traces: int |None = None) -> HandleTraces:
        """
        The stacks handle tracing recorded for this process's handles, newest
        first (`!htrace`): those of `handle` when given, at most `max_traces`.
        `debug_info` is `None` when tracing is off for the process.
        """
    def handles(self, /, limit: int = 256) -> HandleTable:
        """
        Enumerate up to `limit` handles in this process's handle table.
        """
    @property
    def heaps(self, /) -> Heaps:
        """
        The heaps in this process's PEB.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory through this process's page tables.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Modules from this process's PEB loader lists.
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
        The process `_PEB` cursor, or `None` when it has no PEB.
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
        The region holding `address` as `VirtualQuery` reports it (`!vprot`):
        base, allocation base and protection, region size, state, protection,
        and type.
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
        Symbols resolved in this process's address space.
        """
    @property
    def threads(self, /) -> Threads:
        """
        Windows threads owned by this process.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The process's identity as a plain `dict` (`pid`, `name`, `dtb`,
        `eprocess`, `wow64`), the shape MCP renders.
        """
    def token(self, /) -> Token:
        """
        The process token and its security information.
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types and cursors bound to this process's address space.
        """
    @property
    def wow64(self, /) -> bool:
        """
        Whether this process has a WOW64 (32-bit) PEB.
        """

@final
class ProcessGlobalFlags(BaseRecord):
    """
    A process's `_PEB.NtGlobalFlag`.
    """
    @property
    def flags(self, /) -> list[GlobalFlag]: ...
    @property
    def value(self, /) -> int: ...

@final
class ProcessIdentity(BaseRecord):
    """
    A process's identity (`ps`, `!process 0 0`).
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
        Whether it is a 32-bit process running under WOW64.
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
    A process's `_RTL_USER_PROCESS_PARAMETERS`: its strings read on their
    own, each unavailable when paged out.
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
    Running processes keyed by PID (`dbg.processes`). Iterating walks the
    process list afresh; `find(name)` matches image names.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, pid: int, /) -> Process: ...
    def __iter__(self, /) -> ProcessIterator: ...
    def __len__(self, /) -> int: ...
    def find(self, /, name: str) -> list[Process]:
        """
        Find every exact image-name match, case-insensitively.
        """
    def get(self, /, pid: int) -> Process |None:
        """
        Find a process by PID; a missing PID returns `None`.
        """

@final
class ProcessorError(BaseRecord):
    """
    A processor whose state could not be read.
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
        Address of the `_CONTEXT` embedded in the processor state.
        """
    @property
    def name(self, /) -> str:
        """
        The type name.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes of the structure.
        """
    @property
    def special_registers(self, /) -> Diagnostic[SpecialRegistersArea]: ...

@final
class PteWalk(BaseRecord):
    """
    A full page-table walk (`!pte`): the levels reached, top down (a
    large-page mapping short-circuits, so fewer levels).
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
    A numbered queued spinlock and the processors owning or waiting for it.
    """
    @property
    def holders(self, /) -> list[QueuedLockHolder]: ...
    @property
    def lock(self, /) -> int |None:
        """
        The spinlock, from the first processor entry that names it.
        """
    @property
    def name(self, /) -> str:
        """
        The queue number's name without its `LockQueue` prefix and `Lock`
        suffix (`IoCancel`), or `LockQueue[n]` when unknown.
        """
    @property
    def number(self, /) -> int:
        """
        Its `_KSPIN_LOCK_QUEUE_NUMBER`.
        """

@final
class QueuedLockHolder(BaseRecord):
    """
    A processor's entry in a queued spinlock it owns or waits for.
    """
    @property
    def processor(self, /) -> int: ...
    @property
    def reason(self, /) -> str |None:
        """
        How a corrupt entry disagrees; `None` otherwise.
        """
    @property
    def state(self, /) -> str:
        """
        `owner`, `waiting`, or `corrupt` (the entry's bits and the queue
        links disagree).
        """
    @property
    def wait_order(self, /) -> int |None:
        """
        1-based place in the wait queue behind the owner; `None` unless
        waiting.
        """

@final
class QueuedLocks(BaseRecord):
    """
    Every numbered queued spinlock across the processors (`!qlocks`).
    """
    @property
    def errors(self, /) -> list[ProcessorError]: ...
    @property
    def locks(self, /) -> list[QueuedLock]: ...
    @property
    def processors(self, /) -> list[int]:
        """
        Processors whose `_KPRCB.LockQueue` was read.
        """

@final
class ReadyQueue(BaseRecord):
    """
    One processor's ready list for one priority.
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
        Non-empty queues.
        """
    @property
    def total(self, /) -> int:
        """
        Threads listed across `queues`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry bound.
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
        The thread decoded.
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
    A process's VAD region collection (`!vad`).
    """
    def __contains__(self, addr: int, /) -> bool: ...
    def __getitem__(self, addr: int, /) -> MemoryRegion: ...
    def __iter__(self, /) -> MemoryRegionIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> MemoryRegion |None:
        """
        Find the VAD region containing `addr`, or return `None`.
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
        An int, or for a vector register a `0x`-prefixed 32-digit hex
        string.
        """

@final
class Registers:
    """
    A register file bound to a vCPU or recovered frame context.
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getattr__(self, name: str, /) -> int: ...
    def __getitem__(self, name: str, /) -> int: ...
    def __iter__(self, /) -> NameIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None: ...
    def __setitem__(self, name: str, value: int, /) -> None: ...
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
    The kernel's executive-resource list (`!locks`).
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
    A thread owning an executive resource.
    """
    @property
    def count(self, /) -> int:
        """
        How many times the thread acquired it.
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
        Whether the walk stopped at its bound before the end.
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
        Page-table pages read.
        """

@final
class RunStatus(BaseRecord):
    """
    Whether the target runs and where it stopped.
    """
    @property
    def attached_process(self, /) -> ProcessIdentity |None:
        """
        The process chosen with `.process` whose memory `dt`, `dq`, ...
        read; it survives resumes.
        """
    @property
    def coherent(self, /) -> bool:
        """
        False after a reboot until the kernel's loaded-module list exists:
        process and module enumeration is not yet meaningful.
        """
    @property
    def current_thread(self, /) -> str:
        """
        The backend thread/vCPU selected.
        """
    @property
    def kernel_base(self, /) -> int:
        """
        The rediscovered `nt` base; it changes across a reboot.
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer when halted, None while running.
        """
    @property
    def running(self, /) -> bool: ...
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        For a vCPU halted in the Windows hypervisor, the VTL states it
        saved for the vCPU's virtual processor, VTL0's first.
        """
    @property
    def stopped_process(self, /) -> ProcessIdentity |None:
        """
        The process whose page tables the stopped vCPU has loaded.
        """
    @property
    def stopped_thread(self, /) -> ThreadSummary |None:
        """
        The Windows thread the stopped vCPU runs; its owner can differ
        from `stopped_process` (`KeStackAttachProcess`).
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to `rip` when halted; code outside NT is named
        for what it is (`hvix64+0x3a6bde`).
        """

@final
class RunningProcessor(BaseRecord):
    """
    A processor's running, next, and idle threads (`!running`).
    """
    @property
    def current_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The thread running on it; `None` inside when there is none.
        """
    @property
    def idle_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The processor's idle thread.
        """
    @property
    def index(self, /) -> int:
        """
        Processor number.
        """
    @property
    def kpcr(self, /) -> Diagnostic[int]: ...
    @property
    def next_thread(self, /) -> Diagnostic[ThreadSummary |None]:
        """
        The thread selected to run next; `None` inside when there is none.
        """
    @property
    def prcb(self, /) -> Diagnostic[int]: ...
    @property
    def short_stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The running thread's first frames; `None` unless stacks were
        requested.
        """

@final
class RunningProcessors(BaseRecord):
    """
    Every processor's running threads (`!running`).
    """
    @property
    def processors(self, /) -> list[RunningProcessor]: ...

@final
class RuntimeFunction(BaseRecord):
    """
    One function-table entry and its unwind data. Addresses are absolute;
    `*_rva` fields are the raw image-relative values.
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
        The decoded unwind data, None when it is unreadable.
        """
    @property
    def unwind_data(self, /) -> int:
        """
        The entry's raw unwind word: the unwind info's RVA, or ARM64's
        packed unwind data.
        """
    @property
    def unwind_info(self, /) -> int |None:
        """
        The unwind info's address; None for ARM64 packed unwind data.
        """

@final
class SavedVtlState(BaseRecord):
    """
    One VTL of a virtual processor, as the Windows hypervisor last saved
    it in the VTL's Enlightened VMCS. A VMCS holds no general-purpose
    register but `rsp`.
    """
    @property
    def cr0(self, /) -> int: ...
    @property
    def cr3(self, /) -> int:
        """
        The VTL's page-table root.
        """
    @property
    def cr4(self, /) -> int: ...
    @property
    def cs(self, /) -> int: ...
    @property
    def current(self, /) -> bool:
        """
        Whether the VP's assist page names this state's eVMCS current:
        the VTL the hypervisor was entered from, or is about to enter.
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
        The physical address of the eVMCS page the state was read from.
        """
    @property
    def exit_reason(self, /) -> int:
        """
        The VM-exit reason the VTL last left with: the basic reason in
        bits 15:0, bit 31 set for a failed VM entry.
        """
    @property
    def exit_reason_name(self, /) -> str |None:
        """
        The exit reason's name (`HLT`, `VMCALL`, ...), when it is a
        common one.
        """
    @property
    def fs(self, /) -> int: ...
    @property
    def fs_base(self, /) -> int: ...
    @property
    def gs(self, /) -> int: ...
    @property
    def gs_base(self, /) -> int: ...
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
        The symbol at `rip` in the VTL's own address space, when one
        resolved.
        """
    @property
    def vtl(self, /) -> int:
        """
        0 or 1.
        """

@final
class SchedulerError(BaseRecord):
    """
    A per-processor or per-queue read that failed during a scheduler walk.
    """
    @property
    def message(self, /) -> str: ...
    @property
    def processor(self, /) -> int |None:
        """
        The processor it concerns, if any.
        """
    @property
    def queue(self, /) -> int |None:
        """
        The queue it concerns, if any.
        """

@final
class Section(BaseRecord):
    """
    One PE section: its name, RVA, mapped size, and `rwx` permissions.
    """
    @property
    def name(self, /) -> str:
        """
        The section name (`.text`).
        """
    @property
    def permissions(self, /) -> str:
        """
        Mapped permissions as `rwx`, `-` for a missing one.
        """
    @property
    def rva(self, /) -> int:
        """
        Its offset from the image base.
        """
    @property
    def size(self, /) -> int:
        """
        Its mapped size.
        """

@final
class SecureKernel:
    """
    The secure kernel (`securekernel.exe`) running in VTL1, with views bound to
    its system address space. Read-only: writes raise `NtoseyeError`.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        Base address of `securekernel.exe`.
        """
    @property
    def dtb(self, /) -> int:
        """
        The secure kernel's system page-table root.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in the secure kernel's symbol scope.
        Registers are VTL0 state and are refused.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory through the secure kernel's system page tables.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Modules the secure kernel loaded (`securekernel.exe`, `skci.dll`, ...).
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Symbols of the secure kernel's modules (`securekernel!...`). NT's
        symbols do not resolve here.
        """
    @property
    def trustlets(self, /) -> list[Trustlet]:
        """
        The secure kernel's processes (trustlets), walked afresh and validated
        against the NT process list. Raises `NtoseyeError` when this build's
        process layout is not recognized.
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types read through VTL1 memory. The public secure-kernel PDB
        carries no types; name NT's explicitly (`nt!_LIST_ENTRY`).
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
        The names of the control bits set.
        """
    @property
    def dacl(self, /) -> Diagnostic[Acl |None]:
        """
        Its value is `None` when absent or a null (unrestricted) ACL.
        """
    @property
    def group(self, /) -> Diagnostic[Sid |None]:
        """
        The group SID; its value is `None` for a null group.
        """
    @property
    def owner(self, /) -> Diagnostic[Sid |None]:
        """
        The owner SID; its value is `None` for a null owner.
        """
    @property
    def revision(self, /) -> Diagnostic[int]: ...
    @property
    def sacl(self, /) -> Diagnostic[Acl |None]:
        """
        Its value is `None` when absent or a null ACL.
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
        Segment contexts (`SegContexts`), one per page-segment size class.
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
        Size of `_HEAP_VS_CHUNK_HEADER` in bytes: 16 on x64, 8 on x86;
        every VS chunk starts with one.
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
        Largest allocation this context serves, in bytes.
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
    `ntdll!RtlpHpHeapGlobals`: the keys a segment heap encodes with.
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
        The session's processes.
        """

@final
class SessionProcess(BaseRecord):
    """
    A process and its session id.
    """
    @property
    def process(self, /) -> ProcessIdentity:
        """
        The process record.
        """
    @property
    def session(self, /) -> int |None:
        """
        `None` when neither `_EPROCESS` nor the primary token yields one.
        """

@final
class SessionProcesses(BaseRecord):
    """
    The processes of a session, optionally matching an image glob
    (`!sprocess`).
    """
    @property
    def detailed(self, /) -> bool:
        """
        Whether the detailed listing (`-f`) was requested.
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
        Whether the process walk stopped at its bound.
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
        The session requested; `None` when all were (or the selected
        process has no known id).
        """
    @property
    def sessions(self, /) -> list[Session]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the process walk stopped at its bound.
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
        The built-in name, when it is a well-known SID.
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
        `None` when the PDB records no column.
        """
    @property
    def file(self, /) -> str:
        """
        The source file as the PDB records it.
        """
    @property
    def line(self, /) -> int: ...
    @property
    def local_exists(self, /) -> bool:
        """
        Whether `local_path` exists on this machine.
        """
    @property
    def local_path(self, /) -> str |None:
        """
        The file after source-path remapping, when one applies.
        """

@final
class SpecialRegistersArea(BaseRecord):
    """
    Where `_KSPECIAL_REGISTERS` sits in a processor state.
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
        Bytes of the structure.
        """

@final
class SsdtEntry(BaseRecord):
    """
    A system-service table slot.
    """
    @property
    def index(self, /) -> int:
        """
        The system-service number.
        """
    @property
    def module(self, /) -> str |None:
        """
        The module containing the routine; None when none does.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The routine's symbol; None when none resolves.
        """
    @property
    def target(self, /) -> int:
        """
        The routine the slot resolves to.
        """

@final
class SsdtTable(BaseRecord):
    """
    A system-service table: the kernel SSDT or the win32k shadow (`ssdt`).
    """
    @property
    def base(self, /) -> int: ...
    @property
    def entries(self, /) -> list[SsdtEntry]: ...
    @property
    def label(self, /) -> str:
        """
        Which table.
        """
    @property
    def limit(self, /) -> int:
        """
        The number of services.
        """

@final
class StackFrame(BaseRecord):
    """
    One frame of a walked stack.
    """
    @property
    def index(self, /) -> int:
        """
        The frame's position in the walked stack, innermost 0.
        """
    @property
    def ip(self, /) -> int:
        """
        The instruction pointer.
        """
    @property
    def source(self, /) -> str:
        """
        How the frame was recovered: `current`, `seed`, `unwind`, or `scan`.
        """
    @property
    def source_location(self, /) -> SourceLocation |None:
        """
        The source line at `ip`, when line information resolves it.
        """
    @property
    def sp(self, /) -> int:
        """
        The stack pointer.
        """
    @property
    def symbol(self, /) -> str:
        """
        The symbol at `ip`; empty when none resolved.
        """

class Stop:
    """
    Why the target stopped. Every stop is one of the nested kinds; test with
    `isinstance(stop, Stop.Breakpoint)` or `match`. A stop is bound to the
    target generation it happened in.
    """
    def __repr__(self, /) -> str: ...
    @property
    def breakpoints(self, /) -> list[Breakpoint]:
        """
        Breakpoint or watchpoint handles for this stop; empty on other kinds,
        so `bp in stop.breakpoints` works on any stop.
        """
    @property
    def cpu(self, /) -> Cpu:
        """
        Processor that stopped.
        """
    @property
    def process(self, /) -> Process |None:
        """
        Process whose page tables were active at this stop, if known.
        """
    def record(self, /) -> ExceptionRecord:
        """
        Decode the current exception record (`.exr -1`).
        """
    @property
    def rip(self, /) -> int |None:
        """
        Instruction pointer captured at this stop.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        Nearest symbol captured at this stop, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        Windows thread executing on the stopped vCPU, if known.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @final
    class Breakpoint(Stop):
        """
        A code breakpoint or data-watchpoint hit. `condition_error` is set when
        its condition failed to evaluate; such a hit is surfaced, not skipped.
        """
        __match_args__: Final = ("condition_error", "_context")
        def __new__(cls, /, condition_error: str |None, _context: _StopContext) -> Stop.Breakpoint: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def condition_error(self, /) -> str |None:
            """
            Why the breakpoint's condition failed to evaluate, if it did.
            """
    @final
    class Bugcheck(Stop):
        """
        The guest is bugchecking (BSOD); `info` is the bugcheck analysis.
        """
        __match_args__: Final = ("info", "_context")
        def __new__(cls, /, info: Bugcheck |None, _context: _StopContext) -> Stop.Bugcheck: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def info(self, /) -> Bugcheck |None:
            """
            The bugcheck analysis (`!analyze`'s code, parameters, and culprit).
            """
    @final
    class Exception(Stop):
        """
        A Windows exception: `code` (NTSTATUS), whether it is the first chance,
        and the faulting address.
        """
        __match_args__: Final = ("code", "first_chance", "address", "_context")
        def __new__(cls, /, code: int, first_chance: bool |None, address: int |None, _context: _StopContext) -> Stop.Exception: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def address(self, /) -> int |None:
            """
            The faulting address, when the exception carries one.
            """
        @property
        def code(self, /) -> int:
            """
            The exception's NTSTATUS code.
            """
        @property
        def first_chance(self, /) -> bool |None:
            """
            Whether this is the first chance (`None` when the backend does not say).
            """
    @final
    class Interrupt(Stop):
        """
        A break-in (`interrupt()`), or another stop without an exception code.
        """
        __match_args__: Final = ("_context",)
        def __new__(cls, /, _context: _StopContext) -> Stop.Interrupt: ...
        @property
        def _context(self, /) -> _StopContext: ...
    @final
    class Reboot(Stop):
        """
        The guest rebooted; every earlier handle is now stale. While `coherent`
        is false the kernel's module list does not exist yet: kernel symbols
        and breakpoints work, and `run()` lets boot continue.
        """
        __match_args__: Final = ("kernel_base", "coherent", "_context")
        def __new__(cls, /, kernel_base: int |None, coherent: bool, _context: _StopContext) -> Stop.Reboot: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def coherent(self, /) -> bool:
            """
            Whether the kernel's module list exists yet.
            """
        @property
        def kernel_base(self, /) -> int |None:
            """
            The new kernel's base address (moved by KASLR).
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
    A PDB type bound to an address in an address space: a reflective cursor.
    """
    def __dir__(self, /) -> list[str]:
        """
        PDB fields and the cursor's public members, for tab completion.
        """
    def __eq__(self, other: object, /) -> bool: ...
    def __getattr__(self, name: str, /) -> Any:
        """
        Reflective field access; missing fields raise `AttributeError`.
        """
    def __getitem__(self, key: str |int, /) -> Any:
        """
        The field value, or an integer sibling cursor index (`((T*)p)[i]`).
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None:
        """
        `cursor.Field = value`; only actual PDB fields are assignable.
        """
    def __setitem__(self, name: str, value: Any, /) -> None:
        """
        Write a PDB field by name.
        """
    @property
    def addr(self, /) -> int:
        """
        Address this cursor refers to.
        """
    def address_of(self, /, name: str) -> int:
        """
        The address of field `name`, as C's `&cursor->name`: what a watchpoint
        or a raw read needs. A bitfield's address is its storage unit's.
        """
    def cast(self, /, type_name: str) -> Struct:
        """
        Reinterpret this address as another PDB type.
        """
    def follow(self, /, name: str) -> Struct:
        """
        Follow a pointer field to its typed target.
        """
    def read(self, /) -> dict[str, Any]:
        """
        Read one whole-struct snapshot into a dictionary; nested struct fields are omitted.
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
    A `_SUBSECTION` following a control area.
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
        The MM protection of `SubsectionFlags`.
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
        The symbol's address.
        """
    @property
    def module(self, /) -> str:
        """
        The module the symbol belongs to.
        """
    @property
    def name(self, /) -> str:
        """
        The symbol name.
        """
    @property
    def offset(self, /) -> int:
        """
        How far past the symbol the queried address is.
        """

@final
class SymbolCandidate(BaseRecord):
    """
    One definition a symbol name resolves to.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def compiland(self, /) -> str |None:
        """
        The defining compiland, for a private symbol.
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
    One problem found while loading a module's symbols.
    """
    @property
    def compiland(self, /) -> str |None:
        """
        The compiland it concerns, when it is compiland-specific.
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
    The outcome of a symbol reload: how many modules loaded, lacked a
    PDB, were skipped, or failed, plus the first diagnostics (bounded).
    """
    @property
    def diagnostic_count(self, /) -> int:
        """
        All diagnostics, including those past `diagnostics`' bound.
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
        Symbol-bearing modules gone since the previous refresh.
        """

@final
class SymbolSearchMatch(BaseRecord):
    """
    A symbol a name search matched.
    """
    @property
    def address(self, /) -> int |None:
        """
        `None` when the match does not resolve to a unique address.
        """
    @property
    def module(self, /) -> str |None: ...
    @property
    def name(self, /) -> str: ...

@final
class Symbols:
    """
    Symbol lookup scoped to an address space: `dbg.symbols`, `proc.symbols`.
    """
    def __contains__(self, name: str, /) -> bool:
        """
        Whether at least one symbol candidate has this name.
        """
    def __getitem__(self, name: str, /) -> int:
        """
        Resolve a symbol to its address, raising `SymbolNotFoundError` when absent.
        """
    def candidates(self, /, name: str) -> list[SymbolCandidate]:
        """
        Return every exact candidate, including module and private-compiland provenance.
        """
    def get(self, /, name: str) -> int |None:
        """
        Resolve a symbol to its address, or return `None` when absent.
        """
    def locals_at(self, /, addr: int) -> list[ProcedureLocal]:
        """
        List PDB local/parameter layouts covering `addr`, without evaluating values.
        """
    def nearest(self, /, addr: int) -> Symbol |None:
        """
        Return the nearest symbol identity, or `None` if no symbol covers `addr`.
        """
    @property
    def path(self, /) -> list[str]:
        """
        Ordered symbol sources (`.sympath`); assignment replaces the full path.
        """
    @path.setter
    def path(self, /, sources: Sequence[str]) -> None: ...
    def reload(self, /) -> SymbolReloadReport:
        """
        Reload symbols in this space and re-resolve symbolic breakpoints.
        """
    def reset_path(self, /) -> None:
        """
        Restore the default symbol sources (`.symfix`).
        """
    def search(self, /, query: str, limit: int = 50) -> list[SymbolSearchMatch]:
        """
        Fuzzy-search symbol names; `module!query` scopes the search to a module.
        """
    def source_addresses(self, /, file: str, line: int) -> list[int]:
        """
        Resolve a source file and line to every matching loaded address.
        """
    def source_location(self, /, addr: int) -> SourceLocation |None:
        """
        Resolve an address to PDB source metadata and its remapped local path.
        """
    @property
    def source_path(self, /) -> list[str]:
        """
        Ordered source-path mappings (`.srcpath`); assignment replaces them.
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
        Processes counted, including those past the listing bound.
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
    A run of free system PTEs: clear bits in an allocation bitmap.
    """
    @property
    def pte(self, /) -> int:
        """
        Address of the run's first PTE.
        """
    @property
    def ptes(self, /) -> int:
        """
        Length in PTEs.
        """
    @property
    def va(self, /) -> int |None:
        """
        Virtual address that PTE maps, when `MmPteBase` is known.
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
        Virtual address `base_pte` maps; `None` without `MmPteBase`.
        """
    @property
    def bitmap(self, /) -> int: ...
    @property
    def bitmap_bits(self, /) -> int: ...
    @property
    def bitmap_free(self, /) -> int:
        """
        Free PTEs counted from the bitmap's clear bits.
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
        The free runs in address order, when listing was requested.
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
        PTEs each bitmap bit covers.
        """
    @property
    def total(self, /) -> int:
        """
        `TotalSystemPtes`: PTEs made available so far.
        """
    @property
    def tracking(self, /) -> bool:
        """
        Whether the kernel tracks which driver mapped each PTE (`TrackPtes`).
        """
    @property
    def unreadable_bitmap_bytes(self, /) -> int:
        """
        Bitmap bytes that could not be read (counted as allocated).
        """
    @property
    def unscanned_bitmap_bits(self, /) -> int:
        """
        Bits past the bound on how much of one bitmap is read; left out of
        every count.
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
    What a crash dump's header records.
    """
    @property
    def bugcheck_code(self, /) -> int: ...
    @property
    def bugcheck_parameters(self, /) -> list[int]: ...
    @property
    def directory_table_base(self, /) -> int:
        """
        The kernel page-table root the dump records.
        """
    @property
    def exception_code(self, /) -> int |None:
        """
        The exception code the dump records.
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
        When the dump was taken (FILETIME).
        """
    @property
    def triage_overflowed(self, /) -> bool:
        """
        Whether the dump's triage data overflowed.
        """
    @property
    def uptime_seconds(self, /) -> int |None:
        """
        Seconds the system had been up.
        """

@final
class TargetKernel(BaseRecord):
    """
    The kernel image's identity.
    """
    @property
    def base(self, /) -> int: ...
    @property
    def file_version(self, /) -> str |None: ...
    @property
    def name(self, /) -> str:
        """
        The image's file name.
        """
    @property
    def pdb_age(self, /) -> int |None:
        """
        The PDB's age.
        """
    @property
    def pdb_guid(self, /) -> str |None:
        """
        The PDB's GUID, identifying its symbols.
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
    The target's UTC time and uptime (`.time`).
    """
    @property
    def interrupt_time(self, /) -> int |None:
        """
        `KUSER_SHARED_DATA.InterruptTime`: 100 ns units since boot, the
        clock timers' `due_time` counts in.
        """
    @property
    def system_time(self, /) -> int |None:
        """
        The target's UTC time (FILETIME).
        """
    @property
    def system_time_iso(self, /) -> str |None:
        """
        `system_time` as ISO 8601.
        """
    @property
    def uptime(self, /) -> str |None:
        """
        The uptime, formatted.
        """
    @property
    def uptime_seconds(self, /) -> int |None:
        """
        Seconds since boot.
        """

@final
class TargetVersion(BaseRecord):
    """
    The target's build, architecture, kernel, symbols, debugger version,
    time, and dump metadata (`vertarget`).
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
        The crash dump's header; `None` for a live target.
        """
    @property
    def kernel(self, /) -> TargetKernel |None:
        """
        The kernel image; `None` when it was not found.
        """
    @property
    def major_version(self, /) -> int |None: ...
    @property
    def minor_version(self, /) -> int |None: ...
    @property
    def processors(self, /) -> int |None:
        """
        How many processors the target has.
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
        The kernel's symbol status label; `None` when the kernel was not
        found.
        """
    @property
    def time(self, /) -> TargetTime: ...

@final
class Teb(BaseRecord):
    """
    A thread's `_TEB` (`!teb`), each field read on its own.
    """
    @property
    def activation_context(self, /) -> Diagnostic[int |None]:
        """
        The active activation context; value `None` when there is none.
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
        The WOW64 `_TEB32`; `None` for a native thread.
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
        `WowTebOffset`: the byte offset to the WOW64 `_TEB32` (0 for none).
        """

@final
class Teb32(BaseRecord):
    """
    A WOW64 thread's 32-bit `_TEB32`, each field read on its own.
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
    One Windows thread. The ETHREAD address is its identity within a debugger.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> ApcQueues:
        """
        Decode this thread's APC lists (`!apc`).
        """
    def backtrace(self, /, limit: int = 64) -> list[Frame]:
        """
        Recover this thread's stack from live registers or its parked context.
        A thread whose processor is halted in the Windows hypervisor unwinds
        from the VTL0 state the hypervisor saved, where NT left off.
        """
    @property
    def cpu(self, /) -> Cpu |None:
        """
        The processor the thread is running on, or `None` when it is not running.
        """
    @property
    def ethread(self, /) -> int:
        """
        The `_ETHREAD` address: the thread's identity.
        """
    def inspect(self, /) -> ThreadSummary:
        """
        Thread summary and saved scheduling details (`!thread`).
        """
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` address.
        """
    def last_error(self, /) -> LastError:
        """
        Decode the thread's Win32 last-error and NTSTATUS values (`!gle`).
        """
    @property
    def object(self, /) -> Struct:
        """
        The typed `_ETHREAD` object.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The owning process's id.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The owning process.
        """
    @property
    def state(self, /) -> int |None:
        """
        The scheduler state, a `_KTHREAD_STATE` member (`IntEnum`).
        """
    @property
    def teb(self, /) -> Struct |None:
        """
        The process-bound `_TEB`, or `None` for kernel threads.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread id (`None` for a thread that has none, like idle threads).
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The thread as a plain `dict`, the shape MCP renders.
        """
    def trap_frame(self, /) -> TrapFrame:
        """
        Decode the saved `_KTRAP_FRAME` (`!trap`).
        """
    @property
    def wait_reason(self, /) -> int |None:
        """
        Why the thread waits, a `_KWAIT_REASON` member (`IntEnum`).
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
    A thread's state and walked stack (`!stacks`).
    """
    @property
    def error(self, /) -> str |None:
        """
        Why the stack could not be walked, if it could not.
        """
    @property
    def frames(self, /) -> list[StackFrame]:
        """
        Frames, innermost first: the top one at level 0, up to 32 at
        level 1, up to 64 at level 2.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...
    @property
    def top_symbol(self, /) -> Diagnostic[str |None]:
        """
        The top frame's symbol.
        """
    @property
    def truncated(self, /) -> int:
        """
        Frames past the walk bound, not listed.
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
        The symbol or module filter, if one was given.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether the walk was interrupted before it finished.
        """
    @property
    def level(self, /) -> int:
        """
        Detail level (0, 1, or 2), which bounds the frames walked.
        """
    @property
    def scanned_threads(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ThreadStack]: ...

@final
class ThreadSummary(BaseRecord):
    """
    A Windows thread, as `threads`, `!thread`, and every scheduler
    listing report it. Fields the walk could not read are `None`.
    """
    @property
    def active(self, /) -> str |None:
        """
        The vCPU running the thread, when the listing resolves it; `None`
        when none runs it, and while the target runs.
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
        Current scheduling priority.
        """
    @property
    def process_name(self, /) -> str |None:
        """
        The owning process's image name.
        """
    @property
    def state(self, /) -> int |None:
        """
        `_KTHREAD.State`.
        """
    @property
    def state_name(self, /) -> str |None:
        """
        The state's name (`Running`, `Waiting`, ...).
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
        The wait reason's name (`Executive`, `UserRequest`, ...).
        """

@final
class Threads:
    """
    A thread collection: `dbg.threads` (all) or `proc.threads`.
    """
    def __contains__(self, tid: int, /) -> bool: ...
    def __getitem__(self, tid: int, /) -> Thread:
        """
        Resolve a TID, raising `KeyError` when it is not present.
        """
    def __iter__(self, /) -> ThreadIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def at(self, /, address: int) -> Thread:
        """
        Resolve an ETHREAD or KTHREAD address.
        """
    def get(self, /, tid: int) -> Thread |None:
        """
        Resolve a TID, returning `None` when it is not present.
        """

@final
class TimerBucketEnd(BaseRecord):
    """
    A timer-table bucket whose list walk did not end back at its head.
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
    Every processor's timer table (`!timer`).
    """
    @property
    def entries(self, /) -> list[TimerTableEntry]: ...
    @property
    def errors(self, /) -> list[SchedulerError]: ...
    @property
    def interrupt_time(self, /) -> Diagnostic[int]:
        """
        The interrupt time (`KUSER_SHARED_DATA.InterruptTime`) when the
        tables were read, which the entries' `due_time` counts in.
        """
    @property
    def terminations(self, /) -> list[TimerBucketEnd]:
        """
        Buckets whose walk ended abnormally.
        """
    @property
    def total(self, /) -> int:
        """
        Timers listed in `entries`.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its entry bound.
        """

@final
class TimerTableEntry(BaseRecord):
    """
    A timer found in a processor's timer table.
    """
    @property
    def bucket(self, /) -> int:
        """
        Timer-table bucket index.
        """
    @property
    def processor(self, /) -> int: ...
    @property
    def timer(self, /) -> KernelTimer: ...

@final
class Token(BaseRecord):
    """
    A process's primary token (`!token`).
    """
    @property
    def authentication_id(self, /) -> Diagnostic[int]:
        """
        The logon session's LUID.
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
        `TOKEN_TYPE`: 1 primary, 2 impersonation.
        """
    @property
    def user(self, /) -> Diagnostic[SidAndAttributes |None]:
        """
        Its value is `None` when the token names no user.
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
        Where the frame was read from.
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
    The crashing processor's `_KPRCB` essentials a triage dump recorded.
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
    The one-shot crash triage report (`!analyze`): run status, bugcheck
    or exception, backtrace, modules, dump records, and findings.
    """
    @property
    def backtrace(self, /) -> list[StackFrame] |None:
        """
        The current thread's stack; `None` while running or when the
        unwind failed (see `warnings`).
        """
    @property
    def blackboxes(self, /) -> list[BlackboxStream]: ...
    @property
    def broken_driver(self, /) -> str |None:
        """
        The driver the dump records as broken.
        """
    @property
    def bugcheck(self, /) -> Bugcheck |None:
        """
        The bugcheck, when the target is bugchecking.
        """
    @property
    def crash_context(self, /) -> CrashContext |None:
        """
        The crashing process and thread a triage dump recorded.
        """
    @property
    def culprit(self, /) -> Culprit |None:
        """
        The module the evidence blames; `None` when it names no
        non-kernel module.
        """
    @property
    def exception(self, /) -> DumpException |None:
        """
        The exception a dump recorded.
        """
    @property
    def failure_signature(self, /) -> FailureSignature |None: ...
    @property
    def modules(self, /) -> list[LoadedModule]:
        """
        Loaded modules, capped by the caller (see `modules_total`).
        """
    @property
    def modules_total(self, /) -> int:
        """
        How many modules are loaded.
        """
    @property
    def prcb(self, /) -> TriagePrcb |None:
        """
        The crashing processor a triage dump recorded.
        """
    @property
    def status(self, /) -> RunStatus:
        """
        The target's run status.
        """
    @property
    def system_info(self, /) -> DumpSystemInfo |None:
        """
        The dump's system information.
        """
    @property
    def triage_overflowed(self, /) -> bool |None:
        """
        Whether the dump's triage data overflowed; `None` for a target
        that is not a dump.
        """
    @property
    def unloaded_drivers(self, /) -> list[UnloadedDriver]: ...
    @property
    def verifier(self, /) -> VerifierFinding |None:
        """
        The Driver Verifier violation, for a verifier bugcheck.
        """
    @property
    def warnings(self, /) -> list[str]:
        """
        Best-effort collection failures that did not prevent the report.
        """
    @property
    def whea(self, /) -> WheaFinding |None:
        """
        The hardware error record, for a WHEA bugcheck.
        """

@final
class Trustlet:
    """
    An isolated user-mode process (trustlet) in VTL1, such as `LsaIso.exe`.
    Its views read through the trustlet's own page tables, which map its user
    half and the secure kernel. Read-only.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        Address of the secure kernel's process object for this trustlet.
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
        Virtual memory through the trustlet's page tables.
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
        The NT process (VTL0 side), or `None` once it has exited.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        The secure kernel's symbols, resolved in this trustlet's address space.
        The trustlet's own user-mode modules are not enumerated.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The trustlet's identity as a plain `dict` (`pid`, `name`,
        `trustlet_id`, `dtb`, `address`), the shape `!trustlets` lists.
        """
    @property
    def trustlet_id(self, /) -> int:
        """
        The trustlet ID from its creation attributes (1 for `LsaIso.exe`).
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types read through the trustlet's memory (`nt!` types by name).
        """

@final
class Type:
    """
    A named PDB struct/union layout or enum definition.
    """
    def __repr__(self, /) -> str: ...
    def at(self, /, addr: int) -> Struct:
        """
        Bind this layout to an address as a reflective struct cursor.
        """
    @property
    def fields(self, /) -> dict[str, Field]:
        """
        Field layouts by name, in offset order. Enums have no fields.
        """
    @property
    def name(self, /) -> str:
        """
        PDB type name (for example, `_EPROCESS`).
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes, including the underlying storage width for enums.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def values(self, /) -> dict[str, int]:
        """
        Enum members by name, in declaration order; raises for structs and
        unions.
        """
    def walk(self, /, head: int, link_field: str) -> list[Struct]:
        """
        Walk an intrusive list whose head is at `head` and whose links are `link_field`.
        """

@final
class TypeLayout(BaseRecord):
    """
    A struct or union's field layout (`dt`).
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
        Size in bytes.
        """

@final
class Types:
    """
    PDB types scoped to an address space: `dbg.types`, `proc.types`.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Type:
        """
        Resolve a struct, union, or enum by PDB name; unknown names raise `KeyError`.
        """
    def __repr__(self, /) -> str: ...
    def get(self, /, name: str) -> Type |None:
        """
        Return the named type, or `None` when it does not resolve.
        """

@final
class UniqStackGroup(BaseRecord):
    """
    Threads whose walked stacks have the same frames and truncation.
    """
    @property
    def frames(self, /) -> list[StackFrame]:
        """
        The first thread's frames, innermost first; the others share its
        instruction pointers, not its stack pointers.
        """
    @property
    def thread_count(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ThreadSummary]: ...
    @property
    def truncated(self, /) -> int:
        """
        Frames past the walk bound, not compared.
        """

@final
class UniqStackScope(BaseRecord):
    """
    Which threads `!uniqstack` grouped.
    """
    @property
    def kind(self, /) -> str:
        """
        `all` or `process`.
        """
    @property
    def name(self, /) -> str |None:
        """
        The process's image name; `None` for `all`.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The process's id; `None` for `all`.
        """

@final
class UniqStacks(BaseRecord):
    """
    Threads grouped by identical call stacks (`!uniqstack`).
    """
    @property
    def groups(self, /) -> list[UniqStackGroup]:
        """
        In the order their first thread was walked.
        """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether the walk was interrupted before it finished.
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
        Threads whose stacks were walked and grouped.
        """

@final
class UnloadedDriver(BaseRecord):
    """
    A driver the crash dump records as recently unloaded.
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
    A thread whose stack could not be walked, so it could not be searched
    or grouped.
    """
    @property
    def error(self, /) -> str:
        """
        Why the walk failed.
        """
    @property
    def thread(self, /) -> ThreadSummary: ...

@final
class UnwindHandler(BaseRecord):
    """
    An unwind info's exception or termination handler.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def data(self, /) -> int:
        """
        Where the handler's language-specific data starts.
        """
    @property
    def symbol(self, /) -> str: ...

@final
class VcpuStatus(BaseRecord):
    """
    A vCPU (backend execution context) and the guest code it runs.
    """
    @property
    def context(self, /) -> str:
        """
        The address space the vCPU executes in: `kernel`, a process name,
        or `unknown`; empty when it could not be determined.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the register context was unavailable, when it was.
        """
    @property
    def id(self, /) -> str:
        """
        The backend thread/vCPU id (`p1.1`).
        """
    @property
    def rip(self, /) -> int |None:
        """
        None when the register context was unreadable.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtlState]:
        """
        For a vCPU halted in the Windows hypervisor, the VTL states it
        saved for the vCPU's virtual processor, VTL0's first.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to `rip`, when one resolved.
        """

@final
class Verifier(BaseRecord):
    """
    Driver Verifier's configuration, statistics, verified drivers, and
    configured-but-unloaded suspect drivers (`!verifier`).
    """
    @property
    def configured_but_unloaded(self, /) -> Diagnostic[list[VerifierSuspectDriver]]:
        """
        Suspect drivers configured for verification that are not loaded.
        """
    @property
    def drivers(self, /) -> Diagnostic[list[VerifierDriverSummary]]:
        """
        The verified drivers.
        """
    @property
    def drivers_truncated(self, /) -> bool:
        """
        Whether the driver table advertised fewer entries than it links,
        so the walk stopped before visiting every driver.
        """
    @property
    def level(self, /) -> Diagnostic[int]:
        """
        The verification level (`MmVerifierData.Level`).
        """
    @property
    def level_options(self, /) -> Diagnostic[list[str]]:
        """
        The names of the checks `level` enables.
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
    One verified driver's image, signing level, and counters
    (`!verifier <module>`).
    """
    @property
    def acquire_spin_locks(self, /) -> int: ...
    @property
    def allocations_failed(self, /) -> int: ...
    @property
    def allocations_failed_deliberately(self, /) -> int:
        """
        Allocations the verifier failed on purpose (fault injection).
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
        The driver's `_DRIVER_OBJECT`.
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
        The image's signing level (`SE_SIGNING_LEVEL`).
        """
    @property
    def suspect(self, /) -> VerifierSuspectDriver |None:
        """
        The driver's suspect-list entry, with its load history; `None`
        when it has none.
        """
    @property
    def synchronize_executions(self, /) -> int: ...

@final
class VerifierDriverSummary(BaseRecord):
    """
    A driver Driver Verifier is verifying, from `!verifier`'s list.
    """
    @property
    def entry(self, /) -> int:
        """
        The driver's verifier entry.
        """
    @property
    def module(self, /) -> str:
        """
        The driver's module name.
        """
    @property
    def nonpaged_bytes(self, /) -> int:
        """
        Nonpaged pool the driver holds, in bytes.
        """
    @property
    def paged_bytes(self, /) -> int:
        """
        Paged pool the driver holds, in bytes.
        """
    @property
    def state(self, /) -> str:
        """
        The entry's state (`Loaded`).
        """

@final
class VerifierFinding(BaseRecord):
    """
    A Driver Verifier bugcheck, decoded by its subcode.
    """
    @property
    def addresses(self, /) -> list[VerifierFindingAddress]:
        """
        The addresses the parameters name, by role.
        """
    @property
    def arguments(self, /) -> list[VerifierFindingArgument]:
        """
        The bugcheck parameters, described for the subcode.
        """
    @property
    def associated_driver(self, /) -> str |None:
        """
        The driver the violation is attributed to.
        """
    @property
    def bugcheck_code(self, /) -> int: ...
    @property
    def bugcheck_name(self, /) -> str: ...
    @property
    def known_subcode(self, /) -> bool:
        """
        Whether the subcode is one this decoder knows.
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
    An address a verifier bugcheck names, and its role.
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
    Driver Verifier's aggregate counters; each reads on its own and can
    fail.
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
    A driver configured for verification, from the verifier's suspect list.
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
        How many times the driver has loaded.
        """
    @property
    def unloads(self, /) -> int:
        """
        How many times the driver has unloaded.
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
        What `value` counts: `pages`, `bytes`, or empty for a plain count.
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
        The storage device the volume is on.
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
        Always None: VS chunk headers carry no flags.
        """
    @property
    def granule(self, /) -> int:
        """
        Header size in bytes (see `SegmentHeap.granule`).
        """
    @property
    def kind(self, /) -> str:
        """
        Always `vs-chunk`.
        """
    @property
    def previous_size(self, /) -> int:
        """
        Bytes of the chunk before it.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes, header included.
        """
    @property
    def state(self, /) -> str:
        """
        `busy` or `free`.
        """
    @property
    def unused_bytes(self, /) -> int |None:
        """
        Slack recorded in the chunk's last word, in bytes; None when the
        header records none.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte.
        """
    @property
    def user_size(self, /) -> int:
        """
        Bytes available to the caller.
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
        Chunks the walk found.
        """
    @property
    def chunks(self, /) -> list[HeapBlock]:
        """
        The subsegment's chunks; empty unless entries were listed.
        """
    @property
    def signature_ok(self, /) -> bool:
        """
        Whether the subsegment's signature matched.
        """

@final
class Watchpoint(Breakpoint):
    """
    A hardware data watchpoint.
    """
    @property
    def access(self, /) -> str:
        """
        Data access type (`"write"` or `"read_write"`).
        """
    @property
    def length(self, /) -> int:
        """
        Width of the watched memory access in bytes.
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
        The `FxDriver`; `None` before `WdfDriverCreate`.
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
        The IFR log's `_WDF_IFR_HEADER` (`WdfLogHeader`); `None` without
        one.
        """
    @property
    def name(self, /) -> str |None:
        """
        `Public.DriverName`; `None` when it is empty or not printable.
        """
    @property
    def problems(self, /) -> list[str]:
        """
        What in the globals failed validation; the fields it concerns are
        `None`.
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
        The KMDF version the driver bound to (`WdfBindInfo->Version`).
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
        The `_WDF_OBJECT_CONTEXT_TYPE_INFO`; `None` for a header without a
        context type.
        """

@final
class WdfDevice(BaseRecord):
    """
    A WDFDEVICE: its device objects, state machines, and queues
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
        The `FxPkgPnp`; null for a control device.
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
        Why the queue list walk stopped short of its head; `None` when it
        completed.
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
    One of a driver's device objects and the WDFDEVICE behind it.
    """
    @property
    def device(self, /) -> int |None:
        """
        The `FxDevice`; `None` when the device object is not one of this
        driver's WDFDEVICEs.
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
        Why the device object does not lead to one of this driver's
        WDFDEVICEs.
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
        Why the device chain walk stopped before a null link; `None` when
        it reached one.
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
        Why the context header chain stopped before a null `NextHeader`;
        `None` when it reached one.
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
        `m_ObjectSize`: the object and its extra bytes.
        """
    @property
    def offset(self, /) -> int |None:
        """
        The `WDFOBJECT_OFFSET` an offset handle subtracts from what it
        points at.
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
        Why the client list walk stopped short of its head; `None` when it
        completed.
        """

@final
class WdfLog(BaseRecord):
    """
    A client driver's In-Flight Recorder log, oldest record first
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
        What failed validation, when `end` is `corrupt`.
        """
    @property
    def current(self, /) -> int:
        """
        Where the next record goes.
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
        The record area's size, bytes.
        """
    @property
    def use_timestamps(self, /) -> bool:
        """
        Whether records carry timestamps ('L2').
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
        FILETIME; `None` for an 'LR' record, which has none.
        """
    @property
    def timestamp_utc(self, /) -> str |None:
        """
        `timestamp` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        """

@final
class WdfObjectRef(BaseRecord):
    """
    A KMDF object's address, handle, and type, as far as they read.
    """
    @property
    def address(self, /) -> int: ...
    @property
    def handle(self, /) -> int |None:
        """
        `None` for an object without a handle or one that does not read.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The `FX_OBJECT_TYPES` name of its `m_Type`.
        """

@final
class WdfQueue(BaseRecord):
    """
    A WDFQUEUE: its configuration, state, and requests (`!wdfkd.wdfqueue`).
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
        Why the walk stopped short; `None` when it completed.
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
        Why the walk stopped short; `None` when it completed.
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
        Why the walk stopped short; `None` when it completed.
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
        Whether it is the device's default queue.
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
    The WHEA error record a hardware-error bugcheck carries.
    """
    @property
    def record(self, /) -> Diagnostic[WheaRecord]:
        """
        The decoded record, or why it could not be decoded.
        """
    @property
    def record_address(self, /) -> int |None:
        """
        Where the record lives; `None` when the bugcheck names none.
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
        How many sections the record has; `sections` holds at most 64.
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
        The I/O work item it belongs to, when queued by `IoQueueWorkItem`.
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
        `_KPRIQUEUE.MaximumCount`: how many threads may run items at once.
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
        NUMA node.
        """
    @property
    def partition(self, /) -> int:
        """
        The `_EPARTITION` it belongs to.
        """
    @property
    def pending(self, /) -> int:
        """
        Items on all 32 priority lists, listed or not.
        """
    @property
    def priorities(self, /) -> list[WorkQueuePriority]:
        """
        The priority lists holding items or running threads, restricted to
        the requested priorities.
        """
    @property
    def queue_index(self, /) -> int: ...
    @property
    def queue_index_name(self, /) -> str |None:
        """
        `queue_index` by name, when it is a known one.
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
    One of a work queue's 32 priority lists.
    """
    @property
    def current_count(self, /) -> int:
        """
        `CurrentCount[priority]`: threads running an item of this priority.
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def queue_types(self, /) -> list[str]:
        """
        The `WORK_QUEUE_TYPE`s `ExQueueWorkItem` maps to this priority.
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
    Every executive worker queue (`!exqueue`).
    """
    @property
    def errors(self, /) -> list[str]:
        """
        Partitions or queues that could not be decoded.
        """
    @property
    def flags(self, /) -> int:
        """
        The `!exqueue` flags.
        """
    @property
    def priority_filter(self, /) -> list[int] |None:
        """
        The priorities flags 0x10/0x20/0x40 selected; `None` lists all.
        """
    @property
    def queues(self, /) -> list[WorkQueue]: ...

@final
class WorkerThread(BaseRecord):
    """
    A thread serving a work queue.
    """
    @property
    def kthread(self, /) -> int: ...
    @property
    def stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The thread's stack; `None` unless stacks were requested and the
        thread decoded.
        """
    @property
    def thread(self, /) -> Diagnostic[ThreadSummary]: ...

@final
class ZombieProcess(BaseRecord):
    """
    An exited process whose object is still referenced.
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
    A terminated thread whose object is still referenced.
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
        The owning process's image name; `None` when unreadable.
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
    Exited processes and terminated threads still referenced, found by
    scanning nonpaged pool (`!zombies`).
    """
    @property
    def interrupted(self, /) -> bool:
        """
        Whether the scan was interrupted before it finished.
        """
    @property
    def live_processes(self, /) -> int:
        """
        Live processes seen by the scan.
        """
    @property
    def live_threads(self, /) -> int:
        """
        Live threads seen by the scan.
        """
    @property
    def processes(self, /) -> list[ZombieProcess] |None:
        """
        `None` when the flags did not ask for processes.
        """
    @property
    def region_end(self, /) -> int:
        """
        The scanned pool region's end.
        """
    @property
    def region_start(self, /) -> int:
        """
        The scanned pool region's start.
        """
    @property
    def scanned_pages(self, /) -> int: ...
    @property
    def threads(self, /) -> list[ZombieThread] |None:
        """
        `None` when the flags did not ask for threads.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether a result list hit its cap.
        """

@final
class _StopContext:
    """
    Rust-only snapshot backing the shared properties of a typed stop.
    """

def _cli_main() -> int:
    """
    Run the `ntoseye` command line on `sys.argv` and return its exit status:
    the wheel's `ntoseye` script. The GIL is released for the whole session;
    custom commands take it back while they run.
    """

def attach(backend: Literal["kd", "kdnet", "gdb", "memory", "dmp"] = ..., connect: str |None = None, key: str |None = None, memory_source: Literal["auto", "host", "kd"] = ...) -> Debugger:
    """
    Attach to a guest and return a `Debugger`.
    
    `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
    `"dmp"`. `connect` is the backend target: socket path / address for
    kd/kdnet/gdb, or the dump file path for dmp; the per-backend default is used
    when omitted (except dmp, which requires a path). `key` is required for
    kdnet. `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
    
    kd/kdnet/gdb take a per-target instance lock before building the backend, so
    a second live attach against the same target fails fast rather than racing
    on the handshake the first session owns; memory/dmp are passive.
    """

def decode_error(code: int) -> ErrorCode:
    """
    Decode an NTSTATUS, Win32, or HRESULT code to its name and description
    (`!error`). Needs no target.
    """
