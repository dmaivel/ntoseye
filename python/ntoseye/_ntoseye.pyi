"""
The native module of the ntoseye SDK. Import from `ntoseye`, which
re-exports all of it.
"""

from collections.abc import Callable, Iterator, Sequence
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
    __match_args__: Final[tuple[Literal["index"], Literal["type"], Literal["type_name"], Literal["flags"], Literal["flag_names"], Literal["access_mask"], Literal["sid"]]]
    @property
    def access_mask(self, /) -> Diagnostic[int]:
        """
        The access mask; unavailable when the ACE body cannot be read.
        """
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
    def sid(self, /) -> Diagnostic[Sid]:
        """
        The SID in the ACE body; unavailable for a truncated or unreadable SID.
        """
    @property
    def type(self, /) -> int: ...
    @property
    def type_name(self, /) -> str: ...

@final
class Acl(BaseRecord):
    """
    A decoded ACL header and its ACEs (`!acl`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["revision"], Literal["size"], Literal["ace_count"], Literal["bounded"], Literal["unknown_revision"], Literal["aces"]]]
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
    region, a kernel region, or nothing that ntoseye recognizes. Complements
    `pte_traverse` (how it's mapped) with where it lives.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["dtb"], Literal["kind"], Literal["module"], Literal["section"], Literal["va_type"], Literal["region"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int:
        """
        The address space of the lookup.
        """
    @property
    def kind(self, /) -> Literal["kernel_module", "user_image", "kernel_region", "private", "mapped", "unknown", "physical", "vtl1", "foreign"]: ...
    @property
    def module(self, /) -> AddressModule |None:
        """
        The module containing the address, if any.
        """
    @property
    def region(self, /) -> MemoryRegionInfo |None:
        """
        The VAD region containing the address, if any.
        """
    @property
    def section(self, /) -> str |None:
        """
        The module section containing the address, if any.
        """
    @property
    def va_type(self, /) -> str |None:
        """
        The `_MI_SYSTEM_VA_TYPE` name, for a kernel region (e.g.
        `KernelStacks`, `PagedPool`, `SystemPtes`).
        """

@final
class AddressModule(BaseRecord):
    """
    The loaded module that contains an address.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["base"], Literal["size"], Literal["offset"]]]
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
class AddressSummary(BaseRecord):
    """
    WinDbg's `!address` summary: regions by usage, by type and protection of
    those in use, and by state.
    """
    __match_args__: Final[tuple[Literal["by_usage"], Literal["by_type"], Literal["by_state"], Literal["by_protect"], Literal["total"], Literal["busy"]]]
    @property
    def busy(self, /) -> int:
        """
        The size of the regions not free.
        """
    @property
    def by_protect(self, /) -> list[SummaryRow]:
        """
        Committed regions, by protection.
        """
    @property
    def by_state(self, /) -> list[SummaryRow]: ...
    @property
    def by_type(self, /) -> list[SummaryRow]:
        """
        Regions in use (not free), by `MEM_*` type.
        """
    @property
    def by_usage(self, /) -> list[SummaryRow]: ...
    @property
    def total(self, /) -> int:
        """
        The size of every region listed.
        """

@final
class AlpcClientPort(BaseRecord):
    """
    A client communication port that a process holds, and the ports that it
    is connected to.
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["port"], Literal["queued"], Literal["connection_port"], Literal["connection_name"], Literal["server_port"], Literal["server_queued"], Literal["server_owner"], Literal["server_owner_name"]]]
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
    __match_args__: Final[tuple[Literal["communication_info"], Literal["server_port"], Literal["server_queued"], Literal["client_port"], Literal["client_queued"], Literal["client_owner"], Literal["client_owner_name"]]]
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
class AlpcField(BaseRecord):
    """
    One `_KALPC_MESSAGE` pointer field: its PDB name, its snake_case name, and
    its value.
    """
    __match_args__: Final[tuple[Literal["field"], Literal["key"], Literal["value"]]]
    @property
    def field(self, /) -> str: ...
    @property
    def key(self, /) -> str: ...
    @property
    def value(self, /) -> int: ...

@final
class AlpcMessage(BaseRecord):
    """
    A `_KALPC_MESSAGE` (`!alpc /m`). A field is None if this Windows build
    does not have it, or if ntoseye cannot read it.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["message_id"], Literal["callback_id"], Literal["sequence_no"], Literal["message_type"], Literal["data_length"], Literal["total_length"], Literal["client_process_id"], Literal["client_thread_id"], Literal["state"], Literal["queue_type"], Literal["queue_port_type"], Literal["state_flags"], Literal["owner_port"], Literal["owner_port_kind"], Literal["port_queue"], Literal["port_queue_kind"], Literal["port_queue_owner"], Literal["port_queue_owner_name"], Literal["cancel_sequence_no"], Literal["extension_buffer_size"], Literal["pointers"], Literal["attributes"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def attributes(self, /) -> list[AlpcField]:
        """
        The `_KALPC_MESSAGE_ATTRIBUTES` fields that this build has.
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
    def owner_port_kind(self, /) -> Literal["connection", "server_communication", "client_communication"] |None:
        """
        The port type of the owner port.
        """
    @property
    def pointers(self, /) -> list[AlpcField]:
        """
        The pointer fields of the message that this build has.
        """
    @property
    def port_queue(self, /) -> int:
        """
        The port whose queue holds the message.
        """
    @property
    def port_queue_kind(self, /) -> Literal["connection", "server_communication", "client_communication"] |None: ...
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
    __match_args__: Final[tuple[Literal["handle"], Literal["port"], Literal["name"], Literal["connections"], Literal["termination"]]]
    @property
    def connections(self, /) -> list[AlpcConnection]: ...
    @property
    def handle(self, /) -> int: ...
    @property
    def name(self, /) -> str |None: ...
    @property
    def port(self, /) -> int: ...
    @property
    def termination(self, /) -> ListTermination: ...

@final
class AlpcPort(BaseRecord):
    """
    An `_ALPC_PORT` (`!alpc /p`). A field is None if this Windows build does
    not have it, or if ntoseye cannot read it.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["pointer_count"], Literal["handle_count"], Literal["kind"], Literal["state"], Literal["port_type"], Literal["state_flags"], Literal["owner"], Literal["owner_name"], Literal["communication_info"], Literal["connection_port"], Literal["server_port"], Literal["client_port"], Literal["sequence_no"], Literal["completion_port"], Literal["completion_list"], Literal["port_context"], Literal["attribute_flags"], Literal["max_message_length"], Literal["queues"], Literal["direct_queue_length"], Literal["connections"], Literal["connection_termination"]]]
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
    def connection_termination(self, /) -> ListTermination |None:
        """
        How the walk of the connection list ended. None if there was no walk.
        """
    @property
    def connections(self, /) -> list[AlpcConnection]:
        """
        The connections of a connection port
        (`CommunicationInfo.CommunicationList`).
        """
    @property
    def direct_queue_length(self, /) -> int |None: ...
    @property
    def handle_count(self, /) -> int: ...
    @property
    def kind(self, /) -> Literal["connection", "server_communication", "client_communication"] |None: ...
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
    __match_args__: Final[tuple[Literal["process"], Literal["created"], Literal["connected"], Literal["server_ports"], Literal["scanned_handles"], Literal["advertised_handles"], Literal["skipped_entries"]]]
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
    def process(self, /) -> ProcessInfo: ...
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
    __match_args__: Final[tuple[Literal["field"], Literal["key"], Literal["length"], Literal["entries"], Literal["termination"]]]
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
        The count that the port keeps for the queue (`<field>Length`). None if
        the port keeps no count.
        """
    @property
    def termination(self, /) -> ListTermination: ...

@final
class Amd64TrapFrame(BaseRecord):
    """
    The x64 registers that a `_KTRAP_FRAME` saved. The nonvolatile r12-r15
    live in the accompanying `_KEXCEPTION_FRAME`, not the trap frame.
    
    What a frame holds depends on the entry that built it, `kind` (see
    [`TrapKind`]). A register the entry does not write is `None` rather than
    whatever its slot held.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["rax"], Literal["rbx"], Literal["rcx"], Literal["rdx"], Literal["rsi"], Literal["rdi"], Literal["rbp"], Literal["rsp"], Literal["r8"], Literal["r9"], Literal["r10"], Literal["r11"], Literal["rip"], Literal["cs"], Literal["ss"], Literal["eflags"], Literal["error_code"], Literal["previous_mode"], Literal["previous_irql"]]]
    @property
    def cs(self, /) -> int: ...
    @property
    def eflags(self, /) -> int: ...
    @property
    def error_code(self, /) -> int |None:
        """
        The exception error code, which is stale for an exception whose
        vector carries none (#DE, #BP, #UD, ...): the frame cannot tell them
        apart.
        """
    @property
    def kind(self, /) -> Literal["interrupt", "exception", "system_call", "zw_call"] |None:
        """
        The entry that built the frame: `interrupt`, `exception`,
        `system call`, or `Zw call`. `None` if the entry is unknown (no or
        an unknown `ExceptionActive`), and then only the machine frame and
        rbp, which every entry writes, are reliable.
        """
    @property
    def previous_irql(self, /) -> int |None:
        """
        The IRQL before the trap, which only interrupts record.
        """
    @property
    def previous_mode(self, /) -> int:
        """
        The mode that the trap came from: 0 for kernel, 1 for user. It is
        read from the saved `cs`, as Windows reads it: the `PreviousMode`
        field is set only by system calls.
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
    __match_args__: Final[tuple[Literal["slot"], Literal["code_offset"], Literal["op"], Literal["op_info"], Literal["description"]]]
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
    __match_args__: Final[tuple[Literal["version"], Literal["flags"], Literal["prolog_size"], Literal["code_count"], Literal["frame_register"], Literal["frame_offset"], Literal["size"], Literal["codes"], Literal["handler"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["kernel_routine"], Literal["kernel_routine_symbol"], Literal["normal_routine"], Literal["normal_routine_symbol"]]]
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
    __match_args__: Final[tuple[Literal["selector"], Literal["threads"], Literal["total"], Literal["truncated"], Literal["layout_error"]]]
    @property
    def layout_error(self, /) -> str |None:
        """
        The error, if ntoseye could not resolve the APC layout.
        """
    @property
    def selector(self, /) -> ApcSelector:
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

class ApcSelector(BaseRecord):
    """
    The threads `!apc` inspects; `kind` says which.
    """
    @property
    def kind(self, /) -> Literal["current_thread", "thread", "process", "number", "all"]:
        """
        The variant: `current_thread`, `thread`, `process`, `number`, `all`.
        """
    @final
    class All(ApcSelector):
        """
        Enumerate every thread in the bounded process/thread walk.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["all"]:
            """
            `all`.
            """
    @final
    class CurrentThread(ApcSelector):
        """
        Select the Windows thread currently selected by the session.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["current_thread"]:
            """
            `current_thread`.
            """
    @final
    class Number(ApcSelector):
        """
        Resolve a numeric target as a thread first, then a PID/EPROCESS.
        """
        __match_args__: Final[tuple[Literal["number"]]]
        @property
        def kind(self, /) -> Literal["number"]:
            """
            `number`.
            """
        @property
        def number(self, /) -> int: ...
    @final
    class Process(ApcSelector):
        """
        Select all threads owned by a PID or EPROCESS value.
        """
        __match_args__: Final[tuple[Literal["process"]]]
        @property
        def kind(self, /) -> Literal["process"]:
            """
            `process`.
            """
        @property
        def process(self, /) -> int: ...
    @final
    class Thread(ApcSelector):
        """
        Select a thread by ETHREAD, KTHREAD, or TID value.
        """
        __match_args__: Final[tuple[Literal["thread"]]]
        @property
        def kind(self, /) -> Literal["thread"]:
            """
            `thread`.
            """
        @property
        def thread(self, /) -> int: ...

@final
class ApcThread(BaseRecord):
    """
    The kernel-mode and user-mode APC queues of a thread.
    """
    __match_args__: Final[tuple[Literal["thread"], Literal["kernel"], Literal["user"], Literal["kernel_termination"], Literal["user_termination"], Literal["state_error"]]]
    @property
    def kernel(self, /) -> list[Apc]: ...
    @property
    def kernel_termination(self, /) -> ListTermination:
        """
        How the kernel-mode list walk ended.
        """
    @property
    def state_error(self, /) -> str |None:
        """
        The error, if ntoseye could not read the APC state of the thread.
        """
    @property
    def thread(self, /) -> ThreadInfo: ...
    @property
    def user(self, /) -> list[Apc]: ...
    @property
    def user_termination(self, /) -> ListTermination:
        """
        How the user-mode list walk ended.
        """

@final
class ApicIcr(BaseRecord):
    """
    The interrupt command register, decoded.
    """
    __match_args__: Final[tuple[Literal["raw"], Literal["vector"], Literal["delivery"], Literal["logical"], Literal["pending"], Literal["level_assert"], Literal["level_triggered"], Literal["shorthand"], Literal["destination"]]]
    @property
    def delivery(self, /) -> str: ...
    @property
    def destination(self, /) -> int: ...
    @property
    def level_assert(self, /) -> bool: ...
    @property
    def level_triggered(self, /) -> bool: ...
    @property
    def logical(self, /) -> bool: ...
    @property
    def pending(self, /) -> bool: ...
    @property
    def raw(self, /) -> int: ...
    @property
    def shorthand(self, /) -> Literal["none", "self", "all", "all_but_self"]: ...
    @property
    def vector(self, /) -> int: ...

@final
class ApicLvt(BaseRecord):
    """
    A local vector table entry, decoded (Intel SDM vol. 3, 11.5.1).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["raw"], Literal["vector"], Literal["delivery"], Literal["pending"], Literal["active_low"], Literal["remote_irr"], Literal["level"], Literal["masked"], Literal["timer_mode"]]]
    @property
    def active_low(self, /) -> bool: ...
    @property
    def delivery(self, /) -> str:
        """
        `Fixed`, `SMI`, `NMI`, `INIT`, `ExtINT`, or the mode in hex.
        """
    @property
    def level(self, /) -> bool: ...
    @property
    def masked(self, /) -> bool: ...
    @property
    def name(self, /) -> str:
        """
        `Timer`, `LINT0`, `LINT1`, `Error`, `PerfMon`, `Thermal`, or
        `CMCI`.
        """
    @property
    def pending(self, /) -> bool: ...
    @property
    def raw(self, /) -> int: ...
    @property
    def remote_irr(self, /) -> bool: ...
    @property
    def timer_mode(self, /) -> Literal["one_shot", "periodic", "tsc_deadline", "reserved"] |None:
        """
        The timer's mode; `None` for an entry other than the timer.
        """
    @property
    def vector(self, /) -> int: ...

@final
class Arm64EpilogScope(BaseRecord):
    """
    One ARM64 epilog scope.
    """
    __match_args__: Final[tuple[Literal["start_offset"], Literal["first_code"]]]
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
    __match_args__: Final[tuple[Literal["flag"], Literal["reg_f"], Literal["reg_i"], Literal["homes_arguments"], Literal["cr"], Literal["frame_size"], Literal["codes"]]]
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
    The ARM64 registers that a `_KTRAP_FRAME` saved, as the target's PDB
    lays the frame out. The frame holds x0-x18, fp (x29) and lr (x30), and
    keeps the control and debug state beside the return context. A field
    that the build's frame lacks is `None`.
    """
    __match_args__: Final[tuple[Literal["x"], Literal["lr"], Literal["fp"], Literal["pc"], Literal["sp"], Literal["cpsr"], Literal["esr"], Literal["fault_address"], Literal["bcr"], Literal["bvr"], Literal["wcr"], Literal["wvr"], Literal["previous_mode"], Literal["previous_irql"]]]
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
    def x(self, /) -> list[int]:
        """
        x0 to x18.
        """

@final
class Arm64UnwindCode(BaseRecord):
    """
    One ARM64 unwind code.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["bytes"], Literal["description"]]]
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
    __match_args__: Final[tuple[Literal["version"], Literal["exception_data"], Literal["epilog_in_header"], Literal["epilog_count"], Literal["code_words"], Literal["epilog_scopes"], Literal["size"], Literal["codes"], Literal["handler"]]]
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
    __match_args__: Final[tuple[Literal["device"], Literal["driver_object"], Literal["device_type"], Literal["flags"]]]
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
    __match_args__: Final[tuple[Literal["capability"], Literal["supported"]]]
    @property
    def capability(self, /) -> Literal["memory_introspection", "execution_control", "interrupt_target", "single_step", "read_registers", "write_registers", "thread_list", "thread_selection", "kernel_breakpoints", "user_mode_breakpoints", "watchpoints", "target_reload_detection", "kernel_base_hint", "bugcheck_detection", "bugcheck_details", "module_load_events", "debug_output", "msr", "io_ports", "pci_config", "target_control", "target_file_io"]:
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
    An immutable result, the base of every typed result class
    (`PciFunction`, ...), whose properties are its fields. Like a frozen
    dataclass, it compares and hashes by class and fields, matches by
    `__match_args__` (its fields, in order) and is not a container; use
    `to_dict()` to walk the fields by name.
    """
    def __eq__(self, other: object, /) -> bool:
        """
        Equal to a record of the same class with equal fields.
        """
    def __hash__(self, /) -> int:
        """
        The hash of the class and the fields; a `TypeError` when a field is
        unhashable (a `list`), as for a frozen dataclass.
        """
    def __repr__(self, /) -> str: ...
    def to_dict(self, /) -> dict[str, Any]:
        """
        A plain nested `dict`, with all records and diagnostics converted, for
        serializing or comparing a result.
        """

@final
class BigPoolDetail(BaseRecord):
    """
    A large allocation from `PoolBigPageTable`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["target"], Literal["size"], Literal["offset"], Literal["tag"], Literal["tag_name"], Literal["entry"], Literal["index"], Literal["nonpaged"], Literal["pattern"], Literal["pool_flags"], Literal["slush_size"]]]
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
class BlackboxFinding(BaseRecord):
    """
    A blackbox record (pnp, ntfs, bsd, winlogon) of a crash dump: a block of
    its tagged data that ntoseye decodes as WinDbg's `!blackbox*` commands do.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["name"], Literal["command"], Literal["size"], Literal["state"]]]
    @property
    def command(self, /) -> str:
        """
        The command that shows the whole record, such as `!blackboxpnp`.
        """
    @property
    def kind(self, /) -> Literal["pnp", "ntfs", "bsd", "winlogon"]: ...
    @property
    def name(self, /) -> str:
        """
        `PnP`, `NTFS`, `BSD`, or `Winlogon`.
        """
    @property
    def size(self, /) -> int |None:
        """
        The block's size in bytes. `None` if the dump has no block.
        """
    @property
    def state(self, /) -> BlackboxState: ...

class BlackboxState(BaseRecord):
    """
    What a dump holds of a blackbox: `decoded` (with `summary`, what it holds
    in one line), `malformed` (with the `reason`), or `absent`.
    """
    @property
    def kind(self, /) -> Literal["decoded", "malformed", "absent"]:
        """
        The variant: `decoded`, `malformed`, `absent`.
        """
    @final
    class Absent(BlackboxState):
        """
        The dump has no block for the blackbox.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["absent"]:
            """
            `absent`.
            """
    @final
    class Decoded(BlackboxState):
        """
        The dump has the block, and it decodes; `summary` says what it holds.
        """
        __match_args__: Final[tuple[Literal["summary"]]]
        @property
        def kind(self, /) -> Literal["decoded"]:
            """
            `decoded`.
            """
        @property
        def summary(self, /) -> str: ...
    @final
    class Malformed(BlackboxState):
        """
        The dump has the block, but it does not decode.
        """
        __match_args__: Final[tuple[Literal["reason"]]]
        @property
        def kind(self, /) -> Literal["malformed"]:
            """
            `malformed`.
            """
        @property
        def reason(self, /) -> str: ...

class BlockMatch(BaseRecord):
    """
    Where a searched address lands inside a heap, told apart by `kind`.
    """
    @property
    def kind(self, /) -> Literal["nt_entry", "nt_lfh_block", "nt_virtual", "nt_segment", "page", "vs_chunk", "lfh_block", "range", "large"]:
        """
        The variant: `nt_entry`, `nt_lfh_block`, `nt_virtual`, `nt_segment`, `page`, `vs_chunk`, `lfh_block`, `range`, `large`.
        """
    @final
    class Direct(BlockMatch):
        """
        A segment-heap range that the heap allocated directly from its
        segment.
        """
        __match_args__: Final[tuple[Literal["range"]]]
        @property
        def kind(self, /) -> Literal["page"]:
            """
            `page`.
            """
        @property
        def range(self, /) -> PageRange: ...
    @final
    class Large(BlockMatch):
        """
        Inside a segment-heap large allocation.
        """
        __match_args__: Final[tuple[Literal["allocation"]]]
        @property
        def allocation(self, /) -> LargeAllocation: ...
        @property
        def kind(self, /) -> Literal["large"]:
            """
            `large`.
            """
    @final
    class LfhBlock(BlockMatch):
        """
        Inside block `index` of a segment-heap LFH subsegment.
        """
        __match_args__: Final[tuple[Literal["range"], Literal["subsegment"], Literal["index"]]]
        @property
        def index(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["lfh_block"]:
            """
            `lfh_block`.
            """
        @property
        def range(self, /) -> PageRange: ...
        @property
        def subsegment(self, /) -> LfhSubsegment: ...
    @final
    class NtEntry(BlockMatch):
        """
        Inside an NT-heap entry.
        """
        __match_args__: Final[tuple[Literal["segment"], Literal["entry"]]]
        @property
        def entry(self, /) -> NtEntry: ...
        @property
        def kind(self, /) -> Literal["nt_entry"]:
            """
            `nt_entry`.
            """
        @property
        def segment(self, /) -> int:
            """
            The `_HEAP_SEGMENT` that contains the entry.
            """
    @final
    class NtLfhBlock(BlockMatch):
        """
        Inside a legacy-LFH block of an NT heap: block `index` of the user
        block `region` in the busy `entry`.
        """
        __match_args__: Final[tuple[Literal["segment"], Literal["entry"], Literal["region"], Literal["index"]]]
        @property
        def entry(self, /) -> NtEntry: ...
        @property
        def index(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["nt_lfh_block"]:
            """
            `nt_lfh_block`.
            """
        @property
        def region(self, /) -> NtUserBlocks: ...
        @property
        def segment(self, /) -> int: ...
    @final
    class NtSegmentOnly(BlockMatch):
        """
        Inside a segment but not on the chain: the heap header, an
        uncommitted range, or past where the walk had to stop.
        """
        __match_args__: Final[tuple[Literal["segment"], Literal["stopped"]]]
        @property
        def kind(self, /) -> Literal["nt_segment"]:
            """
            `nt_segment`.
            """
        @property
        def segment(self, /) -> int: ...
        @property
        def stopped(self, /) -> HeapWalkStop |None:
            """
            Where the entry walk stopped, and why. None if the walk did not
            stop early.
            """
    @final
    class NtVirtual(BlockMatch):
        """
        Inside an NT-heap virtually allocated block.
        """
        __match_args__: Final[tuple[Literal["block"]]]
        @property
        def block(self, /) -> NtVirtualBlock: ...
        @property
        def kind(self, /) -> Literal["nt_virtual"]:
            """
            `nt_virtual`.
            """
    @final
    class RangeOnly(BlockMatch):
        """
        Inside a page range but outside its subsegment's blocks (header,
        bitmap, or trailing slack).
        """
        __match_args__: Final[tuple[Literal["range"]]]
        @property
        def kind(self, /) -> Literal["range"]:
            """
            `range`.
            """
        @property
        def range(self, /) -> PageRange: ...
    @final
    class VsChunk(BlockMatch):
        """
        Inside a segment-heap VS chunk.
        """
        __match_args__: Final[tuple[Literal["range"], Literal["vs_subsegment"], Literal["chunk"]]]
        @property
        def chunk(self, /) -> VsChunk: ...
        @property
        def kind(self, /) -> Literal["vs_chunk"]:
            """
            `vs_chunk`.
            """
        @property
        def range(self, /) -> PageRange: ...
        @property
        def vs_subsegment(self, /) -> int:
            """
            The `_HEAP_VS_SUBSEGMENT` that contains the chunk.
            """

@final
class BlockedIrp(BaseRecord):
    """
    The IRP of a 0x9F/0x3: where it is pending, and its `_POP_IRP_DATA`.
    """
    __match_args__: Final[tuple[Literal["irp"], Literal["holder"], Literal["power_irp"]]]
    @property
    def holder(self, /) -> Diagnostic[IrpHolder]:
        """
        The driver of the IRP's current stack location.
        """
    @property
    def irp(self, /) -> int: ...
    @property
    def power_irp(self, /) -> PowerIrp |None:
        """
        The IRP's entry on the power IRP list, when it is there.
        """

@final
class BootStatus(BaseRecord):
    """
    The boot status data (`RTL_BSD_DATA`) the boot manager and the kernel
    keep in `bootstat.dat`. Sections past `version` (its size) are absent.
    """
    __match_args__: Final[tuple[Literal["version"], Literal["truncated_to"], Literal["product_type"], Literal["auto_advanced_boot"], Literal["advanced_boot_menu_timeout"], Literal["last_boot_succeeded"], Literal["last_boot_shutdown"], Literal["sleep_in_progress"], Literal["power_transition"], Literal["boot_attempt_count"], Literal["last_boot_checkpoint"], Literal["checksum"], Literal["last_boot_id"], Literal["last_successful_shutdown_boot_id"], Literal["last_reported_abnormal_shutdown_boot_id"], Literal["error_info"], Literal["power_button"], Literal["transition_extension"], Literal["feature_configuration_state"]]]
    @property
    def advanced_boot_menu_timeout(self, /) -> int: ...
    @property
    def auto_advanced_boot(self, /) -> bool: ...
    @property
    def boot_attempt_count(self, /) -> int: ...
    @property
    def checksum(self, /) -> int: ...
    @property
    def error_info(self, /) -> BsdErrorInfo |None: ...
    @property
    def feature_configuration_state(self, /) -> int |None:
        """
        `0` uninitialized, `1` boot pending, `2` LKG pending, `3` rollback
        pending, `4` committed.
        """
    @property
    def last_boot_checkpoint(self, /) -> bool: ...
    @property
    def last_boot_id(self, /) -> int: ...
    @property
    def last_boot_shutdown(self, /) -> bool: ...
    @property
    def last_boot_succeeded(self, /) -> bool: ...
    @property
    def last_reported_abnormal_shutdown_boot_id(self, /) -> int: ...
    @property
    def last_successful_shutdown_boot_id(self, /) -> int: ...
    @property
    def power_button(self, /) -> PowerButton |None: ...
    @property
    def power_transition(self, /) -> PowerTransition: ...
    @property
    def product_type(self, /) -> int: ...
    @property
    def sleep_in_progress(self, /) -> bool: ...
    @property
    def transition_extension(self, /) -> TransitionExtension |None: ...
    @property
    def truncated_to(self, /) -> int |None:
        """
        The block's size when it is smaller than `version` says.
        """
    @property
    def version(self, /) -> int: ...

@final
class Breakpoint:
    """
    A breakpoint handle. Because a breakpoint stays when ntoseye builds the
    target again, and a symbolic breakpoint resolves again after a reboot, the
    handle has no generation stamp and becomes invalid only when the breakpoint
    is deleted, or, for a one-shot breakpoint, once it fired. Its properties
    are the breakpoint's state now, as `bl` lists it; a data watchpoint's
    `watch_access` and `watch_length` say what it watches.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def action(self, /) -> str |None:
        """
        The commands that run when the breakpoint breaks.
        """
    @property
    def address(self, /) -> int |None:
        """
        The resolved address; None while a symbolic or source breakpoint is
        deferred.
        """
    @property
    def condition(self, /) -> str |None:
        """
        The condition expression that a hit must satisfy.
        """
    @condition.setter
    def condition(self, /, condition: str |None) -> None:
        """
        Assigning an expression raises `ValueError` while a `when=` callback is
        attached, and `add()` also raises it if you give both.
        """
    @property
    def deferred(self, /) -> bool:
        """
        Whether a symbolic or source specification waits for resolution.
        """
    def delete(self, /) -> None:
        """
        Remove this breakpoint. A breakpoint that is already gone, deleted or
        a one-shot breakpoint whose hit stopped the target, is left as it is,
        so deleting after the hit works.
        """
    @property
    def enabled(self, /) -> bool: ...
    @enabled.setter
    def enabled(self, /, enabled: bool) -> None: ...
    @property
    def hit_count(self, /) -> int: ...
    @property
    def hypercall(self, /) -> HypercallFilter |None:
        """
        The hypercall a hit must be handling, and from which caller, for a
        hypercall breakpoint (`!hvbp`). None for any other breakpoint.
        """
    @property
    def id(self, /) -> int:
        """
        The breakpoint's ID, which `bl` and `dbg.breakpoints` use; readable
        after the breakpoint is gone.
        """
    @property
    def info(self, /) -> BreakpointInfo:
        """
        The `BreakpointInfo` record of this handle: its properties as one value.
        """
    @property
    def one_shot(self, /) -> bool:
        """
        Whether ntoseye removes the breakpoint after its first break.
        """
    @one_shot.setter
    def one_shot(self, /, one_shot: bool) -> None: ...
    @property
    def partition(self, /) -> PartitionFilter |None:
        """
        The guest partition of the Windows hypervisor whose VPs a hit must be
        on, for a breakpoint set in its view (`.partition`). None for the
        target's own breakpoints.
        """
    @property
    def pass_count(self, /) -> int:
        """
        The requested hit number. Both 0 and 1 break on the first hit.
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
    def temporary(self, /) -> bool:
        """
        Whether this is a temporary run-to breakpoint.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread restriction, if any.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """
    @property
    def unchecked(self, /) -> bool:
        """
        Set with `bp /a` or `bu /a`: without confirming that an instruction
        starts at the address.
        """
    @property
    def valid(self, /) -> bool:
        """
        True while the breakpoint exists in this session: False once it is
        deleted, and for a one-shot breakpoint once its hit stopped the
        target. The other properties raise `NtoseyeError` once it is False.
        """
    @property
    def vm_exit(self, /) -> ExitFilter |None:
        """
        The VM exit a hit must be handling, and from which caller, for a
        VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
        """
    @property
    def watch_access(self, /) -> Literal["write", "read_write"] |None:
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
class BreakpointCommands(BaseRecord):
    """
    The commands that set the current breakpoints again (`.bpcmds`).
    """
    __match_args__: Final[tuple[Literal["commands"]]]
    @property
    def commands(self, /) -> list[str]:
        """
        One command line per breakpoint, in ID order.
        """

@final
class BreakpointHit(BaseRecord):
    """
    A breakpoint hit that stopped the target.
    """
    __match_args__: Final[tuple[Literal["id"], Literal["kind"], Literal["address"], Literal["access"], Literal["length"], Literal["exit_reason"], Literal["symbol"], Literal["temporary"], Literal["action"], Literal["condition_error"]]]
    @property
    def access(self, /) -> Literal["execute", "write", "read_write"] |None:
        """
        A debug-register breakpoint's access and length.
        """
    @property
    def action(self, /) -> str |None: ...
    @property
    def address(self, /) -> int:
        """
        The planted or watched address, not necessarily where it stopped.
        """
    @property
    def condition_error(self, /) -> str |None:
        """
        Why its condition failed to evaluate; the hit is surfaced instead.
        """
    @property
    def exit_reason(self, /) -> str |None:
        """
        A VM-exit breakpoint's exit reason.
        """
    @property
    def id(self, /) -> int: ...
    @property
    def kind(self, /) -> Literal["code", "hardware", "watch", "hypercall", "vm_exit"]: ...
    @property
    def length(self, /) -> int |None: ...
    @property
    def symbol(self, /) -> str |None: ...
    @property
    def temporary(self, /) -> bool: ...

@final
class BreakpointInfo(BaseRecord):
    """
    A code breakpoint or data watchpoint (`bl`), as the debugger keeps it.
    """
    __match_args__: Final[tuple[Literal["id"], Literal["enabled"], Literal["symbol"], Literal["resolved"], Literal["processor"], Literal["hypercall"], Literal["vm_exit"], Literal["partition"], Literal["condition"], Literal["pass_count"], Literal["hit_count"], Literal["remaining_pass_count"], Literal["one_shot"], Literal["action"], Literal["temporary"], Literal["unchecked"]]]
    @property
    def action(self, /) -> str |None:
        """
        The commands that run when the breakpoint breaks.
        """
    @property
    def address(self, /) -> int |None:
        """
        The resolved address; None while a symbolic or source breakpoint is
        deferred.
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
    def partition(self, /) -> PartitionFilter |None:
        """
        The guest partition of the Windows hypervisor whose VPs a hit must be
        on, for a breakpoint set in its view (`.partition`). None for the
        target's own breakpoints.
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
    def temporary(self, /) -> bool:
        """
        Whether this is a temporary run-to breakpoint.
        """
    @property
    def thread(self, /) -> str |None:
        """
        The only thread that can report a hit (`/t`: `tid N` or
        `ethread 0x...`). None if there is no thread restriction.
        """
    @property
    def unchecked(self, /) -> bool:
        """
        Set with `bp /a` or `bu /a`: without confirming that an instruction
        starts at the address.
        """
    @property
    def vm_exit(self, /) -> ExitFilter |None:
        """
        The VM exit a hit must be handling, and from which caller, for a
        VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
        """
    @property
    def watch_access(self, /) -> Literal["write", "read_write"] |None:
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
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: int, /) -> Breakpoint:
        """
        The breakpoint with an ID.
        """
    def __iter__(self, /) -> Iterator[Breakpoint]: ...
    def __len__(self, /) -> int: ...
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
    def commands(self, /) -> BreakpointCommands:
        """
        Print the commands that set the current breakpoints again.
        
        The output has one line for each breakpoint, in ID order. An address
        breakpoint shows as `bp <address>`, a symbolic or source breakpoint as `bu
        <symbol>` (as `bm` creates it), a hardware breakpoint as `ba
        <access><size> <address>`, and a hypercall breakpoint as `!hvbp <code>
        [partition-id [vp-index]]`, without its pass count, which !hvbp does not
        take. Each line also has the /1, /p, /t, and /c options of the breakpoint,
        its condition (as /w), its pass count, and its command string. To set the
        same breakpoints again, run the lines, either by pasting them or by saving
        them to a file for `$$<`. WinDbg puts a breakpoint ID in each line, but
        these lines have none because the ntoseye bp command does not take one, so
        the new breakpoints get new IDs. A disabled breakpoint comes back enabled.
        """
    def get(self, /, key: int) -> Breakpoint |None:
        """
        The breakpoint with an ID.
        """
    def list(self, /) -> list[BreakpointInfo]:
        """
        List all breakpoints.
        
        The status column shows `e` for enabled, `d` for disabled, or `o` for
        owed. An owed breakpoint is a kernel code breakpoint that waits for its
        page to become resident.
        """
    def watch(self, /, target: int |str, *, access: Literal["write", "read_write"] = ..., length: int = 1, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a hardware data watchpoint.
        """

@final
class BsdErrorInfo(BaseRecord):
    """
    The error info section of the boot status data.
    """
    __match_args__: Final[tuple[Literal["boot_id"], Literal["repeat_count"], Literal["other_error_count"], Literal["code"], Literal["status"]]]
    @property
    def boot_id(self, /) -> int: ...
    @property
    def code(self, /) -> int: ...
    @property
    def other_error_count(self, /) -> int: ...
    @property
    def repeat_count(self, /) -> int: ...
    @property
    def status(self, /) -> int: ...

@final
class BugcheckAnalysis(BaseRecord):
    """
    A decoded bugcheck (BSOD): the code resolved to a name and per-parameter
    descriptions, the responsible driver (from the dump record, the KD stream
    or the fault site), and the faulting instruction if ntoseye identified it.
    One source of truth for bugcheck analysis.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["name"], Literal["description"], Literal["driver"], Literal["args"], Literal["fault"], Literal["trap_frames"], Literal["source"]]]
    @property
    def args(self, /) -> list[BugcheckArg]:
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
        Set only when the data was not where it should have been, naming
        where it was instead: `nt!KiBugCheckData` holding a pointer to the
        real slots rather than the slots themselves. `None` is the normal
        case, including every bugcheck the target reported itself.
        """
    @property
    def trap_frames(self, /) -> list[BugcheckTrapFrame]:
        """
        The trap frames that the parameters point to.
        """

@final
class BugcheckArg(BaseRecord):
    """
    One bugcheck parameter and what it means for the code.
    """
    __match_args__: Final[tuple[Literal["value"], Literal["description"]]]
    @property
    def description(self, /) -> str:
        """
        What this parameter holds for the bugcheck code. Empty if the code
        has no documented meaning for this parameter.
        """
    @property
    def value(self, /) -> int: ...

@final
class BugcheckDecoding(BaseRecord):
    """
    A bugcheck code and parameters decoded (`!analyze -show`).
    """
    __match_args__: Final[tuple[Literal["analysis"], Literal["power"]]]
    @property
    def analysis(self, /) -> BugcheckAnalysis: ...
    @property
    def power(self, /) -> PowerFailureFinding |None:
        """
        What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck.
        """

@final
class BugcheckFault(BaseRecord):
    """
    The instruction a bugcheck faulted at.
    """
    __match_args__: Final[tuple[Literal["ip"], Literal["symbol"], Literal["driver"]]]
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
class BugcheckInfo(BaseRecord):
    """
    A bugcheck's code and its four parameters, and the driver the transport
    names for it.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["parameters"], Literal["driver"]]]
    @property
    def code(self, /) -> int: ...
    @property
    def driver(self, /) -> str |None: ...
    @property
    def parameters(self, /) -> list[int]: ...

@final
class BugcheckTrapFrame(BaseRecord):
    """
    A trap frame that a bugcheck parameter points to, with its decoded
    registers or the reason that decoding failed.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["rip_symbol"], Literal["error"]]]
    @property
    def address(self, /) -> int:
        """
        The address that ntoseye read the frame from.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that decoding failed. `None` exactly when `frame` is
        present.
        """
    @property
    def frame(self, /) -> Amd64TrapFrame |Arm64TrapFrame |None:
        """
        The saved registers. `None` if decoding failed.
        """
    @property
    def rip_symbol(self, /) -> str |None:
        """
        The symbol at the interrupted instruction, when the frame decoded.
        """

@final
class CacheAttribute(BaseRecord):
    """
    The `CacheAttribute` of a PFN.
    """
    __match_args__: Final[tuple[Literal["value"]]]
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
    __match_args__: Final[tuple[Literal["shared_cache_map"], Literal["file_object"], Literal["file_name"], Literal["file_size"], Literal["valid_data_length"], Literal["open_count"], Literal["dirty_pages"], Literal["mapped_vacbs"], Literal["valid_bytes"]]]
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
    A `wt` call trace: the call tree, the instructions that it stepped, and
    why it stopped ([`Session::trace_calls`]).
    """
    __match_args__: Final[tuple[Literal["root"], Literal["instructions"]]]
    @property
    def end(self, /) -> Literal["returned", "limit", "interrupted", "breakpoint", "diverted", "failed"]:
        """
        `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
        `failed`. `interrupted` means Ctrl+C or the `timeout` ended it.
        `diverted` means that an interrupt diverted a step and the traced
        thread is not known. Any value other than `returned` means that
        the tree is partial.
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
    __match_args__: Final[tuple[Literal["name"], Literal["instructions"], Literal["children"]]]
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
class CapturedRange(BaseRecord):
    """
    One captured range of a dump without a memory-info list, with the usage
    the dump shows for its start.
    """
    __match_args__: Final[tuple[Literal["start"], Literal["length"], Literal["usage"], Literal["detail"]]]
    @property
    def detail(self, /) -> str |None:
        """
        The module, thread, or heap the usage names.
        """
    @property
    def length(self, /) -> int: ...
    @property
    def start(self, /) -> int: ...
    @property
    def usage(self, /) -> Literal["free", "image", "stack", "teb", "peb", "heap", "unknown"]: ...

@final
class CapturedStack(BaseRecord):
    """
    The part of a thread's stack that a dump captured.
    """
    __match_args__: Final[tuple[Literal["start"], Literal["size"]]]
    @property
    def size(self, /) -> int:
        """
        Its size in bytes.
        """
    @property
    def start(self, /) -> int: ...

@final
class CellLocation(BaseRecord):
    """
    Where a cell of a hive is (`!reg cellindex`).
    """
    __match_args__: Final[tuple[Literal["hive"], Literal["cell"], Literal["volatile"], Literal["address"], Literal["size"]]]
    @property
    def address(self, /) -> int:
        """
        The cell: its size field, which its data follows.
        """
    @property
    def block(self, /) -> int |None:
        """
        Where the map entry maps the block: its place in the bin that
        holds it.
        """
    @property
    def cell(self, /) -> int: ...
    @property
    def directory(self, /) -> int |None:
        """
        The cell map directory index; `None` in a flat hive.
        """
    @property
    def hive(self, /) -> int: ...
    @property
    def map_entry(self, /) -> int |None:
        """
        The block's `_HMAP_ENTRY`.
        """
    @property
    def offset(self, /) -> int |None:
        """
        The offset in the block; `None` in a flat hive.
        """
    @property
    def size(self, /) -> Diagnostic[int]:
        """
        The cell's size field: negative for a cell in use.
        """
    @property
    def table(self, /) -> int |None:
        """
        The cell map table index; `None` in a flat hive.
        """
    @property
    def volatile(self, /) -> bool: ...

@final
class ClassDevice(BaseRecord):
    """
    A storage class device as `!storagekd.storclass` lists it.
    """
    __match_args__: Final[tuple[Literal["private_data"], Literal["fdo"], Literal["extension"], Literal["driver"], Literal["device_number"], Literal["vendor"], Literal["product"], Literal["revision"], Literal["serial"], Literal["bus_type"], Literal["removable"], Literal["boot_device"], Literal["packets_total"], Literal["packets_free"], Literal["in_flight"], Literal["packets_stopped"]]]
    @property
    def boot_device(self, /) -> bool: ...
    @property
    def bus_type(self, /) -> str |None:
        """
        `STORAGE_BUS_TYPE` without its `BusType` prefix.
        """
    @property
    def device_number(self, /) -> int |None: ...
    @property
    def driver(self, /) -> str |None:
        """
        The class driver's service name (`disk`).
        """
    @property
    def extension(self, /) -> int |None: ...
    @property
    def fdo(self, /) -> int |None:
        """
        The FDO and its `_FUNCTIONAL_DEVICE_EXTENSION`; `None` when no
        transfer packet names the FDO.
        """
    @property
    def in_flight(self, /) -> list[ClassTransferPacket]:
        """
        The packets classpnp has sent down the stack.
        """
    @property
    def packets_free(self, /) -> int:
        """
        Those on a free list: a NUMA node's, a processor's, or the one
        packet classpnp keeps for forward progress.
        """
    @property
    def packets_stopped(self, /) -> list[str]:
        """
        Why a walk of the packets stopped short.
        """
    @property
    def packets_total(self, /) -> int:
        """
        The transfer packets classpnp allocated (on
        `AllTransferPacketsList`).
        """
    @property
    def private_data(self, /) -> int:
        """
        `_CLASS_PRIVATE_FDO_DATA`, the entry on `classpnp!AllFdosList`.
        """
    @property
    def product(self, /) -> str |None: ...
    @property
    def removable(self, /) -> bool: ...
    @property
    def revision(self, /) -> str |None: ...
    @property
    def serial(self, /) -> str |None: ...
    @property
    def vendor(self, /) -> str |None: ...

@final
class ClassDeviceDetail(BaseRecord):
    """
    One storage class device in detail.
    """
    __match_args__: Final[tuple[Literal["device"], Literal["lower_device"], Literal["lower_pdo"], Literal["bytes_per_sector"], Literal["length"], Literal["timeout"], Literal["max_retries"], Literal["error_count"], Literal["errors"]]]
    @property
    def bytes_per_sector(self, /) -> int: ...
    @property
    def device(self, /) -> ClassDevice: ...
    @property
    def error_count(self, /) -> int: ...
    @property
    def errors(self, /) -> list[ClassError]:
        """
        The errors still in the 16-entry log, oldest first.
        """
    @property
    def length(self, /) -> int:
        """
        `PartitionLength` of partition zero: the device's capacity in bytes.
        """
    @property
    def lower_device(self, /) -> int:
        """
        The lower device object, and the PDO under the stack.
        """
    @property
    def lower_pdo(self, /) -> int: ...
    @property
    def max_retries(self, /) -> int: ...
    @property
    def timeout(self, /) -> int:
        """
        `TimeOutValue` in seconds.
        """

@final
class ClassDevices(BaseRecord):
    """
    The storage class devices on `classpnp!AllFdosList`.
    """
    __match_args__: Final[tuple[Literal["devices"], Literal["unreadable"], Literal["stopped"]]]
    @property
    def devices(self, /) -> list[ClassDevice]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the list stopped short of its head.
        """
    @property
    def unreadable(self, /) -> list[ClassUnreadable]:
        """
        The entries whose private data does not read, in list order.
        """

@final
class ClassError(BaseRecord):
    """
    One error classpnp logged (`_CLASS_ERROR_LOG_DATA`): the SRB that failed
    and its sense data.
    """
    __match_args__: Final[tuple[Literal["tick"], Literal["port"], Literal["path"], Literal["target"], Literal["lun"], Literal["paging"], Literal["retried"], Literal["unhandled"], Literal["srb_status"], Literal["scsi_status"], Literal["cdb"], Literal["sense"]]]
    @property
    def age_ms(self, /) -> int |None:
        """
        Milliseconds from the error to the guest's current tick count.
        """
    @property
    def cdb(self, /) -> list[int]: ...
    @property
    def command(self, /) -> str |None:
        """
        The CDB's command, with its LBA and block count when it has them.
        """
    @property
    def lun(self, /) -> int: ...
    @property
    def paging(self, /) -> bool: ...
    @property
    def path(self, /) -> int: ...
    @property
    def port(self, /) -> int |None:
        """
        `None` where classpnp did not know the port (it logs -1).
        """
    @property
    def retried(self, /) -> bool: ...
    @property
    def scsi_status(self, /) -> int: ...
    @property
    def sense(self, /) -> str |None: ...
    @property
    def srb_status(self, /) -> int: ...
    @property
    def srb_status_text(self, /) -> str:
        """
        The SRB status by name, with `QUEUE_FROZEN` and `AUTOSENSE_VALID`.
        """
    @property
    def target(self, /) -> int: ...
    @property
    def tick(self, /) -> int: ...
    @property
    def unhandled(self, /) -> bool: ...

@final
class ClassTransferPacket(BaseRecord):
    """
    A transfer packet (`_TRANSFER_PACKET`) classpnp has sent down the stack
    and not seen completed.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["irp"], Literal["original_irp"], Literal["srb"], Literal["retries_left"], Literal["timed_out"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def irp(self, /) -> int:
        """
        The IRP classpnp sent down, and the client's IRP it serves.
        """
    @property
    def original_irp(self, /) -> int: ...
    @property
    def request(self, /) -> Srb |None:
        """
        The SRB, decoded.
        """
    @property
    def request_error(self, /) -> str |None:
        """
        Why `request` does not decode.
        """
    @property
    def retries_left(self, /) -> int: ...
    @property
    def srb(self, /) -> int: ...
    @property
    def timed_out(self, /) -> bool: ...

@final
class ClassUnreadable(BaseRecord):
    """
    A class device whose private data does not read.
    """
    __match_args__: Final[tuple[Literal["private_data"], Literal["error"]]]
    @property
    def error(self, /) -> str: ...
    @property
    def private_data(self, /) -> int: ...

class CodeOwner(BaseRecord):
    """
    What holds a code address: `kind` `module` (`name`, and `system` when
    it is part of Windows or a language runtime), `dynamic_code` (no module;
    a dynamic function table covers it, `table_start..table_end`), or
    `unowned` (`region`: the memory, as the dump's memory-info list records
    it).
    """
    @property
    def kind(self, /) -> Literal["module", "dynamic_code", "unowned"]:
        """
        The variant: `module`, `dynamic_code`, `unowned`.
        """
    @final
    class DynamicCode(CodeOwner):
        """
        No module; a dynamic function table the process registered covers
        it, as for JIT-compiled code. The table covers
        `table_start..table_end`.
        """
        __match_args__: Final[tuple[Literal["table_start"], Literal["table_end"]]]
        @property
        def kind(self, /) -> Literal["dynamic_code"]:
            """
            `dynamic_code`.
            """
        @property
        def table_end(self, /) -> int: ...
        @property
        def table_start(self, /) -> int: ...
    @final
    class Module(CodeOwner):
        """
        A loaded module. `system` when it is part of Windows or a language
        runtime, which raise and dispatch exceptions on a caller's behalf.
        """
        __match_args__: Final[tuple[Literal["name"], Literal["system"]]]
        @property
        def kind(self, /) -> Literal["module"]:
            """
            `module`.
            """
        @property
        def name(self, /) -> str: ...
        @property
        def system(self, /) -> bool: ...
    @final
    class Unowned(CodeOwner):
        """
        No module and no dynamic function table. `region` describes the
        memory when the dump's memory-info list records it.
        """
        __match_args__: Final[tuple[Literal["region"]]]
        @property
        def kind(self, /) -> Literal["unowned"]:
            """
            `unowned`.
            """
        @property
        def region(self, /) -> str |None: ...

class CodeView(BaseRecord):
    """
    A CodeView debug record (`IMAGE_DEBUG_TYPE_CODEVIEW`), which identifies
    the PDB that the image was built with.
    """
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
    def kind(self, /) -> Literal["rsds", "nb10"]:
        """
        The variant: `rsds`, `nb10`.
        """
    @final
    class Nb10(CodeView):
        """
        PDB 2.0: a timestamp signature, an age, and the PDB path.
        """
        __match_args__: Final[tuple[Literal["signature"], Literal["age"], Literal["pdb"]]]
        @property
        def age(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["nb10"]:
            """
            `nb10`.
            """
        @property
        def pdb(self, /) -> str:
            """
            The PDB path that the linker recorded.
            """
        @property
        def signature(self, /) -> int:
            """
            The PDB timestamp signature, for `NB10`.
            """
    @final
    class Rsds(CodeView):
        """
        PDB 7.0: a GUID, an age, and the PDB path.
        """
        __match_args__: Final[tuple[Literal["age"], Literal["pdb"]]]
        @property
        def age(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["rsds"]:
            """
            `rsds`.
            """
        @property
        def pdb(self, /) -> str:
            """
            The PDB path that the linker recorded.
            """

@final
class ControlAreaDetail(BaseRecord):
    """
    The `_CONTROL_AREA` of a section, with its segment and subsections
    (`!ca`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["segment"], Literal["section_references"], Literal["pfn_references"], Literal["mapped_views"], Literal["user_references"], Literal["flags"], Literal["flag_names"], Literal["file_object"], Literal["file_name"], Literal["segment_detail"], Literal["subsections"], Literal["subsections_stopped"]]]
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
    def segment_detail(self, /) -> Diagnostic[SegmentDetail]: ...
    @property
    def subsections(self, /) -> list[SubsectionDetail]: ...
    @property
    def subsections_stopped(self, /) -> str |None:
        """
        Why the subsection walk stopped before a null `NextSubsection`.
        `None` if the walk got to a null `NextSubsection`.
        """
    @property
    def user_references(self, /) -> int: ...

@final
class Cpu:
    """
    One processor, identified by its number.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apic(self, /) -> LocalApic:
        """
        Show a processor's local APIC: its ID, priorities, LVT, timer, and pending
        vectors.
        
        Reads the local APIC of the selected processor, or of the processor you
        give: in x2APIC mode through its MSRs (0x800-0x83f), in xAPIC mode through
        its registers at the physical address IA32_APIC_BASE names, read uncached.
        Both need a backend that reads MSRs and device registers: kd or kdnet. The
        target reads them on the processor that stopped it, so for another processor
        ntoseye switches the target to it and back, as rdmsr /p does. Shows the APIC
        ID and version, whether it is the bootstrap processor, the task and
        processor priorities, the spurious-interrupt vector register, the logical
        destination, the interrupt command register as an IPI (vector, delivery
        mode, destination), each local vector table entry (timer, LINT0, LINT1,
        error, performance counter, thermal, CMCI) with its vector, delivery mode,
        trigger, and mask, the timer's counts and divisor, the error status, and the
        vectors in service (ISR), requested (IRR), and level-triggered (TMR).
        """
    def backtrace(self, /, limit: int = 64, vtl: int |None = None) -> list[Frame]:
        """
        Walk this processor's stack from its own registers, whatever `.thread`,
        `.cxr` or `.frame` selected. Halted in the Windows hypervisor, the
        frames are the hypervisor's (`hv+...`), as `.cxr` then `k` shows them;
        elsewhere they are the code it runs. With `vtl`, the walk starts where
        that VTL left off, as the hypervisor saved it (`.vtlcxr`): NT's stack
        for 0, the secure kernel's for 1. A `vtl` needs the processor halted
        in the hypervisor. Frames outside NT's address spaces have no locals.
        `thread.backtrace()` walks a Windows thread instead, from where NT left
        off when its processor is in the hypervisor.
        """
    @property
    def context(self, /) -> str:
        """
        What the vCPU runs: `kernel`, a process name, `hypervisor`, `VTL1`,
        a guest partition's VP (`partition 0x3 VP 1`), or `unknown`; `no
        context` for a dump CPU whose context the dump lacks. Empty if
        ntoseye cannot read the register context.
        """
    def cpuinfo(self, /) -> CpuInfo:
        """
        Show processor identification, speed, and feature bits.
        
        Shows the processor number, vendor, family, model, stepping, speed, and
        feature bits if they are available. For a field that is not available,
        ntoseye uses the triage-dump metadata.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that the register context is not available. None if it is
        available.
        """
    def gdt(self, /) -> Gdt:
        """
        Decode the bounded GDT of the current processor.
        
        Shows the bounded GDT entries of the selected processor, with the base,
        limit, privilege, mode, and presence of each entry.
        """
    def hypercall_caller(self, /) -> HypercallCaller |None:
        """
        The virtual processor whose hypercall this processor handles, for a
        vCPU halted in the Windows hypervisor, as `!hvcall` finds it: the
        guest partition's VP that it serves, else the root partition's VP on
        this processor. A `when=` callback of `breakpoints.add_hypercall()`
        reads the caller's registers and memory through it
        (`dbg.cpus[stop.cpu].hypercall_caller()`), as the breakpoint's
        condition does.
        `None` when the vCPU is not halted in the hypervisor, or the caller is
        unknown: the partitions cannot be walked, or no saved state of a VP
        that the processor runs is current.
        """
    def idt(self, /, vector: int |None = None) -> Idt:
        """
        Decode one IDT entry or the bounded 256-entry IDT.
        
        Shows one IDT vector or all 256 entries, with the handler, selector, gate
        type, DPL, presence, non-nt hooks, and KiIsrThunk chain hints of each
        entry.
        """
    @property
    def info(self, /) -> VcpuInfo:
        """
        The `VcpuInfo` record of this handle: its properties as one value.
        """
    def irql(self, /) -> Irql:
        """
        Show the current IRQL of a processor.
        
        Shows the current IRQL and the Windows level name of the selected
        processor. At a KD break-in, this is the IRQL that the debugger sees,
        which can be different from the level before the break-in.
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
    @property
    def number(self, /) -> int:
        """
        The zero-based processor number: this processor is
        `dbg.cpus[number]`.
        """
    def pcr(self, /) -> Pcr:
        """
        Show the main KPCR data of the selected processor.
        
        Shows the KPCR and KPRCB addresses, the thread pointers, the descriptor
        registers, the TSS, and the available IRQL fields. On AMD64 Windows,
        kernel GS usually points to the KPCR, and backend GS-base registers are
        optional.
        """
    def prcb(self, /) -> Prcb:
        """
        Show the main KPRCB data of the selected processor.
        
        Shows the processor number, the thread pointers, the DPC and interrupt
        counters, and the available ProcessorState metadata of the selected
        KPRCB.
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
        None if ntoseye cannot read the register context.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtl]:
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
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread that runs on this processor.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class CpuFeatureBits(BaseRecord):
    """
    One `_KPRCB` feature-bit field.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["value"]]]
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
    __match_args__: Final[tuple[Literal["processor"], Literal["kprcb"], Literal["source"], Literal["vendor"], Literal["vendor_id"], Literal["family"], Literal["model"], Literal["stepping"], Literal["mhz"], Literal["feature_bits"], Literal["triage_fallback"]]]
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
class CpuTriageFallback(BaseRecord):
    """
    The triage PRCB metadata of the dump, which ntoseye uses when it
    cannot read the KPRCB.
    """
    __match_args__: Final[tuple[Literal["processor_number"], Literal["vendor"], Literal["family"], Literal["mhz"]]]
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
    The processors of the target, by number (`dbg.cpus[0]`,
    `dbg.cpus[stop.cpu]`). The target must be halted to list them.
    """
    def __contains__(self, item: Any, /) -> bool:
        """
        Whether `item` is one of the items (`==`).
        """
    def __getitem__(self, index: int, /) -> Cpu: ...
    def __iter__(self, /) -> Iterator[Cpu]: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, index: int) -> Cpu |None:
        """
        The item at position `index` (negative from the end), or
        `None` if there is none.
        """

@final
class CulpritAttribution(BaseRecord):
    """
    What the available evidence identifies as the cause of the crash: a
    module, or on a user-mode minidump, generated code no module holds.
    Absence means the evidence was not sufficient to name a non-kernel
    culprit.
    """
    __match_args__: Final[tuple[Literal["subject"], Literal["confidence"], Literal["evidence"]]]
    @property
    def confidence(self, /) -> Literal["low", "medium", "high"]: ...
    @property
    def evidence(self, /) -> list[CulpritEvidence]:
        """
        The evidence that points to the culprit.
        """
    @property
    def subject(self, /) -> CulpritSubject: ...

@final
class CulpritEvidence(BaseRecord):
    """
    One item of evidence for a culprit attribution.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["detail"], Literal["address"]]]
    @property
    def address(self, /) -> int |None:
        """
        The address that the evidence uses, if the evidence is an address.
        """
    @property
    def detail(self, /) -> str: ...
    @property
    def kind(self, /) -> Literal["recorded_broken_driver", "recorded_bugcheck_driver", "bugcheck_fault_address", "exception_address", "current_instruction", "top_frame", "power_failure_driver", "pnp_lock_owner_stack", "first_non_system_frame"]: ...

class CulpritSubject(BaseRecord):
    """
    What a culprit attribution names: `kind` `module` (`module`, its name),
    or `dynamic_code` (`dynamic_code`: JIT-compiled or generated code that a
    dynamic function table covers, on a user-mode minidump).
    """
    @property
    def kind(self, /) -> Literal["module", "dynamic_code"]:
        """
        The variant: `module`, `dynamic_code`.
        """
    @final
    class DynamicCode(CulpritSubject):
        """
        On a user-mode minidump, code no module holds that a dynamic
        function table covers: JIT-compiled or otherwise generated code.
        """
        __match_args__: Final[tuple[Literal["dynamic_code"]]]
        @property
        def dynamic_code(self, /) -> DynamicCodeCulprit: ...
        @property
        def kind(self, /) -> Literal["dynamic_code"]:
            """
            `dynamic_code`.
            """
    @final
    class Module(CulpritSubject):
        __match_args__: Final[tuple[Literal["module"]]]
        @property
        def kind(self, /) -> Literal["module"]:
            """
            `module`.
            """
        @property
        def module(self, /) -> str: ...

@final
class DataDirectory(BaseRecord):
    """
    One `IMAGE_DATA_DIRECTORY` entry.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["name"], Literal["rva"], Literal["size"]]]
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
    def rva(self, /) -> int:
        """
        An RVA, except for the security directory, whose value is a file
        offset (the certificate table is not mapped).
        """
    @property
    def size(self, /) -> int: ...

@final
class DebugLine(BaseRecord):
    """
    A captured line of guest debug output (DbgPrint, kernel printf).
    """
    __match_args__: Final[tuple[Literal["seq"], Literal["timestamp_ms"], Literal["text"]]]
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
class DebugOutputPage(BaseRecord):
    """
    A page of captured guest debug output, plus the cursor for the next poll.
    """
    __match_args__: Final[tuple[Literal["lines"], Literal["next_seq"], Literal["dropped"]]]
    @property
    def dropped(self, /) -> bool:
        """
        Whether the bounded ring removed lines that the caller did not read
        (the cursor predated the lines it keeps).
        """
    @property
    def lines(self, /) -> list[DebugLine]: ...
    @property
    def next_seq(self, /) -> int:
        """
        The cursor to give on the next call to continue after the last line.
        """

@final
class DebugRecord(BaseRecord):
    """
    One `IMAGE_DEBUG_DIRECTORY` entry as `!dh` shows it, with its CodeView
    record decoded when it is one.
    """
    __match_args__: Final[tuple[Literal["codeview"]]]
    @property
    def address_of_raw_data(self, /) -> int: ...
    @property
    def characteristics(self, /) -> int: ...
    @property
    def codeview(self, /) -> Diagnostic[CodeView] |None:
        """
        The decoded CodeView record, or why it does not read. `None` for
        other entry types.
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
        `cv`, `pogo`, `repro`, ...
        """
    @property
    def version(self, /) -> str:
        """
        `major.minor`.
        """

@final
class Debugger:
    """
    A live debugging session. You can use it as a context manager: when the
    `with` block ends, the debugger closes (`close()`), which removes all
    breakpoints, resumes the target, and ends the session.
    
    You can use it from any Python thread, and the session thread runs the calls
    one at a time. A call that waits (`run()`, `wait()`) releases the GIL.
    Ctrl+C (`KeyboardInterrupt`) during a call that runs or waits on the
    target breaks in, as in the REPL, and raises the exception; the target is
    left halted where it was. Between calls the session continues to
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
    @property
    def cpus(self, /) -> Cpus:
        """
        The processors (vCPUs) of the target: `cpus[0].registers.rip`.
        """
    def crash(self, /, timeout: float |None = None) -> Stop:
        """
        Force a MANUALLY_INITIATED_CRASH (bugcheck 0xE2).
        
        Windows first writes its crash dump, which often takes a minute, and the
        target ignores break-ins during this time. Then Windows reboots or, if
        automatic restart is disabled, breaks in. Ctrl+C stops the wait.
        """
    def debug_log(self, /, since: int = 0) -> DebugOutputPage:
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
        using the registers of the stopped vCPU (on a user-mode minidump, of
        the selected thread).
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
        Break into the running target and return the stop that results. On a
        halted target, return the stop it is halted at (`break` refuses it).
        """
    @property
    def memory(self, /) -> Memory:
        """
        Kernel virtual memory, read through the page tables of the kernel. User
        addresses are not mapped here, so read them through `process.memory`.
        On a user-mode minidump, the captured process's memory.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Loaded kernel modules: `modules["nt"]`, iteration, `.at(address)`. On a
        user-mode minidump, the modules the dump lists.
        """
    def notices(self, /) -> list[Notice]:
        """
        Remove and return what the debugger reported since the last call, in
        order. Each notice has a `level`: `"warning"` for something that did
        not work as it should, such as a breakpoint that failed to re-arm or
        host memory that no longer matched after a reload, or `"info"` for
        status, such as a background symbol fetch finishing, a breakpoint
        slot that was reclaimed, or the `ModLoad:` line of an `sxn ld` filter.
        """
    @property
    def partition(self, /) -> int |None:
        """
        The ID of the hypervisor partition inspected in place of the target
        (see `select_partition`), or `None` while the target is.
        """
    @property
    def physical(self, /) -> Memory:
        """
        Guest-physical memory, without address translation. A user-mode
        minidump has none, and its reads raise `NtoseyeError`.
        """
    @property
    def processes(self, /) -> Processes:
        """
        Running processes, keyed by PID: `processes[4]`, `.find(name)`.
        """
    def reboot(self, /, timeout: float |None = None) -> Stop:
        """
        Reboot the debug target and reload its kernel context.
        
        ntoseye sends the reboot without confirmation, and handles the next KD
        state-change through the normal target-reload path.
        """
    def reload(self, /) -> None:
        """
        Rebuild the guest state now (find the kernel again). Stops already do
        this when the backend reports a reload, and this function forces a
        rebuild. A user-mode minidump has no kernel to find, and raises
        `NtoseyeError`.
        """
    def run(self, /, timeout: float |None = None, *, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None, disposition: Literal["handled", "not_handled"] |None = None) -> Stop |None:
        """
        Resume VM execution.
        
        With an address, g runs to a temporary breakpoint at that address.
        ntoseye checks that an instruction starts there as bp does: it refuses an
        address inside an instruction and warns when it cannot check. In
        secure-kernel code, this breakpoint uses a debug register, and ntoseye
        never patches the code. The .vtl 1 memory view accepts only g without an
        address, which leaves the view before it resumes the VM. To stop in VTL1,
        use `ba e1`.
        """
    @property
    def secure_kernel(self, /) -> SecureKernel:
        """
        The VBS secure kernel (VTL1), with read-only `memory`, `symbols`,
        `types`, `modules`, and `trustlets`. ntoseye finds it in host memory on
        first use and raises `NtoseyeError` if VBS is not running or the backend
        cannot read host memory. This feature is experimental.
        """
    def select_partition(self, /, partition_id: int) -> None:
        """
        Inspect the Windows guest that hypervisor partition `partition_id`
        runs (a Windows Sandbox, a Hyper-V VM) in place of the target, as
        `.partition` does: `memory`, `processes`, `modules`, `symbols`,
        `types` and `threads` then read that guest, through its EPT, and the
        vCPUs are its VPs, with their VTL0 registers. The target stays
        halted. `memory.write` writes the guest's memory through its EPT, and
        a register write goes to the target's vCPU that runs the selected VP at
        the stop; a VP no vCPU runs has its registers in the hypervisor's
        memory, and raises `NtoseyeError`. `breakpoints.add(..., hardware=True)`
        and `breakpoints.watch` set the partition's breakpoints, which stop
        only on its VPs (`processor=` names one) and need the gdb backend;
        software breakpoints raise. `run` leaves the view and runs the
        target, and a hit of the partition's breakpoint returns in its view,
        on the VP that hit it. `step`, `step_over` and `step_out` step the
        thread of the selected VP, and `run(address=...)` runs until any of its
        VPs reaches an address, each a run of the target to a breakpoint of the
        partition's; `step(until=...)` and `trace_calls` raise. The root
        partition's ID (1) returns to the target. Handles minted on either side
        of a switch go stale (`generation` advances). The target must be halted.
        This feature is experimental.
        """
    def step(self, /, timeout: float |None = None, *, until: Literal["call", "ret", "branch"] |int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Stop:
        """
        Step one instruction (step into).
        """
    def step_out(self, /, timeout: float |None = None) -> Stop:
        """
        Run until the current function returns.
        
        gu stops at the return address only when the thread that you step returns
        from this call. Other threads that get to the address, and deeper calls of
        the same function, continue to run.
        """
    def step_over(self, /, timeout: float |None = None, *, until: Literal["call", "ret", "branch"] |int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Stop:
        """
        Step over the current instruction.
        
        If the instruction is a call, p runs to the instruction after the call and
        stops there only when the thread that you step returns from that call.
        Other threads that get to the address, and deeper calls of the same code,
        continue to run.
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
        `search(query)`, and the symbol and source paths. On a user-mode
        minidump, the symbols of the dump's modules.
        """
    @property
    def threads(self, /) -> Threads:
        """
        All Windows threads, keyed by TID: `threads[tid]`, `.at(ethread)`.
        """
    def trace_calls(self, /, timeout: float |None = None, *, limit: int = 10000) -> CallTrace:
        """
        Watch and trace calls until the current function returns.
        """
    @property
    def types(self, /) -> Types:
        """
        Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`. On a user-mode
        minidump, the types of the dump's modules' PDBs (`types["ntdll!_PEB"]`).
        """
    @property
    def user_dump(self, /) -> UserDump |None:
        """
        The process, threads, and exception a user-mode minidump captured,
        or `None` on a kernel target. A user-mode minidump has no kernel, so
        `processes`, `threads`, `cpus`, `drivers`, `physical`, and the
        kernel's `inspect` reports raise `NtoseyeError` on it.
        """
    def wait(self, /, timeout: float |None = None) -> Stop |None:
        """
        Wait for the next stop without resuming. If the target is already
        halted, return the current stop immediately, and return `None` if the
        target is still running after `timeout`.
        """
    def write_dump(self, /, path: str) -> DumpWrite:
        """
        Write a full PAGEDU64 kernel dump from the halted target.
        
        .dump accepts both /f and /ma as WinDbg-compatible full-dump switches.
        ntoseye writes the dump as a stream, page by page, and you can cancel it
        with Ctrl+C.
        """

@final
class DecodedHypercall(BaseRecord):
    """
    The hypercall of a VMCALL exit, with its input decoded as the Hyper-V
    TLFS lays it out (`!hvcall`): the one data model that the REPL, the MCP
    trailer, and the SDK show.
    """
    __match_args__: Final[tuple[Literal["input_value"], Literal["name"], Literal["input_gpa"], Literal["output_gpa"], Literal["decoded"], Literal["fields"], Literal["elements"], Literal["unavailable"]]]
    @property
    def code(self, /) -> int:
        """
        The call code (bits 15:0 of the input value).
        """
    @property
    def decoded(self, /) -> bool:
        """
        Whether ntoseye knows the layout of the call's input. When it does
        not, `fields` holds the input as raw qwords, `Input[0]` on: RDX and
        R8 for a fast call, else the first [`RAW_QWORDS`] of the input page.
        """
    @property
    def elements(self, /) -> list[HypercallElement]:
        """
        A rep call's input list, every element up to the rep count, those
        before the rep start (done already) included.
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
        The call on one line, as the stop header shows it:
        `hypercall 0x0003 HvCallFlushVirtualAddressList rep 0/12`.
        """
    @property
    def unavailable(self, /) -> str |None:
        """
        Why some of the input is not shown: the input page is unreadable, the
        input is in XMM registers, or it runs past the end of its page.
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
    __match_args__: Final[tuple[Literal["base"], Literal["limit"]]]
    @property
    def base(self, /) -> int: ...
    @property
    def limit(self, /) -> int:
        """
        The table limit: the table size in bytes, minus one.
        """

@final
class DevNodeDetail(BaseRecord):
    """
    A decoded `_DEVICE_NODE` and, if requested, its flat subtree
    (`!devnode`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["pdo"], Literal["parent"], Literal["sibling"], Literal["child"], Literal["instance_path"], Literal["service_name"], Literal["state"], Literal["state_name"], Literal["previous_state"], Literal["previous_state_name"], Literal["state_history"], Literal["state_history_entry"], Literal["flags"], Literal["user_flags"], Literal["completion_status"], Literal["problem"], Literal["problem_name"], Literal["problem_status"], Literal["pending_irp"], Literal["subtree"], Literal["subtree_truncated"]]]
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
    def state_history(self, /) -> list[StateHistoryEntry]: ...
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
class DevNodePower(BaseRecord):
    """
    The power fields of the device node of a device's stack.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["instance_path"], Literal["current_state"], Literal["fx_device"], Literal["fx_pending_irp"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def current_state(self, /) -> PowerEnum:
        """
        `CurrentPowerState`: the device state the PDO is in, as PnP records
        it.
        """
    @property
    def fx_device(self, /) -> int:
        """
        The device's runtime power management (`_POP_FX_DEVICE`), or 0 when
        its driver did not register with the power framework.
        """
    @property
    def fx_pending_irp(self, /) -> int |None:
        """
        The device power IRP the power framework has outstanding.
        """
    @property
    def instance_path(self, /) -> str: ...

@final
class DevNodeSummary(BaseRecord):
    """
    The identity and state of a device node, as the subtree and triage
    lists show them.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["pdo"], Literal["instance_path"], Literal["service_name"], Literal["state"], Literal["state_name"], Literal["problem"], Literal["problem_name"], Literal["problem_status"], Literal["pending_irp"], Literal["depth"]]]
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
    One `_DEVICE_OBJECT`, on its driver's device chain.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_OBJECT` address.
        """
    @property
    def attached(self, /) -> int:
        """
        `AttachedDevice`, the device layered above this device. 0 if there is none.
        """
    @property
    def characteristics(self, /) -> int: ...
    @property
    def device_type(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def info(self, /) -> DriverDeviceLink:
        """
        The `DriverDeviceLink` record of this handle: its properties as one value.
        """
    def inspect(self, /) -> DeviceObjectDetail:
        """
        Show a DEVICE_OBJECT and its attached stack.
        """
    @property
    def next(self, /) -> int:
        """
        `NextDevice`, the next device of the driver. 0 at the end of the chain.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class DeviceDriver(BaseRecord):
    """
    A driver, found from one of its device objects or its driver object.
    """
    __match_args__: Final[tuple[Literal["driver_object"], Literal["name"], Literal["driver_start"], Literal["module"]]]
    @property
    def driver_object(self, /) -> int: ...
    @property
    def driver_start(self, /) -> int: ...
    @property
    def module(self, /) -> str |None:
        """
        The loaded module that holds `driver_start`, such as `viostor.sys`.
        """
    @property
    def name(self, /) -> str:
        """
        `\\Driver\\viostor`; empty when the driver object has no name.
        """

@final
class DeviceNotifyState(BaseRecord):
    """
    The device notification pass of a system power action
    (`_POP_DEVICE_SYS_STATE`, `PopAction.DevState`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["irp_minor"], Literal["system_state"], Literal["thread"], Literal["status"], Literal["failed_device"], Literal["waking"], Literal["cancelled"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def cancelled(self, /) -> bool: ...
    @property
    def failed_device(self, /) -> int: ...
    @property
    def irp_minor(self, /) -> int: ...
    @property
    def status(self, /) -> int: ...
    @property
    def system_state(self, /) -> PowerEnum: ...
    @property
    def thread(self, /) -> int: ...
    @property
    def waking(self, /) -> bool: ...

@final
class DeviceObjectDetail(BaseRecord):
    """
    A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
    """
    __match_args__: Final[tuple[Literal["object"], Literal["via_pointer"], Literal["device_type"], Literal["flags"], Literal["characteristics"], Literal["driver_object"], Literal["attached_device"], Literal["next_device"], Literal["current_irp"], Literal["device_extension"], Literal["attached_stack"]]]
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
class DevicePower(BaseRecord):
    """
    `!podev`: a device object's power state.
    """
    __match_args__: Final[tuple[Literal["device"], Literal["driver"], Literal["flags"], Literal["extension"], Literal["power_flags"], Literal["system_state"], Literal["device_state"], Literal["idle"], Literal["devnode"], Literal["irps"]]]
    @property
    def device(self, /) -> int: ...
    @property
    def device_state(self, /) -> PowerEnum:
        """
        The last device state the driver set with `PoSetPowerState`.
        """
    @property
    def devnode(self, /) -> Diagnostic[DevNodePower] |None: ...
    @property
    def driver(self, /) -> Diagnostic[DeviceDriver]: ...
    @property
    def extension(self, /) -> int: ...
    @property
    def flags(self, /) -> int:
        """
        `DEVICE_OBJECT.Flags`, for `DO_POWER_PAGABLE` and `DO_POWER_INRUSH`.
        """
    @property
    def idle(self, /) -> Diagnostic[IdleDetection] |None: ...
    @property
    def irps(self, /) -> Diagnostic[list[PowerIrp]]:
        """
        The power IRPs on `nt!PopIrpList` sent to the device's stack.
        """
    @property
    def power_flags(self, /) -> int: ...
    @property
    def power_inrush(self, /) -> bool:
        """
        `DO_POWER_INRUSH`: the device draws inrush current at power-up.
        """
    @property
    def power_pagable(self, /) -> bool:
        """
        `DO_POWER_PAGABLE`: the driver handles power IRPs at PASSIVE_LEVEL.
        """
    @property
    def system_state(self, /) -> PowerEnum:
        """
        The last system state the driver set with `PoSetPowerState`.
        """

@final
class DeviceStackDetail(BaseRecord):
    """
    A device stack from the top filter to the PDO, and the device node of
    the PDO (`!devstack`).
    """
    __match_args__: Final[tuple[Literal["argument"], Literal["requested_device"], Literal["entries"], Literal["pdo_devnode"], Literal["pdo_devnode_error"], Literal["truncated"]]]
    @property
    def argument(self, /) -> int:
        """
        The address that you gave: a device object, a pointer to a device
        object, or a device node.
        """
    @property
    def entries(self, /) -> list[DeviceStackEntry]:
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
class DeviceStackEntry(BaseRecord):
    """
    A device object in a device stack.
    """
    __match_args__: Final[tuple[Literal["device_object"], Literal["driver_object"], Literal["driver_name"], Literal["device_extension"], Literal["object_name"], Literal["is_argument"]]]
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
class DisasmOperand(BaseRecord):
    """
    One explicit operand of a decoded instruction. Fields that do not apply
    to its `kind` are None.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["text"], Literal["register"], Literal["full_register"], Literal["base"], Literal["index"], Literal["scale"], Literal["displacement"], Literal["size"], Literal["segment"], Literal["immediate"]]]
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
    def kind(self, /) -> Literal["register", "memory", "immediate", "branch", "other"]:
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
class DisasmRow(BaseRecord):
    """
    One decoded instruction. `asm` is its text; `mnemonic` and `operands`
    describe the same instruction structurally, for code that follows code
    instead of reading it.
    """
    __match_args__: Final[tuple[Literal["ip"], Literal["hex"], Literal["length"], Literal["comment"]]]
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
    def ip(self, /) -> int:
        """
        The address of the instruction.
        """
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
    def operands(self, /) -> list[DisasmOperand]:
        """
        The explicit operands, in instruction order.
        """

@final
class DmpException(BaseRecord):
    """
    The exception a crash dump recorded.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["flags"], Literal["address"], Literal["parameters"]]]
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
class DmpSystemInfo(BaseRecord):
    """
    The system that a crash dump comes from, as the system-info stream of
    the dump records it.
    """
    __match_args__: Final[tuple[Literal["major_version"], Literal["minor_version"], Literal["system_time"], Literal["system_up_time"], Literal["product_type"], Literal["suite_mask"], Literal["machine_image_type"], Literal["service_pack_build"]]]
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
    def minor_version(self, /) -> int:
        """
        The build number.
        """
    @property
    def product(self, /) -> str:
        """
        `Workstation`, `DomainController`, `Server`, or `Unknown`.
        """
    @property
    def product_type(self, /) -> int:
        """
        `VER_NT_*`: 1 workstation, 2 domain controller, 3 server.
        """
    @property
    def service_pack_build(self, /) -> int: ...
    @property
    def suite_mask(self, /) -> int:
        """
        The product suite (`VER_SUITE_*`) bits.
        """
    @property
    def system_time(self, /) -> int:
        """
        When the dump was taken (FILETIME), 0 if the dump does not record it.
        """
    @property
    def system_time_utc(self, /) -> str |None:
        """
        When the dump was taken (ISO 8601 UTC). `None` if the dump does not
        record it.
        """
    @property
    def system_up_time(self, /) -> int:
        """
        The system uptime, in 100 ns units.
        """
    @property
    def system_up_time_secs(self, /) -> int |None:
        """
        The system uptime in seconds. `None` if the dump does not record it.
        """

@final
class Dpc(BaseRecord):
    """
    A queued `_KDPC`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["deferred_routine"], Literal["deferred_routine_symbol"], Literal["context"], Literal["importance"]]]
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
    __match_args__: Final[tuple[Literal["processor"], Literal["queue"], Literal["entries"], Literal["termination"]]]
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
    def termination(self, /) -> ListTermination:
        """
        How the list walk ended.
        """

@final
class DpcQueues(BaseRecord):
    """
    The queued DPCs of all processors (`!dpcs`).
    """
    __match_args__: Final[tuple[Literal["queues"], Literal["total"], Literal["truncated"], Literal["errors"]]]
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
    def device_object(self, /) -> int:
        """
        The first device on the chain of the driver. 0 if there is none.
        """
    @property
    def devices(self, /) -> list[Device]:
        """
        The device objects that this driver created.
        """
    @property
    def driver_unload(self, /) -> int: ...
    @property
    def info(self, /) -> DriverObjectInfo:
        """
        The `DriverObjectInfo` record of this handle: its properties as one value.
        """
    def inspect(self, /) -> DriverObjectDetail:
        """
        Show a DRIVER_OBJECT with its device chain and dispatch table.
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
        The size of the driver image in bytes.
        """
    @property
    def start(self, /) -> int:
        """
        The base address of the driver image.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class DriverDeviceLink(BaseRecord):
    """
    A device on the `DeviceObject`/`NextDevice` chain of a driver.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["device_type"], Literal["flags"], Literal["characteristics"], Literal["attached"], Literal["next"]]]
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_OBJECT` address.
        """
    @property
    def attached(self, /) -> int:
        """
        `AttachedDevice`, the device layered above this device. 0 if there is none.
        """
    @property
    def characteristics(self, /) -> int: ...
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
class DriverObjectDetail(BaseRecord):
    """
    A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
    """
    __match_args__: Final[tuple[Literal["object"], Literal["via_pointer"], Literal["name"], Literal["driver_start"], Literal["driver_size"], Literal["driver_section"], Literal["driver_unload"], Literal["devices"], Literal["dispatch"]]]
    @property
    def devices(self, /) -> list[DriverDeviceLink]:
        """
        The `DeviceObject`/`NextDevice` chain.
        """
    @property
    def dispatch(self, /) -> list[IrpDispatchRoutine]:
        """
        The 28 `IRP_MJ_*` dispatch routines (`MajorFunction`), in `IRP_MJ_*`
        code order.
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
class DriverObjectInfo(BaseRecord):
    """
    A `_DRIVER_OBJECT` from the Driver and FileSystem directories of the
    object manager (`drivers`).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["object"], Literal["start"], Literal["size"], Literal["device_object"], Literal["driver_unload"]]]
    @property
    def device_object(self, /) -> int:
        """
        The first device on the chain of the driver. 0 if there is none.
        """
    @property
    def driver_unload(self, /) -> int: ...
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
        The size of the driver image in bytes.
        """
    @property
    def start(self, /) -> int:
        """
        The base address of the driver image.
        """

@final
class DriverQueueState(BaseRecord):
    """
    What the driver keeps of a split queue.
    """
    __match_args__: Final[tuple[Literal["avail_idx"], Literal["last_used"], Literal["free"], Literal["unkicked"]]]
    @property
    def avail_idx(self, /) -> int:
        """
        `master_vring_avail.idx`: the avail index the driver wrote, which
        the ring's own shows once published.
        """
    @property
    def free(self, /) -> int:
        """
        `num_unused`: free descriptors.
        """
    @property
    def last_used(self, /) -> int:
        """
        `last_used`: the used index up to which the driver took buffers back.
        """
    @property
    def unkicked(self, /) -> int:
        """
        `num_added_since_kick`: buffers added since the device was notified.
        """

@final
class Drivers:
    """
    The driver objects in the `Driver` directory of the object manager, keyed
    by name (`dbg.drivers`).
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: str |DriverObjectInfo, /) -> Driver:
        """
        The driver object with a name, with or without its directory prefix,
        or the one a `DriverObjectInfo` record describes.
        """
    def __iter__(self, /) -> Iterator[Driver]: ...
    def __len__(self, /) -> int: ...
    def at(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Driver |None:
        """
        The driver object at `address`, or the one whose image contains it.
        """
    def get(self, /, key: str |DriverObjectInfo) -> Driver |None:
        """
        The driver object with a name, with or without its directory prefix,
        or the one a `DriverObjectInfo` record describes.
        """

@final
class DumpWrite(BaseRecord):
    """
    A kernel dump that `.dump` wrote.
    """
    __match_args__: Final[tuple[Literal["path"], Literal["unreadable_pages"]]]
    @property
    def path(self, /) -> str: ...
    @property
    def unreadable_pages(self, /) -> int:
        """
        The pages that could not be read, written as zeros.
        """

@final
class DynamicCodeCulprit(BaseRecord):
    """
    Generated code a culprit attribution names: no module holds it, and a
    dynamic function table the process registered covers it.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["table_start"], Literal["table_end"], Literal["caller"]]]
    @property
    def address(self, /) -> int:
        """
        The blamed frame's address.
        """
    @property
    def caller(self, /) -> UserFrame |None:
        """
        The first frame further out that a module holds: the module code
        that called into the generated code.
        """
    @property
    def table_end(self, /) -> int: ...
    @property
    def table_start(self, /) -> int:
        """
        The dynamic function table covering it, `table_start..table_end`.
        """

@final
class EptDifference(BaseRecord):
    """
    A range of guest physical memory, `start..end`, that two EPTs map
    differently: with different access, or in one of them only (`None`).
    """
    __match_args__: Final[tuple[Literal["start"], Literal["end"]]]
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
    __match_args__: Final[tuple[Literal["host_physical"], Literal["page_size"], Literal["read"], Literal["write"], Literal["execute"], Literal["user_execute"], Literal["memory_type"], Literal["entries"]]]
    @property
    def entries(self, /) -> list[int]:
        """
        The entry of each level, from the PML4 down.
        """
    @property
    def execute(self, /) -> bool:
        """
        Supervisor-mode execute when `user_execute` is known, else any.
        """
    @property
    def host_physical(self, /) -> int: ...
    @property
    def memory_type(self, /) -> int:
        """
        The memory type of the leaf entry (0 UC, 1 WC, 4 WT, 5 WP, 6 WB).
        """
    @property
    def page_size(self, /) -> int:
        """
        The size of the mapping page: 4 KiB, 2 MiB, or 1 GiB.
        """
    @property
    def read(self, /) -> bool:
        """
        Each access is allowed only if every entry of the walk allows it.
        """
    @property
    def user_execute(self, /) -> bool |None:
        """
        User-mode execute, when the VTL uses mode-based execute control.
        """
    @property
    def write(self, /) -> bool: ...

@final
class ErrorCode(BaseRecord):
    """
    A decoded NTSTATUS, Win32, or HRESULT code (`!error`).
    """
    __match_args__: Final[tuple[Literal["code"], Literal["kind"], Literal["name"], Literal["description"], Literal["severity"], Literal["facility"], Literal["customer"], Literal["win32_code"], Literal["win32_name"]]]
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
    def kind(self, /) -> Literal["ntstatus", "hresult", "win32", "unknown"]: ...
    @property
    def name(self, /) -> str:
        """
        The symbolic name of the code.
        """
    @property
    def severity(self, /) -> Literal["success", "informational", "warning", "error"] |None:
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
    __match_args__: Final[tuple[Literal["address"], Literal["state"], Literal["state_name"], Literal["processor"], Literal["sequence_number"], Literal["timestamp"], Literal["saved_offset"], Literal["current_offset"], Literal["data_end"], Literal["reference_count"]]]
    @property
    def address(self, /) -> int:
        """
        The buffer's kernel address or, for a buffer out of a minidump's ETW
        data, the offset of its header in that block.
        """
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
class EtwBufferIssue(BaseRecord):
    """
    A buffer in which ntoseye could not decode all events.
    """
    __match_args__: Final[tuple[Literal["buffer"], Literal["offset"], Literal["reason"]]]
    @property
    def buffer(self, /) -> int:
        """
        The `EtwBuffer.address` of the buffer.
        """
    @property
    def offset(self, /) -> int:
        """
        The position in the buffer where the walk stopped.
        """
    @property
    def reason(self, /) -> str: ...

@final
class EtwDumpData(BaseRecord):
    """
    The ETW trace sessions that Windows saved as it wrote a minidump
    (tagged data `nt!EtwSecondaryDumpDataGuid`): the sessions started with
    `EVENT_TRACE_ADDTO_TRIAGE_DUMP`, such as EventLog-System, and the system
    fields that the logfile header of an .etl records.
    """
    __match_args__: Final[tuple[Literal["timer_resolution"], Literal["build_number"], Literal["cpu_mhz"], Literal["boot_time"], Literal["perf_frequency"], Literal["loggers"], Literal["stop"]]]
    @property
    def boot_time(self, /) -> int:
        """
        `EtwpBootTime`, a FILETIME.
        """
    @property
    def boot_time_utc(self, /) -> str |None:
        """
        `boot_time` as UTC. `None` if it is out of range.
        """
    @property
    def build_number(self, /) -> int:
        """
        `NtBuildNumber`, its top nibble the free or checked build.
        """
    @property
    def cpu_mhz(self, /) -> int:
        """
        `EtwCPUSpeedInMHz`.
        """
    @property
    def loggers(self, /) -> list[EtwDumpLogger]: ...
    @property
    def perf_frequency(self, /) -> int:
        """
        `EtwPerfFreq`, the QPC frequency of PerfCounter timestamps.
        """
    @property
    def size(self, /) -> int:
        """
        Bytes of the ETW data.
        """
    @property
    def stop(self, /) -> str |None:
        """
        Why the walk of the data stopped before its end. `None` if it read
        all of it.
        """
    @property
    def timer_resolution(self, /) -> int:
        """
        `KeMaximumIncrement`, the clock interrupt interval in 100 ns.
        """

@final
class EtwDumpLogger(BaseRecord):
    """
    An ETW trace session that Windows saved in a minidump: what the
    session's header in the dump records of its `_WMI_LOGGER_CONTEXT`, and
    its buffers.
    """
    __match_args__: Final[tuple[Literal["logger_id"], Literal["name"], Literal["logger_mode"], Literal["buffer_size"], Literal["start_time"], Literal["buffers"]]]
    @property
    def buffer_size(self, /) -> int:
        """
        Bytes per buffer.
        """
    @property
    def buffers(self, /) -> list[EtwBuffer]:
        """
        The buffers saved of the session, which are all the buffers on its
        `GlobalList`. A buffer's `address` is the offset of its header in the
        dump's ETW data, and its `data_end` its bytes there.
        """
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
    def logger_id(self, /) -> int: ...
    @property
    def logger_mode(self, /) -> int: ...
    @property
    def logger_mode_names(self, /) -> list[str]:
        """
        The `EVENT_TRACE_*_MODE` bits that are set in `logger_mode`.
        """
    @property
    def name(self, /) -> str: ...
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
class EtwEvent(BaseRecord):
    """
    An event that ntoseye decoded from a trace buffer, with the buffer it
    came from and its time.
    """
    __match_args__: Final[tuple[Literal["buffer"], Literal["processor"], Literal["system_time"], Literal["record"], Literal["message_format"]]]
    @property
    def buffer(self, /) -> int:
        """
        The buffer that the event came from (its `EtwBuffer.address`).
        """
    @property
    def message_format(self, /) -> EtwMessageFormat |None:
        """
        The message rendered from its TMF, for a WPP message whose trace
        message format a loaded PDB declares; else `None`.
        """
    @property
    def processor(self, /) -> int: ...
    @property
    def record(self, /) -> EtwRecord: ...
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

@final
class EtwEventClass(BaseRecord):
    """
    `Class.Type`/`Level`/`Version` of a classic event.
    """
    __match_args__: Final[tuple[Literal["type"], Literal["level"], Literal["version"]]]
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
    __match_args__: Final[tuple[Literal["id"], Literal["version"], Literal["channel"], Literal["level"], Literal["opcode"], Literal["task"], Literal["keyword"]]]
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
    The events still in the buffers of a session, oldest first
    (`!wmitrace.logdump`).
    """
    __match_args__: Final[tuple[Literal["logger"], Literal["buffers_walked"], Literal["list_stop"], Literal["total_events"], Literal["qpc_frequency"], Literal["cpu_mhz"], Literal["issues"], Literal["message_format_note"], Literal["events"]]]
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
    def issues(self, /) -> list[EtwBufferIssue]:
        """
        The buffers that ntoseye skipped fully (compressed or unreadable), and
        the walks that stopped early.
        """
    @property
    def list_stop(self, /) -> str |None:
        """
        Why the walk of the `GlobalList`, or of a minidump's ETW data,
        stopped before its end. `None` if the walk completed.
        """
    @property
    def logger(self, /) -> EtwLogger |EtwDumpLogger: ...
    @property
    def message_format_note(self, /) -> str |None:
        """
        Why some WPP messages have no `message_format`. `None` if all
        messages have one.
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
class EtwExtendedItem(BaseRecord):
    """
    An `EVENT_HEADER` extended data item.
    """
    __match_args__: Final[tuple[Literal["type"], Literal["data"]]]
    @property
    def data(self, /) -> bytes:
        """
        The bytes of the item.
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
class EtwLogFile(BaseRecord):
    """
    The buffers of a session as an .etl file: a header buffer, then each
    buffer that holds events.
    """
    __match_args__: Final[tuple[Literal["logger"], Literal["buffers"], Literal["list_stop"], Literal["issues"]]]
    @property
    def buffers(self, /) -> int:
        """
        The buffers with events written after the header buffer.
        """
    @property
    def issues(self, /) -> list[EtwBufferIssue]:
        """
        The buffers left out (unreadable) and the buffers cut short before a
        record that does not decode.
        """
    @property
    def list_stop(self, /) -> str |None:
        """
        Why the walk of the `GlobalList`, or of a minidump's ETW data, ended
        early. `None` if the walk completed.
        """
    @property
    def logger(self, /) -> EtwLogger |EtwDumpLogger: ...
    @property
    def size(self, /) -> int:
        """
        Bytes in the file.
        """

@final
class EtwLogSave(BaseRecord):
    """
    An .etl file that `!wmitrace.logsave` wrote on the host.
    """
    __match_args__: Final[tuple[Literal["path"], Literal["file"]]]
    @property
    def file(self, /) -> EtwLogFile: ...
    @property
    def path(self, /) -> str:
        """
        Where the file was written.
        """

@final
class EtwLogger(BaseRecord):
    """
    An active ETW trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["logger_id"], Literal["name"], Literal["log_file_name"], Literal["logger_mode"], Literal["flags"], Literal["flag_names"], Literal["collection_on"], Literal["buffer_size"], Literal["maximum_event_size"], Literal["minimum_buffers"], Literal["maximum_buffers"], Literal["number_of_buffers"], Literal["buffers_available"], Literal["peak_buffers"], Literal["buffers_written"], Literal["events_lost"], Literal["log_buffers_lost"], Literal["real_time_buffers_delivered"], Literal["real_time_buffers_lost"], Literal["consumers"], Literal["start_time"], Literal["flush_timer"], Literal["flush_threshold"], Literal["maximum_file_size"], Literal["logger_thread"], Literal["logger_status"]]]
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
    def instance_guid(self, /) -> str:
        """
        `InstanceGuid`, braced.
        """
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
    __match_args__: Final[tuple[Literal["logger"], Literal["buffers"], Literal["list_stop"]]]
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
    __match_args__: Final[tuple[Literal["silo_state"], Literal["context_array"], Literal["max_loggers"], Literal["loggers"]]]
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
class EtwMessage(BaseRecord):
    """
    The fields that follow a `MESSAGE_TRACE_HEADER`, as the
    `TRACE_MESSAGE_*` option flags of the header select them. A field is
    `None` if the flags do not select it.
    """
    __match_args__: Final[tuple[Literal["number"], Literal["option_flags"], Literal["sequence"], Literal["component_id"]]]
    @property
    def component_id(self, /) -> int |None: ...
    @property
    def guid(self, /) -> str |None:
        """
        The message GUID, braced.
        """
    @property
    def number(self, /) -> int:
        """
        The message number.
        """
    @property
    def option_flags(self, /) -> int: ...
    @property
    def sequence(self, /) -> int |None: ...

@final
class EtwMessageFormat(BaseRecord):
    """
    A WPP message rendered from the trace message format (TMF) that a loaded
    PDB declares for it.
    """
    __match_args__: Final[tuple[Literal["provider"], Literal["function"], Literal["level"], Literal["flags"]]]
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
    def level(self, /) -> str |None:
        """
        The trace level from the TMF (`TRACE_LEVEL_ERROR`, or a number).
        """
    @property
    def provider(self, /) -> str:
        """
        The provider (component) name from the TMF.
        """
    @property
    def text(self, /) -> str |None:
        """
        The message text, rendered from its TMF and the payload.
        """

@final
class EtwRecord(BaseRecord):
    """
    An event record decoded from a trace buffer. A field is `None` if the
    header kind of the event does not have it.
    """
    __match_args__: Final[tuple[Literal["offset"], Literal["header"], Literal["header_type"], Literal["size"], Literal["timestamp"], Literal["process_id"], Literal["thread_id"], Literal["descriptor"], Literal["event_flags"], Literal["hook_id"], Literal["event_class"], Literal["message"], Literal["extended"], Literal["payload"]]]
    @property
    def activity_id(self, /) -> str |None:
        """
        `EVENT_HEADER.ActivityId`, braced.
        """
    @property
    def descriptor(self, /) -> EtwEventDescriptor |None: ...
    @property
    def event_class(self, /) -> EtwEventClass |None:
        """
        The class of a classic event.
        """
    @property
    def event_flags(self, /) -> int |None:
        """
        `EVENT_HEADER.Flags`.
        """
    @property
    def extended(self, /) -> list[EtwExtendedItem]: ...
    @property
    def group(self, /) -> str |None:
        """
        The `EVENT_TRACE_GROUP_*` name of the hook id, if it is known.
        """
    @property
    def guid(self, /) -> str |None:
        """
        The provider GUID (`EVENT_HEADER`), event class GUID
        (`EVENT_TRACE_HEADER`), or message GUID (`MESSAGE_TRACE_HEADER`),
        braced.
        """
    @property
    def header(self, /) -> Literal["system", "compact", "perfinfo", "classic", "instance", "event", "message"]:
        """
        The trace header at the start of the record (`event` for
        `EVENT_HEADER`, ...).
        """
    @property
    def header_type(self, /) -> int: ...
    @property
    def hook_id(self, /) -> int |None:
        """
        The kernel hook id (group << 8 | type) of system and perfinfo events.
        """
    @property
    def message(self, /) -> EtwMessage |None: ...
    @property
    def offset(self, /) -> int:
        """
        The offset of the record in its buffer.
        """
    @property
    def payload(self, /) -> bytes:
        """
        The user data of the event.
        """
    @property
    def process_id(self, /) -> int |None: ...
    @property
    def size(self, /) -> int:
        """
        The record size, with the header included (unaligned).
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
class EventPolicies(BaseRecord):
    """
    The configured exception policies and module load and unload filters
    (`sx`).
    """
    __match_args__: Final[tuple[Literal["exceptions"], Literal["module_events"]]]
    @property
    def exceptions(self, /) -> list[ExceptionPolicy]:
        """
        In code order.
        """
    @property
    def module_events(self, /) -> list[ModuleEventPolicy]:
        """
        In the order they were set.
        """

@final
class ExceptionParameter(BaseRecord):
    """
    One `ExceptionInformation` entry, with what it means for the code when
    that is known.
    """
    __match_args__: Final[tuple[Literal["value"], Literal["label"], Literal["meaning"]]]
    @property
    def label(self, /) -> str |None:
        """
        What the entry is for the code (`access`, `address`, `ThrowInfo`,
        ...). `None` if the code defines no meaning.
        """
    @property
    def meaning(self, /) -> str |None:
        """
        The value decoded: an access type, a status name, a module.
        """
    @property
    def value(self, /) -> int: ...

@final
class ExceptionPolicy(BaseRecord):
    """
    One exception stop policy (`sx`).
    """
    __match_args__: Final[tuple[Literal["code"], Literal["mode"], Literal["command"]]]
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
    def disposition(self, /) -> Literal["break", "handled", "not_handled"] |None:
        """
        An explicit final action: `break`, or continue as `handled` or
        `not_handled`. None for the default action of the mode.
        """
    @property
    def mode(self, /) -> Literal["break", "second_chance", "notify", "ignore"]:
        """
        `break`, `second_chance`, `notify`, or `ignore`.
        """

@final
class ExceptionRecord(BaseRecord):
    """
    A decoded `EXCEPTION_RECORD64` (`.exr`).
    """
    __match_args__: Final[tuple[Literal["record_address"], Literal["code"], Literal["flags"], Literal["nested"], Literal["exception_address"], Literal["parameters"]]]
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
        record of the current event, which ntoseye builds from the stop or
        the dump without reading it from memory.
        """

@final
class ExceptionStop(BaseRecord):
    """
    A Windows exception that stopped the target.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["first_chance"], Literal["address"]]]
    @property
    def address(self, /) -> int |None:
        """
        The exception record's address, when the transport gives one.
        """
    @property
    def code(self, /) -> int:
        """
        The NTSTATUS code.
        """
    @property
    def first_chance(self, /) -> bool |None:
        """
        Whether this is the first chance; `None` when the transport does not
        say.
        """

@final
class Exceptions:
    """
    The stop policy for each exception (`dbg.exceptions`, `sx*`).
    """
    def __iter__(self, /) -> Iterator[ExceptionPolicy]: ...
    def __len__(self, /) -> int: ...
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
    def set(self, /, code: int |str, *, mode: Literal["break", "second_chance", "notify", "ignore"] |None = None, command: str |None = None, disposition: Literal["break", "handled", "not_handled"] |None = None) -> ExceptionPolicy:
        """
        Set how the debugger handles an exception, by NTSTATUS code or WinDbg
        alias (`av`, `bpe`, ...), and return its policy.
        
        `mode` is `break` (the default), `second_chance`, `notify` or `ignore`.
        `command` runs at the stop, which needs an explicit `disposition`: break,
        or continue the exception as handled or not handled. For a module load
        or unload filter, use `set_module_event`.
        """
    def set_module_event(self, /, event: Literal["ld", "ud"], module: str |None = None, *, mode: Literal["break", "second_chance", "notify", "ignore"] |None = None, command: str |None = None) -> ModuleEventPolicy:
        """
        Set a filter for a kernel module load (`ld`) or unload (`ud`), and return
        it.
        
        `module` limits it to one image (a case-insensitive name; the extension
        is optional, and `*`/`?` globs match); without it, the filter applies to
        every image. `mode` is `break` (the default; a load stops after ntoseye
        lists the module and arms its deferred breakpoints, an unload while the
        image is still listed), `notify` (a `ModLoad:` or `Unload module` notice,
        then the target continues), or `second_chance` or `ignore` (it
        continues). `command` runs at the stop, so only with `break`. A named
        filter has precedence over a bare one.
        """

@final
class ExecutiveResource(BaseRecord):
    """
    An `_ERESOURCE` (`!locks <address>`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["active_count"], Literal["flags"], Literal["contention_count"], Literal["shared_waiters"], Literal["exclusive_waiters"], Literal["owners"]]]
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
    What a VM-exit breakpoint stops on: a basic exit reason (Intel SDM
    Vol. 3D, Appendix C), optionally only from one partition or one of its
    VPs.
    """
    __match_args__: Final[tuple[Literal["reason"], Literal["partition"], Literal["vp"]]]
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
        The caller's VP index in `partition`. None for any VP. Set only with
        `partition`: a VP index names a VP of one partition.
        """

@final
class ExportDirectory(BaseRecord):
    """
    `IMAGE_EXPORT_DIRECTORY` and the DLL name it points at.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["characteristics"], Literal["time_date_stamp"], Literal["ordinal_base"], Literal["number_of_functions"], Literal["number_of_names"], Literal["address_of_functions"], Literal["address_of_names"], Literal["address_of_name_ordinals"]]]
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
class FailureSignature(BaseRecord):
    """
    A deterministic identity for a failure that does not depend on
    addresses, so you can use it to compare failures.
    """
    __match_args__: Final[tuple[Literal["code_kind"], Literal["code"], Literal["module"], Literal["symbol"], Literal["source"], Literal["components"], Literal["bucket"]]]
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
    def code_kind(self, /) -> Literal["bugcheck", "exception"]: ...
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
    def source(self, /) -> Literal["bugcheck_fault", "exception_address", "current_instruction", "top_frame", "power_failure_driver", "first_non_system_frame", "code_only"]: ...
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at the failing location.
        """

@final
class FieldInfo(BaseRecord):
    """
    The PDB layout of a field: its byte offset, byte size, and type.
    """
    __match_args__: Final[tuple[Literal["offset"], Literal["size"]]]
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
class FileCacheDetail(BaseRecord):
    """
    The mapped views of the cache manager, from its VACB arrays
    (`!filecache`).
    """
    __match_args__: Final[tuple[Literal["vacb_arrays"], Literal["free_vacbs"], Literal["active_vacbs"], Literal["mapped_bytes"], Literal["valid_bytes"], Literal["files"], Literal["file_count"], Literal["interrupted"]]]
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
class FileHeader(BaseRecord):
    """
    `IMAGE_FILE_HEADER`.
    """
    __match_args__: Final[tuple[Literal["machine"], Literal["number_of_sections"], Literal["time_date_stamp"], Literal["pointer_to_symbol_table"], Literal["number_of_symbols"], Literal["size_of_optional_header"], Literal["characteristics"]]]
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
        `X64`, `X86`, `ARM64`, ...
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
class FileObject(BaseRecord):
    """
    A `_FILE_OBJECT` (`!fileobj`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["file_type"], Literal["size"], Literal["device_object"], Literal["device_type"], Literal["device_name"], Literal["file_name"], Literal["related_file_object"], Literal["flags"], Literal["current_byte_offset"], Literal["fs_context"], Literal["fs_context2"], Literal["section_object_pointer"], Literal["private_cache_map"], Literal["final_status"], Literal["lock_operation"], Literal["delete_pending"], Literal["read_access"], Literal["write_access"], Literal["delete_access"], Literal["shared_read"], Literal["shared_write"], Literal["shared_delete"]]]
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
    __match_args__: Final[tuple[Literal["pattern"], Literal["level"], Literal["scanned_threads"], Literal["interrupted"], Literal["threads"], Literal["unwalked"]]]
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
    __match_args__: Final[tuple[Literal["thread"], Literal["matches"]]]
    @property
    def active(self, /) -> int |None:
        """
        The processor that runs the thread, if the listing resolves it.
        `None` if no processor runs it, and while the target runs.
        """
    @property
    def frames(self, /) -> list[StackFrame]:
        """
        The whole walked stack, innermost first.
        """
    @property
    def match_count(self, /) -> int:
        """
        The number of frames that matched.
        """
    @property
    def matches(self, /) -> list[int]:
        """
        The indexes in the walked stack (`frames`) of the frames that
        matched, innermost first.
        """
    @property
    def matching_frames(self, /) -> list[StackFrame]:
        """
        The frames that matched, in the order of `matches`.
        """
    @property
    def thread(self, /) -> ThreadInfo: ...
    @property
    def truncated(self, /) -> int:
        """
        The number of frames past the walk limit, which were not searched.
        """

@final
class FltFilterDetail(BaseRecord):
    """
    A registered minifilter (`_FLT_FILTER`) and its instances.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["altitude"], Literal["driver_object"], Literal["instances"], Literal["instances_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def altitude(self, /) -> str: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def instances(self, /) -> list[FltInstanceDetail]: ...
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
    A filter manager frame (`_FLTP_FRAME`) and its registered minifilters.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["frame_id"], Literal["filters"], Literal["stopped"]]]
    @property
    def address(self, /) -> int:
        """
        The `_FLTP_FRAME`.
        """
    @property
    def filters(self, /) -> list[FltFilterDetail]: ...
    @property
    def frame_id(self, /) -> int: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the frame's list stopped before the list head.
        `None` if the walk completed.
        """

@final
class FltFilters(BaseRecord):
    """
    The registered minifilters of each filter manager frame
    (`!fltkd.filters`).
    """
    __match_args__: Final[tuple[Literal["frames"], Literal["stopped"]]]
    @property
    def frames(self, /) -> list[FltFilterFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of `FltGlobals.FrameList` stopped before the list
        head. `None` if the walk completed.
        """

@final
class FltInstanceDetail(BaseRecord):
    """
    A minifilter attached to a volume (`_FLT_INSTANCE`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["altitude"], Literal["filter"], Literal["filter_name"], Literal["volume"], Literal["volume_name"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["frame_id"], Literal["instances"], Literal["stopped"]]]
    @property
    def address(self, /) -> int:
        """
        The `_FLTP_FRAME`.
        """
    @property
    def frame_id(self, /) -> int: ...
    @property
    def instances(self, /) -> list[FltInstanceDetail]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the frame's lists stopped before the list head.
        `None` if the walk completed.
        """

@final
class FltInstances(BaseRecord):
    """
    The minifilter instances of each filter manager frame
    (`!fltkd.instances`).
    """
    __match_args__: Final[tuple[Literal["frames"], Literal["stopped"]]]
    @property
    def frames(self, /) -> list[FltInstanceFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of `FltGlobals.FrameList` stopped before the list
        head. `None` if the walk completed.
        """

@final
class FltVolumeDetail(BaseRecord):
    """
    A volume that the filter manager attached to (`_FLT_VOLUME`), and the
    instances on it.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["device_name"], Literal["file_system"], Literal["instances"], Literal["instances_stopped"]]]
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
    def instances(self, /) -> list[FltInstanceDetail]: ...
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
    __match_args__: Final[tuple[Literal["address"], Literal["frame_id"], Literal["volumes"], Literal["stopped"]]]
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
        Why the walk of the frame's list stopped before the list head.
        `None` if the walk completed.
        """
    @property
    def volumes(self, /) -> list[FltVolumeDetail]: ...

@final
class FltVolumes(BaseRecord):
    """
    The volumes of each filter manager frame (`!fltkd.volumes`).
    """
    __match_args__: Final[tuple[Literal["frames"], Literal["stopped"]]]
    @property
    def frames(self, /) -> list[FltVolumeFrame]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of `FltGlobals.FrameList` stopped before the list
        head. `None` if the walk completed.
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
class FunctionDisassembly(BaseRecord):
    """
    A disassembled function (`uf`).
    """
    __match_args__: Final[tuple[Literal["symbol"], Literal["length"], Literal["rows"]]]
    @property
    def length(self, /) -> int:
        """
        The length of the function in bytes.
        """
    @property
    def rows(self, /) -> list[DisasmRow]:
        """
        Its instructions, from its start.
        """
    @property
    def symbol(self, /) -> str:
        """
        The symbol at the start of the function.
        """

@final
class FunctionEntry(BaseRecord):
    """
    The function-table entry that covers an address, and the entry of each
    chained parent (`.fnent`).
    """
    __match_args__: Final[tuple[Literal["module"], Literal["image_base"], Literal["entries"], Literal["incomplete"]]]
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
    __match_args__: Final[tuple[Literal["processor"], Literal["base"], Literal["limit"], Literal["entry_count"], Literal["truncated"], Literal["entries"]]]
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
    __match_args__: Final[tuple[Literal["index"], Literal["raw"], Literal["high_raw"], Literal["base"], Literal["limit"], Literal["type_code"], Literal["descriptor_kind"], Literal["dpl"], Literal["present"], Literal["long_mode"], Literal["default_size"], Literal["granularity"]]]
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
    One GFlags flag: its bit, GFlags abbreviation (`hpa`, `ust`, ...), and
    description.
    """
    __match_args__: Final[tuple[Literal["bit"], Literal["abbreviation"], Literal["description"]]]
    @property
    def abbreviation(self, /) -> str:
        """
        The GFlags abbreviation; empty for 0x200, which has none.
        """
    @property
    def bit(self, /) -> int:
        """
        The bit mask of the flag.
        """
    @property
    def description(self, /) -> str: ...

@final
class GlobalFlagUpdate(BaseRecord):
    """
    A change `!gflag` made to `nt!NtGlobalFlag`: its value before and after.
    """
    __match_args__: Final[tuple[Literal["old"], Literal["new"]]]
    @property
    def new(self, /) -> int: ...
    @property
    def old(self, /) -> int: ...

@final
class GlobalFlags(BaseRecord):
    """
    `nt!NtGlobalFlag` and the `_PEB.NtGlobalFlag` of the current process
    (`!gflag`), and the change the command made to `nt!NtGlobalFlag`.
    """
    __match_args__: Final[tuple[Literal["kernel_address"], Literal["kernel"], Literal["process"], Literal["process_flags"], Literal["change"]]]
    @property
    def change(self, /) -> GlobalFlagUpdate |None:
        """
        The change made to `nt!NtGlobalFlag` before the flags were read.
        `None` if none was asked for.
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
    def kernel_flags(self, /) -> list[GlobalFlag]:
        """
        The flags set in `nt!NtGlobalFlag`.
        """
    @property
    def process(self, /) -> ProcessInfo |None:
        """
        The current process. `None` if no process is selected.
        """
    @property
    def process_flag_names(self, /) -> Diagnostic[list[GlobalFlag]]:
        """
        The flags set in the PEB of the current process.
        """
    @property
    def process_flags(self, /) -> Diagnostic[int]:
        """
        The flags of the current process, read from its PEB; unavailable for
        a process without a PEB (System) or with its PEB paged out.
        """

@final
class HalController(BaseRecord):
    """
    An interrupt controller the HAL registered
    (`_REGISTERED_INTERRUPT_CONTROLLER`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["kind"], Literal["unit_id"], Literal["resource_id"], Literal["min_line"], Literal["max_line"], Literal["problem"], Literal["ranges"], Literal["ranges_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def kind(self, /) -> str:
        """
        `_KNOWN_CONTROLLER_TYPE` without its prefix (`Apic`, `Pic`).
        """
    @property
    def max_line(self, /) -> int: ...
    @property
    def min_line(self, /) -> int: ...
    @property
    def problem(self, /) -> str |None:
        """
        `_INTERRUPT_PROBLEM` without its prefix; `None` for no problem.
        """
    @property
    def ranges(self, /) -> list[HalLineRange]: ...
    @property
    def ranges_stopped(self, /) -> str |None: ...
    @property
    def resource_id(self, /) -> str:
        """
        The ACPI ID the HAL gave the controller's device.
        """
    @property
    def unit_id(self, /) -> int: ...

@final
class HalControllers(BaseRecord):
    """
    The interrupt controllers on `nt!HalpRegisteredInterruptControllers`
    (`!ioapic`), in list order.
    """
    __match_args__: Final[tuple[Literal["controllers"], Literal["stopped"]]]
    @property
    def controllers(self, /) -> list[HalController |HalUnreadable]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the list head.
        """

@final
class HalLine(BaseRecord):
    """
    A line of an interrupt controller as the HAL set it
    (`_INTERRUPT_LINE_STATE`).
    """
    __match_args__: Final[tuple[Literal["line"], Literal["gsi"], Literal["vector"], Literal["irql"], Literal["level"], Literal["polarity"], Literal["target"], Literal["flags"]]]
    @property
    def flags(self, /) -> int: ...
    @property
    def gsi(self, /) -> int |None:
        """
        The global system interrupt, for a pin.
        """
    @property
    def irql(self, /) -> int:
        """
        The IRQL the line's interrupt runs at (`Priority`).
        """
    @property
    def level(self, /) -> bool: ...
    @property
    def line(self, /) -> int: ...
    @property
    def polarity(self, /) -> str: ...
    @property
    def target(self, /) -> str:
        """
        `_INTERRUPT_TARGET_TYPE` without its prefix, and the target ID the
        type uses.
        """
    @property
    def vector(self, /) -> int: ...

@final
class HalLineRange(BaseRecord):
    """
    A range of a controller's lines (`_INTERRUPT_LINES`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["kind"], Literal["min_line"], Literal["max_line"], Literal["gsi_base"], Literal["lines"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def gsi_base(self, /) -> int |None: ...
    @property
    def kind(self, /) -> str:
        """
        `_INTERRUPT_LINE_TYPE` without its prefix (`StandardPin`).
        """
    @property
    def lines(self, /) -> list[HalLine]:
        """
        The lines the HAL set up; the others are unused.
        """
    @property
    def max_line(self, /) -> int: ...
    @property
    def min_line(self, /) -> int: ...

@final
class HalUnreadable(BaseRecord):
    """
    A controller that does not read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def error(self, /) -> str: ...

@final
class HandleEntry(BaseRecord):
    """
    A handle-table entry (`!handle <handle>`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["entry"], Literal["object"], Literal["type_name"], Literal["name"], Literal["granted_access"], Literal["attributes"]]]
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
    __match_args__: Final[tuple[Literal["process"], Literal["table"], Literal["table_level"], Literal["advertised_handles"], Literal["scanned_handles"], Literal["skipped_entries"], Literal["truncated"], Literal["entries"]]]
    @property
    def advertised_handles(self, /) -> int:
        """
        The handle count that the table reports.
        """
    @property
    def entries(self, /) -> list[HandleEntry]: ...
    @property
    def process(self, /) -> ProcessInfo:
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
    __match_args__: Final[tuple[Literal["handle"], Literal["kind"], Literal["process_id"], Literal["thread_id"], Literal["stack"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["symbol"]]]
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
    __match_args__: Final[tuple[Literal["process"], Literal["object_table"], Literal["debug_info"], Literal["table_size"], Literal["recorded"], Literal["parsed"], Literal["unreadable"], Literal["traces"]]]
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
    def process(self, /) -> ProcessInfo:
        """
        The traced process.
        """
    @property
    def recorded(self, /) -> int:
        """
        The total number of recorded traces (`CurrentStackIndex`), of which
        the ring keeps the last `table_size`.
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
class HangProcessor(BaseRecord):
    """
    A processor in `!analyze -hang`, and the thread running on it.
    """
    __match_args__: Final[tuple[Literal["processor"]]]
    @property
    def current(self, /) -> Diagnostic[HangThread]:
        """
        The thread running on the processor, or why it is unknown.
        """
    @property
    def processor(self, /) -> int: ...

@final
class HangReport(BaseRecord):
    """
    What `!analyze -hang` found: the thread on each processor with its
    stack, and the waiting threads.
    """
    __match_args__: Final[tuple[Literal["processors"]]]
    @property
    def processors(self, /) -> list[HangProcessor]:
        """
        One entry per processor, in order; empty when the count is unknown.
        """
    @property
    def waiting(self, /) -> Diagnostic[list[ThreadInfo]]:
        """
        The waiting threads, most pending IRPs first (at most 32), or why
        there are none.
        """

@final
class HangThread(BaseRecord):
    """
    A thread running on a processor, with its stack.
    """
    __match_args__: Final[tuple[Literal["thread"]]]
    @property
    def stack(self, /) -> Diagnostic[list[StackFrame]]:
        """
        The thread's innermost frames (at most 8), or why it did not unwind.
        """
    @property
    def thread(self, /) -> ThreadInfo: ...

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
    @property
    def info(self, /) -> HeapInfo:
        """
        The `HeapInfo` record of this handle: its properties as one value.
        """
    def inspect(self, /, *, list_entries: bool = False) -> HeapDetail:
        """
        Decode this heap (`!heap -h`), with its entries if `list_entries` is
        true.
        """
    @property
    def kind(self, /) -> Literal["nt", "segment", "unknown"]: ...
    @property
    def signature(self, /) -> int |None:
        """
        The `_HEAP.Signature` of an unknown heap (0 if ntoseye could not
        classify it). None for NT and segment heaps.
        """
    @property
    def stats(self, /) -> Diagnostic[HeapStats]:
        """
        Heap-wide sizes and allocator counts.  An unavailable value contains
        the layout, memory, or symbol error for this heap only.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class HeapBlock(BaseRecord):
    """
    One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
    chunk, or a segment-heap LFH block.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["size"], Literal["previous_size"], Literal["flags"], Literal["state"], Literal["kind"], Literal["unused_bytes"], Literal["checksum_ok"], Literal["user"], Literal["user_size"], Literal["index"]]]
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
    def kind(self, /) -> Literal["nt_lfh_block", "vs_chunk", "lfh_block"]: ...
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
    def state(self, /) -> Literal["busy", "free"]:
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
    __match_args__: Final[tuple[Literal["address"], Literal["found"], Literal["truncated"], Literal["heap"], Literal["block"], Literal["errors"]]]
    @property
    def address(self, /) -> int:
        """
        The search address.
        """
    @property
    def block(self, /) -> BlockMatch |None:
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
        Whether the PEB listed more heaps than the search bound, in which
        case the search may have missed the block.
        """

@final
class HeapDetail(BaseRecord):
    """
    One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
    """
    __match_args__: Final[tuple[Literal["index"], Literal["address"], Literal["list_entries"], Literal["nt"], Literal["segment"], Literal["error"]]]
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
    def kind(self, /) -> Literal["nt", "segment", "unknown"]: ...
    @property
    def list_entries(self, /) -> bool:
        """
        Whether ntoseye walked and listed the entries, chunks, and blocks.
        """
    @property
    def nt(self, /) -> NtHeapDetail |None:
        """
        The NT (`_HEAP`) decoding. None for other heap kinds or if the
        decoding failed.
        """
    @property
    def segment(self, /) -> SegmentHeapDetail |None:
        """
        The segment-heap decoding. None for other heap kinds or if the
        decoding failed.
        """
    @property
    def signature(self, /) -> int |None:
        """
        The `_HEAP.Signature` of an unknown heap (0 if ntoseye could not
        classify it). None for NT and segment heaps.
        """

@final
class HeapIdentity(BaseRecord):
    """
    A heap, identified by its PEB-list position, address, and kind.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["address"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        Position in the PEB heap list.
        """
    @property
    def kind(self, /) -> Literal["nt", "segment", "unknown"]: ...
    @property
    def signature(self, /) -> int |None:
        """
        The `_HEAP.Signature` of an unknown heap (0 if ntoseye could not
        classify it). None for NT and segment heaps.
        """

@final
class HeapInfo(BaseRecord):
    """
    One heap of a process, from its PEB heap list (`!heap -s`).
    """
    __match_args__: Final[tuple[Literal["index"], Literal["address"], Literal["stats"]]]
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
    @property
    def kind(self, /) -> Literal["nt", "segment", "unknown"]: ...
    @property
    def signature(self, /) -> int |None:
        """
        The `_HEAP.Signature` of an unknown heap (0 if ntoseye could not
        classify it). None for NT and segment heaps.
        """
    @property
    def stats(self, /) -> Diagnostic[HeapStats]:
        """
        Heap-wide sizes and allocator counts.  An unavailable value contains
        the layout, memory, or symbol error for this heap only.
        """

@final
class HeapStats(BaseRecord):
    """
    A heap's sizes, in bytes, and allocator counts (`!heap -s`).
    """
    __match_args__: Final[tuple[Literal["flags"], Literal["reserved"], Literal["committed"], Literal["free"], Literal["segments"], Literal["virtual_blocks"], Literal["front_end"], Literal["vs_subsegments"], Literal["lfh_subsegments"], Literal["page_allocations"], Literal["large_allocations"]]]
    @property
    def committed(self, /) -> int: ...
    @property
    def flags(self, /) -> int:
        """
        The heap's flags.
        """
    @property
    def free(self, /) -> int: ...
    @property
    def front_end(self, /) -> int |None:
        """
        The front-end allocator (the LFH), if the heap has one.
        """
    @property
    def large_allocations(self, /) -> int: ...
    @property
    def lfh_subsegments(self, /) -> int: ...
    @property
    def page_allocations(self, /) -> int: ...
    @property
    def reserved(self, /) -> int: ...
    @property
    def segments(self, /) -> int: ...
    @property
    def virtual_blocks(self, /) -> int: ...
    @property
    def vs_subsegments(self, /) -> int: ...

@final
class HeapWalkStop(BaseRecord):
    """
    The address where a heap walk stopped, and the reason.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["reason"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def reason(self, /) -> str: ...

@final
class Heaps:
    """
    The PEB heap list of a process.
    """
    def __contains__(self, item: Any, /) -> bool:
        """
        Whether `item` is one of the items (`==`).
        """
    def __getitem__(self, index: int, /) -> Heap: ...
    def __iter__(self, /) -> Iterator[Heap]: ...
    def __len__(self, /) -> int: ...
    def find_block(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> HeapBlockSearch:
        """
        Find the heap block that contains `addr` (`!heap -x`).
        """
    def get(self, /, index: int) -> Heap |None:
        """
        The item at position `index` (negative from the end), or
        `None` if there is none.
        """

@final
class Hive(BaseRecord):
    """
    A loaded hive (`_CMHIVE`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["master"], Literal["mount"], Literal["file"], Literal["base_block"], Literal["base_block_name"], Literal["root_cell"], Literal["version"], Literal["flags"], Literal["flat"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def base_block(self, /) -> int:
        """
        `_HHIVE.BaseBlock`, and the end of the file's name it records.
        """
    @property
    def base_block_name(self, /) -> str |None: ...
    @property
    def file(self, /) -> str |None:
        """
        The file it was loaded from (`FileUserName`, else `FileFullPath`).
        """
    @property
    def flags(self, /) -> int:
        """
        `_HHIVE.HiveFlags`.
        """
    @property
    def flat(self, /) -> bool:
        """
        The hive is one block of memory (a hive the boot loader loaded, read
        before its cell map exists).
        """
    @property
    def master(self, /) -> bool:
        """
        The master hive (`nt!CmpMasterHive`), whose root is `\\REGISTRY`.
        """
    @property
    def mount(self, /) -> str |None:
        """
        Where it is mounted (`HiveRootPath`), `\\REGISTRY` for the master
        hive.
        """
    @property
    def root_cell(self, /) -> Diagnostic[int]:
        """
        `_HBASE_BLOCK.RootCell`, the cell of its root key.
        """
    @property
    def stable_length(self, /) -> int:
        """
        The bytes of its stable storage.
        """
    @property
    def stable_map(self, /) -> int:
        """
        The stable storage's cell map (`_HMAP_DIRECTORY`).
        """
    @property
    def version(self, /) -> int:
        """
        `_HHIVE.Version`, the format's minor version.
        """
    @property
    def volatile_length(self, /) -> int:
        """
        The bytes of its volatile storage.
        """
    @property
    def volatile_map(self, /) -> int:
        """
        The volatile storage's cell map (`_HMAP_DIRECTORY`).
        """

@final
class HiveList(BaseRecord):
    """
    The loaded hives (`!reg hivelist`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def hives(self, /) -> list[Hive]:
        """
        The hives that read.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of `nt!CmpHiveListHead` stopped short.
        """
    @property
    def unreadable(self, /) -> list[RegistryUnreadable]:
        """
        The hives that do not read.
        """

@final
class HvPartition(BaseRecord):
    """
    A partition of the Windows hypervisor, as it was when listed.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["id"], Literal["parent_id"], Literal["privileges"], Literal["virtual_processors"]]]
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
    @property
    def virtual_processors(self, /) -> list[HvVirtualProcessor]:
        """
        The partition's virtual processors, by index.
        """

@final
class HvProcessor(BaseRecord):
    """
    A logical processor whose current VP a VP is: the one that runs it, or
    ran it last.
    """
    __match_args__: Final[tuple[Literal["block"], Literal["number"]]]
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
class HvVirtualProcessor(BaseRecord):
    """
    A virtual processor of a Windows hypervisor partition.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["address"], Literal["vtl"], Literal["vtls"], Literal["processors"]]]
    @property
    def address(self, /) -> int:
        """
        The address of the hypervisor's VP object.
        """
    @property
    def index(self, /) -> int:
        """
        The VP index in its partition.
        """
    @property
    def processors(self, /) -> list[HvProcessor]:
        """
        The processors whose current VP this is (the one that runs it, or
        ran it last).
        """
    @property
    def vtl(self, /) -> int:
        """
        The VTL that the VP runs, or last ran, in.
        """
    @property
    def vtls(self, /) -> list[HvVtl]:
        """
        Each VTL enabled on the VP, lowest first (VTL0 and VTL1 under VBS).
        """

@final
class HvVtl(BaseRecord):
    """
    One VTL of a virtual processor: the hypervisor's context for it and, when
    found, its eVMCS and the guest state saved there.
    """
    __match_args__: Final[tuple[Literal["level"], Literal["context"], Literal["vmcs"]]]
    @property
    def context(self, /) -> int:
        """
        The address of the hypervisor's context object for this VTL.
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
    @property
    def rip(self, /) -> int |None:
        """
        The guest RIP where the VTL left off, or `None` without the eVMCS.
        """
    @property
    def vmcs(self, /) -> int |None:
        """
        The physical address of the VTL's VMCS (an eVMCS under KVM), or
        `None` when ntoseye did not find where the context keeps it (no
        `hv-evmcs`).
        """

@final
class Hypercall(BaseRecord):
    """
    One call code of the hypervisor's hypercall table, as the hypervisor
    dispatches it: its handler, its kind, and the sizes of its fixed input
    and output and of each rep element.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["implemented"], Literal["handler"], Literal["input_size"], Literal["input_element_size"], Literal["output_size"], Literal["output_element_size"]]]
    @property
    def code(self, /) -> int: ...
    @property
    def handler(self, /) -> int: ...
    @property
    def implemented(self, /) -> bool:
        """
        Whether the call has its own handler, not the reserved code 0's,
        which unimplemented codes share.
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
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def hypercall(self, /) -> DecodedHypercall |None:
        """
        The call with its input decoded, as `!hvcall` shows it, or `None`
        when the caller's registers are not known.
        """
    @property
    def info(self, /) -> HypercallCallerInfo:
        """
        The `HypercallCallerInfo` record of this handle: its properties as one value.
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
        The record (`info`) as a plain `dict`.
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
class HypercallCallerInfo(BaseRecord):
    """
    The virtual processor whose hypercall a processor halted in the Windows
    hypervisor handles (`cpu.hypercall_caller()`), found as `!hvcall` and a
    hypercall breakpoint's filter find it: the call as the caller made it,
    and the caller's memory, which a hypercall breakpoint's condition reads.
    """
    __match_args__: Final[tuple[Literal["partition_id"], Literal["root"], Literal["vp_index"], Literal["vtl"]]]
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
    @property
    def root(self, /) -> bool:
        """
        Whether the caller is a VP of the root partition (Windows itself)
        rather than of a guest partition.
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
    __match_args__: Final[tuple[Literal["index"], Literal["fields"]]]
    @property
    def fields(self, /) -> list[HypercallField]: ...
    @property
    def index(self, /) -> int: ...

@final
class HypercallField(BaseRecord):
    """
    One field of a hypercall's input, as the Hyper-V TLFS lays it out.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["offset"], Literal["size"], Literal["value"], Literal["meaning"]]]
    @property
    def meaning(self, /) -> str |None:
        """
        What the value means, where it has a name or stands for a set:
        `HV_PARTITION_ID_SELF`, `VPs 0-3`, a register's TLFS name.
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
        The offset in the input, from its first byte, rep list included.
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
    A hypercall breakpoint's filter (`!hvbp`): the call code a hit's caller
    made, and the partition, and VP index in it, the caller must be.
    
    The breakpoint is on the call's handler, which the hypervisor runs for
    every caller and, for a handler several codes share, for each of them.
    Like the thread filter, the caller is known only once the hit arrives:
    the VP whose exit the processor handles, and the code in its RCX.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["partition"], Literal["vp"]]]
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
        The caller's VP index in `partition`. None for any VP. Set only with
        `partition`: a VP index names a VP of one partition.
        """

@final
class HypervisorPartition:
    """
    A partition of the Windows hypervisor, as it was when listed.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
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
    def info(self, /) -> HvPartition:
        """
        The `HvPartition` record of this handle: its properties as one value.
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
        The record (`info`) as a plain `dict`.
        """
    @property
    def virtual_processors(self, /) -> list[VirtualProcessor]:
        """
        The partition's virtual processors, by index.
        """

@final
class HypervisorVtl:
    """
    One VTL of a virtual processor: the hypervisor's context for it and, when
    found, its eVMCS and the guest state saved there.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def context(self, /) -> int:
        """
        The address of the hypervisor's context object for this VTL.
        """
    def disassemble(self, /, address: int, count: int, physical: bool = False) -> list[DisasmRow]:
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
    def info(self, /) -> HvVtl:
        """
        The `HvVtl` record of this handle: its properties as one value.
        """
    def io_intercepts(self, /) -> IoIntercepts:
        """
        Which I/O instructions of this VTL exit, as `!hvvmcs -io` shows them:
        the port ranges its I/O bitmaps intercept, or, when its controls use
        none, every port (`every`) or none. Raises `NtoseyeError` without the
        VTL's eVMCS, or when a bitmap is unreadable.
        """
    @property
    def level(self, /) -> int:
        """
        The VTL (0 for NT, 1 for the secure kernel).
        """
    def msr_intercepts(self, /) -> MsrIntercepts:
        """
        Which RDMSRs and WRMSRs of this VTL exit, as `!hvvmcs -msr` shows
        them: through its MSR bitmap when its controls use one, else every one
        (`every`). Each intercepted range names the architectural MSRs in it,
        and `read_without_exit` and `write_without_exit` list those the VTL
        accesses without an exit. MSRs outside the bitmap's 0x0-0x1fff and
        0xc0000000-0xc0001fff always exit. Raises `NtoseyeError` without the
        VTL's eVMCS, or when the bitmap is unreadable.
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
        The record (`info`) as a plain `dict`.
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
        The physical address of the VTL's VMCS (an eVMCS under KVM), or
        `None` when ntoseye did not find where the context keeps it (no
        `hv-evmcs`).
        """
    def vmcs_fields(self, /) -> dict[str, int]:
        """
        Every field of this VTL's eVMCS, read now, named as the TLFS names it
        (`guest_rip`, `msr_bitmap`, ...), as `!hvvmcs` shows them:
        `fields["guest_rip"]`. Raises `NtoseyeError` without the VTL's eVMCS.
        """

@final
class IdleDetection(BaseRecord):
    """
    The idle detection a driver registered with
    `PoRegisterDeviceForIdleDetection` (`_DEVICE_OBJECT_POWER_EXTENSION`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["idle_count"], Literal["busy_count"], Literal["busy_reference"], Literal["total_busy_count"], Literal["conservation_idle_time"], Literal["performance_idle_time"], Literal["idle_type"], Literal["idle_state"], Literal["current_state"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def busy_count(self, /) -> int: ...
    @property
    def busy_reference(self, /) -> int: ...
    @property
    def conservation_idle_time(self, /) -> int:
        """
        Seconds idle before the power manager powers the device down, on
        battery and on AC power.
        """
    @property
    def current_state(self, /) -> PowerEnum: ...
    @property
    def idle_count(self, /) -> int: ...
    @property
    def idle_state(self, /) -> PowerEnum:
        """
        The device state the power manager requests when the device idles.
        """
    @property
    def idle_type(self, /) -> PowerEnum: ...
    @property
    def performance_idle_time(self, /) -> int: ...
    @property
    def total_busy_count(self, /) -> int: ...

@final
class Idt(BaseRecord):
    """
    The IDT of a processor (`!idt`), with one vector or the bounded full
    table.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["base"], Literal["limit"], Literal["vector"], Literal["truncated"], Literal["entries"]]]
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
    __match_args__: Final[tuple[Literal["vector"], Literal["address"], Literal["handler"], Literal["symbol"], Literal["selector"], Literal["ist"], Literal["gate_type"], Literal["gate_name"], Literal["dpl"], Literal["present"], Literal["non_nt_hook"], Literal["ki_isr_thunk"]]]
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

class IfrEnd(BaseRecord):
    """
    Why an IFR walk ended: `empty` (no record was ever written),
    `first_record` (the oldest record reached is the first the log held),
    `overwritten` (the records before the oldest one reached were
    overwritten), or `corrupt` (a record failed validation, and the walk
    stopped there).
    """
    @property
    def kind(self, /) -> Literal["empty", "first_record", "overwritten", "corrupt"]:
        """
        The variant: `empty`, `first_record`, `overwritten`, `corrupt`.
        """
    @final
    class Corrupt(IfrEnd):
        __match_args__: Final[tuple[Literal["corruption"]]]
        @property
        def corruption(self, /) -> str:
            """
            The item that failed validation.
            """
        @property
        def kind(self, /) -> Literal["corrupt"]:
            """
            `corrupt`.
            """
    @final
    class Empty(IfrEnd):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["empty"]:
            """
            `empty`.
            """
    @final
    class FirstRecord(IfrEnd):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["first_record"]:
            """
            `first_record`.
            """
    @final
    class Overwritten(IfrEnd):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["overwritten"]:
            """
            `overwritten`.
            """

@final
class IfrRecord(BaseRecord):
    """
    An In-Flight Recorder record (`_WDF_IFR_RECORD`).
    """
    __match_args__: Final[tuple[Literal["offset"], Literal["length"], Literal["sequence"], Literal["prev_offset"], Literal["message_number"], Literal["timestamp"], Literal["args"]]]
    @property
    def args(self, /) -> bytes:
        """
        The WPP argument bytes after the header, padded to 4 bytes.
        """
    @property
    def length(self, /) -> int:
        """
        `Length`: header and arguments.
        """
    @property
    def message_guid(self, /) -> str:
        """
        `MessageGuid`, braced.
        """
    @property
    def message_number(self, /) -> int: ...
    @property
    def offset(self, /) -> int:
        """
        Its offset in the log area.
        """
    @property
    def prev_offset(self, /) -> int:
        """
        `PrevOffset`: the record before it.
        """
    @property
    def sequence(self, /) -> int: ...
    @property
    def timestamp(self, /) -> int |None:
        """
        The FILETIME (UTC). `None` for an 'LR' record, which has no
        timestamp.
        """
    @property
    def timestamp_utc(self, /) -> str |None:
        """
        `timestamp` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        """

@final
class ImageByteDiff(BaseRecord):
    """
    One byte that differs from the cached image.
    """
    __match_args__: Final[tuple[Literal["rva"], Literal["expected"], Literal["actual"], Literal["kind"]]]
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
    def kind(self, /) -> Literal["import_optimization", "retpoline", "ki_patch_self", "region_rebase"] |None:
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
    __match_args__: Final[tuple[Literal["module"], Literal["short_name"], Literal["base_address"], Literal["sections"], Literal["genuine_mismatched_bytes"], Literal["total_mismatched_bytes"], Literal["self_patches"], Literal["mismatch_ranges"], Literal["mismatch_range_overflow"], Literal["all_mismatch_ranges"], Literal["all_mismatch_range_overflow"], Literal["self_patch_ranges"], Literal["self_patch_range_overflow"], Literal["byte_diffs"], Literal["byte_diffs_truncated"]]]
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
class ImageExports(BaseRecord):
    """
    A mapped image's export directory and the exports it lists (`!dh -e`).
    """
    __match_args__: Final[tuple[Literal["directory"], Literal["entries"]]]
    @property
    def directory(self, /) -> ExportDirectory |None:
        """
        `None` if the image has no exports.
        """
    @property
    def entries(self, /) -> list[ModuleExportInfo]: ...

@final
class ImageHeaders(BaseRecord):
    """
    The headers of a mapped image (`!dh`). Each directory is read on its own:
    a discarded or paged-out one (a driver's `INIT`-resident import table) is
    unavailable beside the headers that did read.
    """
    __match_args__: Final[tuple[Literal["base"], Literal["module"], Literal["file_header"], Literal["optional_header"], Literal["data_directories"], Literal["sections"], Literal["debug_directory"], Literal["exports"], Literal["imports"]]]
    @property
    def base(self, /) -> int: ...
    @property
    def data_directories(self, /) -> list[DataDirectory]: ...
    @property
    def debug_directory(self, /) -> Diagnostic[list[DebugRecord]]:
        """
        The debug directory, with each CodeView record decoded.
        """
    @property
    def entry_point(self, /) -> int |None:
        """
        The mapped entry point. `None` if the image has no entry point.
        """
    @property
    def exports(self, /) -> Diagnostic[ImageExports] |None:
        """
        The export directory. `None` if you did not ask for it.
        """
    @property
    def file_header(self, /) -> FileHeader: ...
    @property
    def format(self, /) -> str:
        """
        `PE32` or `PE32+`.
        """
    @property
    def imports(self, /) -> Diagnostic[list[ImportDescriptor]] |None:
        """
        The import descriptors. `None` if you did not ask for them.
        """
    @property
    def module(self, /) -> str |None:
        """
        The loaded module at `base`, if there is one.
        """
    @property
    def optional_header(self, /) -> OptionalHeader: ...
    @property
    def sections(self, /) -> list[SectionHeader]: ...

@final
class ImageMismatchRange(BaseRecord):
    """
    A contiguous RVA range of mismatched bytes.
    """
    __match_args__: Final[tuple[Literal["start"], Literal["end"]]]
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
class ImageSectionCheck(BaseRecord):
    """
    The comparison of one executable section with the cached image.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["rva"], Literal["genuine_mismatches"], Literal["total_mismatches"], Literal["self_patches"], Literal["skipped"], Literal["skip_reason"], Literal["unavailable"]]]
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
class ImageSelfPatchCounts(BaseRecord):
    """
    The number of bytes that ntoseye identifies as known kernel self-patches,
    by kind.
    """
    __match_args__: Final[tuple[Literal["import_optimization"], Literal["retpoline"], Literal["ki_patch_self"], Literal["region_rebase"]]]
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
    def total(self, /) -> int:
        """
        The bytes of every kind.
        """

@final
class ImageSelfPatchRange(BaseRecord):
    """
    A contiguous RVA range that ntoseye identifies as one kind of kernel
    self-patch.
    """
    __match_args__: Final[tuple[Literal["start"], Literal["end"], Literal["kind"], Literal["function"]]]
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
    def kind(self, /) -> Literal["import_optimization", "retpoline", "ki_patch_self", "region_rebase"]: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes.
        """
    @property
    def start(self, /) -> int: ...

@final
class ImportDescriptor(BaseRecord):
    """
    One `IMAGE_IMPORT_DESCRIPTOR`, which identifies a DLL that the image
    imports from, and its entries.
    """
    __match_args__: Final[tuple[Literal["import_name_table"], Literal["time_date_stamp"], Literal["forwarder_chain"], Literal["import_address_table"], Literal["entries"], Literal["incomplete"]]]
    @property
    def entries(self, /) -> list[ImportEntry]: ...
    @property
    def forwarder_chain(self, /) -> int: ...
    @property
    def import_address_table(self, /) -> int:
        """
        `FirstThunk`.
        """
    @property
    def import_name_table(self, /) -> int:
        """
        `OriginalFirstThunk`.
        """
    @property
    def incomplete(self, /) -> str |None:
        """
        Why `entries` stops short of the table's end: a thunk that does not
        read, or no terminator within the bound. `None` when the table was
        read to its terminator.
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
class ImportEntry(BaseRecord):
    """
    One imported function: its import-name-table entry and the import
    address table slot beside it.
    """
    __match_args__: Final[tuple[Literal["bound"]]]
    @property
    def bound(self, /) -> int |None:
        """
        The bound address in the import address table. `None` if that slot
        does not read.
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
class IndirectTable(BaseRecord):
    """
    What an indirect descriptor's table holds: its descriptors, and the
    bytes the driver gives the device and the device may write back.
    """
    __match_args__: Final[tuple[Literal["descriptors"], Literal["out_bytes"], Literal["in_bytes"]]]
    @property
    def descriptors(self, /) -> int: ...
    @property
    def in_bytes(self, /) -> int: ...
    @property
    def out_bytes(self, /) -> int: ...

@final
class Inspect:
    """
    System-wide reports and helpers that decode an object at an address
    (`dbg.inspect`). The results are typed records. On a user-mode
    minidump, which has no kernel, only `version`, `time`, `triage`,
    `bugcheck`, `exception_record`, and `context_record` apply; the others
    raise `NtoseyeError`.
    """
    def __repr__(self, /) -> str: ...
    def acl(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Acl:
        """
        Decode an ACL and its ACEs.
        """
    def alpc_message(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> AlpcMessage:
        """
        Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
        """
    def alpc_port(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> AlpcPort:
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
        of a thread (`!apc`): `target` is a `Process`, a `Thread`, or an
        `_ETHREAD` address, and all threads by default.
        """
    def blackbox_bsd(self, /) -> BootStatus:
        """
        Show the boot status data (bootstat.dat) the crash dump recorded.
        
        Whether the last boot succeeded and shut down, the boot IDs of the last
        successful and abnormal shutdowns, the power transition and power button
        state, and the feature configuration state, as WinDbg's !blackboxbsd shows
        them.
        """
    def blackbox_ntfs(self, /) -> list[NtfsRecord]:
        """
        Show the NTFS slow I/O and oplock break timeouts the crash dump recorded.
        
        Each record shows its type and length; a slow I/O timeout its IRP, SCB,
        and waiting thread, and an oplock break timeout its reason (the NTFS
        routine), IRP, SCB, and the owning and breaking processes, as WinDbg's
        !blackboxntfs shows them.
        """
    def blackbox_pci(self, /) -> list[PciRecord]:
        """
        List the PCI functions pci.sys recorded in the crash dump, with their
        command and status.
        
        Each function shows its bus, device, and function, its vendor and device
        IDs and revision, and its command and status registers with their flags as
        WinDbg's !blackboxpci shows them: i (I/O), m (memory), b (bus master), v
        (VGA palette snoop), p (parity), s (SERR) for the command, and c
        (capability list), 6 (66 MHz), P (master data parity error), A (signaled
        target abort), S (signaled system error) for the status. WinDbg prints the
        command register's value as the status value; ntoseye prints the status
        register's.
        """
    def blackbox_pnp(self, /) -> PnpBlackbox:
        """
        Show the PnP event the crash dump recorded.
        
        The PnP activity, its time, the event, whether it was in progress, the
        device's problem code, the veto, and the device instance ID, as WinDbg's
        !blackboxpnp shows them.
        """
    def blackbox_winlogon(self, /) -> WinlogonBlackbox:
        """
        Show what winlogon was doing when the crash dump was written.
        """
    def bugcheck(self, /) -> BugcheckAnalysis |None:
        """
        Show the bugcheck code and its four parameters.
        
        Uses the bugcheck that the stop reported. If there is none, it uses the
        bugcheck in nt!KiBugCheckData, as $bug_code and $bug_param1-4 do, and if
        there is none there, the bugcheck in the crash dump header. !analyze uses
        the same order.
        """
    def callbacks(self, /) -> list[NotifyCallback]:
        """
        List the process, thread, and image notification callbacks.
        """
    def class_device(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> ClassDeviceDetail:
        """
        Read the class device whose FDO, device extension, or private data
        is at `address`, with its requests in flight and its error log
        (`!storagekd.storclass <address>`).
        """
    def class_devices(self, /) -> ClassDevices:
        """
        List the storage class devices on `classpnp!AllFdosList`
        (`!storagekd.storclass`).
        """
    def context_record(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Frame:
        """
        Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
        """
    def control_area(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> ControlAreaDetail:
        """
        Decode the control area of a section, with its segment and subsections.
        
        Shows the section, PFN, mapped-view, and user reference counts, the
        _MMSECTION_FLAGS that are set, and the backing file object and its name. It
        also shows the segment (PTE count, size, committed pages, and prototype
        PTEs) and, for each subsection, the base PTE, the PTE count, the starting
        sector, the sector count, and the protection. The command reads up to 1,024
        subsections along NextSubsection, starting from the subsection after the
        control area, and stops at a subsection that points to a different control
        area. To find a control area, use the SectionObjectPointer of a file object
        or the Subsection of a VAD.
        """
    def decode_bugcheck(self, /, code: int, parameters: Sequence[int] = ...) -> BugcheckDecoding:
        """
        Decode a bugcheck code and its parameters as if the target had stopped
        with it (`!analyze -show`), and for a DRIVER_POWER_STATE_FAILURE (0x9F),
        read what its parameters point to. The target must be a kernel.
        """
    def device(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Device:
        """
        Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
        """
    def device_power(self, /, device: int |str |Process |Thread |Module |Driver |Device |Heap) -> DevicePower:
        """
        Show the power state of a device object.
        
        Shows the device's driver and power flags, the system and device power
        states its driver last set with PoSetPowerState (from the PowerFlags of its
        DEVOBJ_EXTENSION), the idle detection the driver registered, if any, the
        device state PnP records in the device node of the stack, whether the driver
        registered with the power framework and the device power IRP that it has
        outstanding, and the power IRPs on nt!PopIrpList sent to any device of the
        stack.
        """
    def device_stack(self, /, device_or_node: int |str |Process |Thread |Module |Driver |Device |Heap) -> DeviceStackDetail:
        """
        Show the device stack for a DEVICE_OBJECT or device node.
        
        The argument can be any DEVICE_OBJECT in the stack, or the DEVICE_NODE of
        the stack. The command shows the stack from the top filter down to the PDO,
        with the !DevObj, !DrvObj, !DevExt, and object name of each device, and a
        `>` marks the argument. After the stack, the command shows the device node
        of the PDO.
        """
    def devnode(self, /, node: int |str |Process |Thread |Module |Driver |Device |Heap |None = None, *, recurse: bool |None = None) -> DevNodeDetail:
        """
        Show a PnP device node and, optionally, its subtree.
        
        Shows the instance path, the service, the state and state history, the
        flags, the problem code, and the pending IRP of a device node. If you do not
        give a node, or give 0, the command shows the root device node. Use -r, or a
        trailing 1 as in WinDbg, to walk the subtree of the node, with one node on
        each line.
        """
    def dpcs(self, /) -> DpcQueues:
        """
        List the deferred procedure calls that are queued on each processor.
        
        The command walks the two _KPRCB DpcData queues. Each walk detects cycles
        and has an entry limit.
        """
    def etw_buffers(self, /, logger: int |str) -> EtwLoggerBuffers:
        """
        List the trace buffers on the GlobalList of an ETW trace session
        (`!wmitrace.strdump logger`).
        """
    def etw_crash_events(self, /, logger: int |str, *, count: int |None = None) -> EtwEventDump:
        """
        Decode the events of an ETW trace session that Windows saved in a
        crash dump, oldest first (`!wmitrace.logdump` in a minidump).
        `logger` is the logger ID or the session name, and `count` keeps
        only the most recent events.
        """
    def etw_crash_save(self, /, logger: int |str, path: str) -> EtwLogSave:
        """
        Save the buffers of an ETW trace session that Windows saved in a crash
        dump as an .etl file at `path` on the host (`!wmitrace.logsave` in a
        minidump). `logger` is the logger ID or the session name.
        """
    def etw_crash_session(self, /, logger: int |str) -> EtwDumpLogger:
        """
        Show one ETW trace session that Windows saved in a crash dump, with its
        buffers (`!wmitrace.logger` and `!wmitrace.strdump logger` in a
        minidump). `logger` is the logger ID or the session name.
        """
    def etw_crash_sessions(self, /) -> EtwDumpData:
        """
        List the ETW trace sessions that Windows saved as it wrote a crash
        dump, and their buffers (`!wmitrace.strdump` in a minidump): the
        sessions started with `EVENT_TRACE_ADDTO_TRIAGE_DUMP`, such as
        EventLog-System. A minidump has no other copy of them; in a kernel or
        full dump, `etw_loggers()` reads every session from memory.
        """
    def etw_events(self, /, logger: int |str, *, count: int |None = None) -> EtwEventDump:
        """
        Decode the events that are still in the buffers of an ETW trace session,
        oldest first (`!wmitrace.logdump`). `count` keeps only the most recent
        events. For a WPP message, `message_format.text` is the message rendered
        from the TMF that a loaded PDB declares, and the raw `record.payload` is
        always kept.
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
    def etw_save(self, /, logger: int |str, path: str) -> EtwLogSave:
        """
        Save the in-memory buffers of an ETW trace session as an .etl file at
        `path` on the host (`!wmitrace.logsave`), which ETW consumers such as
        tracerpt open. `logger` is the logger ID, the context address, or the
        session name.
        """
    def exception_record(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> ExceptionRecord:
        """
        Show an EXCEPTION_RECORD64.
        """
    def file_cache(self, /) -> FileCacheDetail:
        """
        Show the views that the cache manager has mapped, for each file.
        
        Walks the VACB arrays (CcVacbArrays) to find the views in use, and groups
        the views by shared cache map. For each file, the command shows its name,
        the mapped 256 KB views, the pages of these views that are present in
        memory, the dirty pages, the file size, and the open count, with the file
        that has the most present data first. The summary shows the VACBs in use and
        free, and the bytes mapped and present. The command lists up to 1,024 files,
        and you can interrupt the walk.
        """
    def file_object(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> FileObject:
        """
        Decode a FILE_OBJECT and its relations to its device and name.
        """
    def findstack(self, /, symbol: str, *, level: int = 1) -> FindStack:
        """
        List the threads with a stack frame that matches a symbol or module.
        
        The command walks the stack of each Windows thread, up to 64 frames, as
        !stacks 2 does. `module!name` matches frames in that module whose function
        starts with name, as in WinDbg, so `nt!KeWait` matches KeWaitForSingleObject
        and KeWaitForMultipleObjects, and `nt!` matches all frames in nt. A bare
        word matches a module by name or a function by prefix. With * or ?, the
        module and function are globs (`nt!*Wait*`). Matches ignore case. Display
        level 0 lists the matching threads and the number of frames that match,
        level 1 (the default) adds the matching frames, and level 2 shows the whole
        stack and marks the matching frames with *. The command cannot search a
        thread whose stack does not walk, such as a thread that runs on a processor
        while the target runs, and lists these threads after the matches.
        """
    def flt_filters(self, /) -> FltFilters:
        """
        List the registered minifilters and their instances.
        
        Walks each filter manager frame in fltmgr!FltGlobals and its registered
        filters. For each filter, the command shows its altitude and its attached
        instances, with their names and altitudes. The command uses the types from
        the PDB of fltmgr.
        """
    def flt_instances(self, /, filter: int |str |None = None) -> FltInstances:
        """
        List minifilter instances with their filter and volume.
        
        Lists each instance of each registered filter. To list the instances of one
        filter, give its name (`WdFilter`) or its _FLT_FILTER address. For each
        instance, the command shows its name, altitude, filter, and the volume that
        it is attached to.
        """
    def flt_volumes(self, /) -> FltVolumes:
        """
        List the volumes that the filter manager is attached to, with their
        instances.
        
        Walks the attached volumes of each filter manager frame. For each volume,
        the command shows the device name, the file-system type, and the attached
        instances with their names and altitudes.
        """
    def global_flags(self, /) -> GlobalFlags:
        """
        Decode nt!NtGlobalFlag and the _PEB.NtGlobalFlag of the current process
        (`!gflag`): the value of each and the bits by their GFlags names.
        """
    def hang(self, /) -> HangReport:
        """
        Find what a hung system is doing (`!analyze -hang`): the thread on each
        processor with its stack, and the waiting threads with the most pending
        IRPs. The target must be a kernel.
        """
    def interrupt_controllers(self, /) -> HalControllers:
        """
        Show the I/O APIC and PIC lines as the HAL set them up.
        
        Walks the HAL's registered interrupt controllers
        (nt!HalpRegisteredInterruptControllers) and shows each one, an I/O APIC or a
        legacy PIC, with its unit ID, ACPI resource ID, line range, and any problem
        the HAL recorded, then each line the HAL set up, from its own record of the
        line (_INTERRUPT_LINE_STATE): the line and its global system interrupt, the
        vector, the IRQL, edge or level trigger, polarity, and the processor target.
        This is what the HAL programmed into the redirection entries, read from
        kernel memory, so it works on every backend and in a kernel dump; it does
        not read the I/O APIC's registers.
        """
    def ipi(self, /, processor: int |None = None) -> IpiState:
        """
        Show the interprocessor interrupt (IPI) state of one processor or of all
        processors.
        
        For each processor, shows the IPI fields that its _KPRCB has on this Windows
        build. IpiFrozen is the freeze state that the debugger and KeFreezeExecution
        control (Running, Frozen, Freeze owner, ...). TargetCount and PacketBarrier
        apply to the processor as a sender and show the targets that did not finish
        its packet yet. The command also shows SelfIpiRequestSummary and IpiFrame,
        the trap frame of the IPI that the processor services now. Windows 10 and
        later builds have one mailbox for each sender, and on these builds the
        command also shows the requests that are in the queue of the processor and
        are not taken yet. For each request, it shows the sender, the request type,
        and for a packet, the worker routine and parameters. The request type
        (packet, TB flush, or cache flush) comes from RequestSummary. For the
        processor as a sender, the command also shows the processors whose queues
        still hold its request.
        """
    def irp(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> IrpInfo:
        """
        Show an IRP and its I/O stack locations.
        
        Shows the IRP as WinDbg does: which stack location is current, the MDL,
        system buffer and thread, then each location from the lowest driver's up,
        the current one marked with > and a run of locations the IRP has not reached
        as one unused line. A location shows its major and minor function, flags and
        control, device and file, its completion routine and context with when the
        routine runs (Success, Error, Cancel) and whether its driver returned
        pending, the device's driver, and four arguments. The driver of the location
        below it in the list set that completion routine. With a second argument,
        such as 1, it first shows the IRP's status, requestor mode, user event and
        user buffer.
        """
    def irp_find(self, /, *, pool_type: Literal["nonpaged", "paged"] |None = None, restart: int |str |Process |Thread |Module |Driver |Device |Heap |None = None, criteria: Literal["arg", "device", "fileobject", "mdlprocess", "thread", "userevent"] |None = None, value: int = 0) -> IrpFindDetail:
        """
        Scan pool for the IRPs that IoAllocateIrp allocates.
        
        Scans the pool region for 16-byte-aligned _POOL_HEADERs with the tag Irp. On
        Windows 10 1803 and later, the region comes from MiState.Vs.SystemVaRegions,
        and otherwise it is MmNonPagedPoolStart/End or MmPagedPoolStart/End. The
        scan walks the page tables and reads only mapped pages, and big allocations
        come from PoolBigPageTable. The command counts a block only if its body is a
        live _IRP. In a live _IRP, Type is 6 (IoFreeIrp clears it), and Size is the
        header plus whole stack locations and at least IoSizeOfIrp(StackCount). A
        lookaside IRP keeps its larger packet size. CurrentLocation is at most
        StackCount + 1. For each IRP, the command shows its thread
        (Tail.Overlay.Thread), the process of its MDL, and the major function, minor
        function, device, and owning driver of the current stack location. If
        CurrentLocation is more than StackCount, the IRP shows as complete. -v also
        shows the pool header, I/O status, PendingReturned, UserEvent, UserBuffer,
        and OriginalFileObject, and also the file object and completion routine of
        the current location. pool-type is 0 (nonpaged, the default) or 1 (paged).
        The command does not accept 2 (special) or 4 (session), because these pool
        types have no region of their own on these builds. restart-address continues
        a scan from that page. The criteria are the same as in WinDbg: arg
        (Argument1-4 of a stack location), device (DeviceObject of a stack
        location), fileobject (Tail.Overlay.OriginalFileObject), mdlprocess
        (MdlAddress->Process), thread (Tail.Overlay.Thread), and userevent
        (UserEvent). Use 0 as the restart address to scan the whole pool. The scan
        stops after 4,096 IRPs, or when you press Ctrl-C, and then shows the command
        that continues the scan, with the criteria. The scan checks the big-pool
        allocations last. If the scan gets to the limit in the big-pool allocations,
        the command shows a message. A restart cannot get to the remaining big-pool
        allocations. A driver can build IRPs in its own allocations
        (IoInitializeIrp). These IRPs have the tag of that driver, so the scan does
        not find them. Use irps to list the IRPs in thread IrpLists.
        """
    def irps(self, /, *, filter: str |None = None) -> list[IrpHit]:
        """
        Find the in-flight IRPs in thread IrpLists and device CurrentIrp fields.
        """
    def job(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Job:
        """
        Show a job object and the processes in it.
        
        Shows a job object. The address can be a job, or a process or thread, for
        which the command shows its job. If you do not give an address, or give 0,
        the command shows the job of the current process. Flag 1 (the default)
        shows the accounting, limits, and flags of the job, and also the child
        jobs, the parent and root job, and the silo state. Flag 2 lists the
        processes assigned to the job (from ProcessListHead).
        """
    def lookaside(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> LookasideDetail:
        """
        Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
        """
    def lookasides(self, /) -> LookasideListsDetail:
        """
        List the exported nonpaged and paged `GENERAL_LOOKASIDE` lists
        (`!lookaside`), detecting cycles.
        """
    def mdl(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap, *, pfn_count: int |None = None) -> MdlDetail:
        """
        Decode a memory descriptor list and the page frames it describes.
        
        The command shows the _MDL header and the PFN array that follows it. The
        header fields are Next, Size, MdlFlags by MDL_* name, Process,
        MappedSystemVa, StartVa, ByteCount, and ByteOffset. By default, the PFN
        count is the number of pages that ByteCount spans from ByteOffset, and a
        pfn-count overrides this value. In both cases, the count cannot be more than
        the slots that Size leaves after the header. If the Size, ByteOffset, or
        span of the header cannot describe an MDL, the command gives an error. The
        command does not follow Next, so for a chained MDL, run !mdl on the Next
        address.
        """
    def memusage(self, /, *, process_limit: int = 64) -> SystemMemorySummary:
        """
        Show the system memory-use counters and the counters of a limited number
        of processes.
        
        The command uses validated memory-manager globals, KDBG fields, or
        recognized public getter code, and EPROCESS.Vm counters. It does not scan
        physical memory, and it does not walk all VADs.
        """
    def ndis_filter(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> NdisFilterDetail:
        """
        Read the NDIS filter module at `address` (`!ndiskd.filter <address>`).
        """
    def ndis_filter_driver(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> NdisFilterDriverDetail:
        """
        Read the NDIS filter driver block at `address` and its filter
        modules (`!ndiskd.filterdriver <address>`).
        """
    def ndis_filter_drivers(self, /) -> NdisFilterDriverList:
        """
        List the NDIS filter drivers (`!ndiskd.filterdriver`).
        """
    def ndis_filters(self, /) -> NdisFilterList:
        """
        List the NDIS filter modules of every miniport (`!ndiskd.filter`).
        """
    def ndis_minidriver(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> NdisMinidriver:
        """
        Read the NDIS miniport driver block at `address` and its miniports
        (`!ndiskd.minidriver <address>`).
        """
    def ndis_minidrivers(self, /) -> NdisDriverList:
        """
        List the NDIS miniport drivers (`!ndiskd.minidriver`).
        """
    def ndis_miniport(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> NdisMiniportDetail:
        """
        Read the NDIS miniport at `address` with its driver, filter stack,
        bindings, and pending OID request (`!ndiskd.miniport`).
        """
    def ndis_miniports(self, /) -> NdisMiniportList:
        """
        List the NDIS miniports (network adapters).
        
        Walks ndis!ndisMiniportList and shows one line per miniport: the address of
        its _NDIS_MINIPORT_BLOCK, which !ndiskd.miniport takes, the service of its
        miniport driver, the miniport state (Running, Pausing, Paused, Restarting,
        Initializing, Halted), the media connect state with the transmit link speed
        (and the receive speed when it differs), the device power state, the
        interface index, and the friendly name. Virtual miniports, such as Hyper-V's
        adapters, are on the list too. The command needs the PDB for ndis.sys.
        """
    def ndis_nbl(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap, *, data: bool = False) -> NdisNbl:
        """
        Decode the NET_BUFFER_LIST at `address` and its NET_BUFFERs
        (`!ndiskd.nbl`). With `data`, each NET_BUFFER's `data` holds up to
        64 KiB of its frame, read through its MDLs' PFNs, or `data_error` why it
        does not read (`!ndiskd.nbl -data`).
        """
    def ndis_nbl_chain(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap, *, data: bool = False) -> NdisNblChain:
        """
        Decode the NET_BUFFER_LISTs on the `Next` chain from `address`
        (`!ndiskd.nbl -chain`). With `data`, each NET_BUFFER's `data` holds up
        to 64 KiB of its frame, or `data_error` why it does not read
        (`!ndiskd.nbl -chain -data`).
        """
    def ndis_oids(self, /) -> NdisPendingOids:
        """
        Show the OID requests that miniports and filters have not completed.
        
        Reads the PendingOidRequest of every miniport on ndis!ndisMiniportList and
        every filter module on ndis!ndisGlobalFilterList, and shows each request
        with its owner, type, OID by its ntddndis.h name, and buffer. NDIS passes a
        miniport or filter one OID request at a time, apart from direct OID
        requests, so a request that stays here holds up the ones behind it. The
        command needs the PDB for ndis.sys.
        """
    def ndis_protocol(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> NdisProtocolDetail:
        """
        Read the NDIS protocol block at `address` and its bindings
        (`!ndiskd.protocol <address>`).
        """
    def ndis_protocols(self, /) -> NdisProtocolList:
        """
        List the NDIS protocol drivers (`!ndiskd.protocol`).
        """
    def object(self, /, object: int |str |Process |Thread |Module |Driver |Device |Heap) -> ObjectDetail:
        """
        Show an executive object header and body, and list the entries of a directory.
        
        A path that starts with `\\` is the name of an object in the object namespace
        (`!object \\`, `!object \\Driver\\ACPI`). The command looks up the path from
        the root directory and ignores case. It does not follow symbolic links in
        the path. For a directory, the command lists the entries and their types.
        """
    def object_security(self, /, object: int |str |Process |Thread |Module |Driver |Device |Heap) -> ObjectSecurity:
        """
        Decode the security descriptor that an object header references.
        
        The command masks the low four bits of the OBJECT_HEADER.SecurityDescriptor
        fast reference before it decodes the descriptor.
        """
    def pci(self, /, bus: int = 0, device: int |None = None, function: int |None = None, *, last_bus: int |None = None) -> PciScan:
        """
        Read and decode PCI configuration space (`!pci`) for the functions on
        `bus` (through `last_bus`), or for one `device` and `function`. It reads
        all 4 KiB of each function, with the extended capabilities, as `config`.
        This needs a halted target and a backend that can get to configuration
        space (kd/kdnet, or gdb on QEMU).
        """
    def pci_tree(self, /) -> PciTree:
        """
        Show the PCI bus hierarchy that pci.sys tracks, with the functions on each
        bus.
        
        Reads the pci.sys segment list (pci!PciSegmentList), the root buses of each
        segment, and the functions and child buses of each bus. The data comes from
        the extensions of the driver (pci!_PCI_BUS and pci!_PCI_DEVICE), which exist
        on Windows 8 and later. Because the command reads only guest memory, it
        works on all backends. A bus line shows the bus number and the FDO
        extension. A function line shows the device and function number, the vendor
        and device ID, the PDO extension (devext), the PDO (devstack, for
        !devstack), and the class code and name. The secondary bus of a bridge
        follows the bridge and is indented. The JSON output also has the PnP
        instance path of each function.
        """
    def pfn(self, /, value: int, *, physical_address: bool = False) -> PfnDetail:
        """
        Decode an _MMPFN entry.
        
        A plain value is a page-frame number. Use -a to read the value as a physical
        address.
        """
    def pnp_triage(self, /) -> PnpTriageDetail:
        """
        Show the PnP device nodes that have problems, pending IRPs, or incomplete
        starts.
        """
    def pool(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> PoolPageDetail:
        """
        Show the pool page that contains an address.
        """
    def pool_find(self, /, tag: str, *, pool_type: Literal["nonpaged", "paged"] |None = None) -> PoolFindDetail:
        """
        Find pool blocks with a matching tag.
        
        The command reads the mapped pages of the pool ranges and the big-page
        table. On Windows 10 1803 and later, the pool ranges are the fixed regions
        in MiState.Vs.SystemVaRegions. On earlier builds, they come from
        MmNonPagedPoolStart and related symbols. The optional type selects nonpaged
        (0) or paged (1) pool. The scan stops after 1,024 matches, and you can
        interrupt it.
        """
    def pool_usage(self, /, tag: str |None = None, *, sort: Literal["tag", "nonpaged", "paged"] = ...) -> PoolUsageDetail:
        """
        Show pool tracker usage by tag.
        
        The command adds up the usage from the tag table of each processor. The
        flags follow WinDbg: bit 1 (2) sorts by nonpaged bytes, bit 2 (4) sorts by
        paged bytes, and bit 0 (1) shows the alloc/free columns. The tag match is
        case-sensitive and supports * and ?.
        """
    def pool_validate(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> PoolValidationDetail:
        """
        Check the block headers of the pool page that contains an address.
        
        The command reports the page as VALID or INVALID, with the first
        inconsistency. The blocks of a classic pool page must make a chain from the
        start of the page to its end, in which the PreviousSize of each block
        matches the BlockSize of the block before it. Segment-heap pages (Windows 10
        1903 and later) have no PreviousSize chain, so on these pages the
        inconsistency is a block whose BlockSize runs over the header of another
        block. The PoolType of a classic block must also identify the pool (paged or
        nonpaged) that holds the page. A level of 1 or more also lists all block
        headers. The command does not do the single-bit-error scan of WinDbg.
        """
    def power_action(self, /) -> PowerActionDetail:
        """
        Show the system power action and the power IRPs in flight.
        
        Shows nt!PopAction: the power action in progress, its state and flags, and
        the system state being entered, with the device notification pass when one
        runs. Then lists every power IRP the power manager has allocated, from
        nt!PopIrpList: its PDO, the device it was sent to, its minor function and
        the power state it asks for, where it is pending now (the driver of its
        current stack location), and how long the drivers have had it when the power
        IRP watchdog runs. Last come the threads that pass power IRPs to drivers,
        from nt!PopIrpThreadList, with the IRP and device each is working on.
        """
    def queued_locks(self, /) -> QueuedLocks:
        """
        Show which processors own or wait for each numbered queued spinlock.
        
        Reads the _KPRCB.LockQueue entries of each processor, which hold one
        _KSPIN_LOCK_QUEUE for each _KSPIN_LOCK_QUEUE_NUMBER lock. The table has the
        same layout as in WinDbg, with one row for each lock and one column for each
        processor. O marks the owner, and 1-n marks the wait order, which the
        command finds by following the queue links from the owner. C marks an entry
        whose owner or wait bits do not agree with the links. The table shows only
        the numbered locks (KeAcquireQueuedSpinLock). In-stack queued spinlocks are
        on the stacks of the callers that acquire them.
        """
    def rcdr_drivers(self, /) -> RcdrDriverList:
        """
        List the drivers the WPP recorder keeps logs for
        (`!rcdrkd.rcdrloglist`).
        """
    def rcdr_log(self, /, driver: str, *, log: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> RcdrLogDump:
        """
        Show a driver's WPP recorder log records, oldest first.
        
        Walks each of the driver's recorder logs, both the normal and the error
        partition, back from the newest record, and shows the records of all of them
        merged in the order the driver logged them (their sequence numbers come from
        one counter per driver). -a shows only the log whose _WPP_AUTOLOG_HEADER you
        give, as !rcdrkd.rcdrloglist lists it. Each record shows its sequence
        number, its time when the log keeps timestamps, the log it is in, and its
        message formatted from the trace message format (TMF) annotations in a
        loaded PDB, or else the message GUID and number and the argument bytes.
        Microsoft's public PDBs carry no TMF annotations; add your driver's private
        PDB to the symbol path for its messages. The walk is !wdfkd.wdflogdump's:
        the records share KMDF's IFR format.
        """
    def rcdr_logs(self, /, driver: str) -> RcdrLogs:
        """
        List the WPP recorder logs of `driver`, by its name with or without
        `.sys` or its recorder context (`!rcdrkd.rcdrloglist <driver>`).
        """
    def read_tagged(self, /, tag: str) -> bytes:
        """
        Read the data of the crash dump's block tagged `tag` (`.enumtag`), a
        GUID with or without braces, such as the one a driver passes to
        `KeRegisterBugCheckReasonCallback` for its secondary dump data.
        `target.dump.tagged_blocks` lists the blocks.
        """
    def ready(self, /, processor: int |None = None) -> ReadyQueues:
        """
        List the dispatcher ready queues of all processors or of one processor.
        
        The command reads DispatcherReadyListHead from each _KPRCB, or ReadyListHead
        on newer builds. Each queue walk has an entry limit and, like `dt -l`,
        reports null links, cycles, unreadable links, and when it reaches its entry
        limit.
        """
    def registry_cell(self, /, hive: int |str |Process |Thread |Module |Driver |Device |Heap, cell: int) -> CellLocation:
        """
        Find where cell index `cell` of the hive at `hive` is, through the
        hive's cell map (`!reg cellindex`).
        """
    def registry_hives(self, /) -> HiveList:
        """
        List the registry hives loaded in kernel memory, with where each is
        mounted and the file it was loaded from (`!reg hivelist`).
        """
    def registry_key(self, /, path: str) -> RegKey:
        """
        Read the registry key at `path`, a full path such as
        `HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip` or
        `\\REGISTRY\\MACHINE\\...`, with its subkeys and its values, each
        value's data typed by its type (`!reg querykey`).
        """
    def registry_key_at(self, /, hive: int |str |Process |Thread |Module |Driver |Device |Heap, node: int |str |Process |Thread |Module |Driver |Device |Heap) -> RegKey:
        """
        Read the registry key whose key node (`_CM_KEY_NODE`) is at `node`
        in the hive at `hive` (`!reg keyinfo`).
        """
    def registry_value(self, /, path: str, name: str) -> RegValue:
        """
        Read the value `name` of the registry key at `path`; `""` names the
        key's default value. Its `data` is a `str`, a `list[str]`, an `int`,
        or `bytes`, by the value's type (`!reg querykey <path> -v <name>`).
        """
    def resource(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> ExecutiveResource:
        """
        Decode an executive resource (`!locks address`).
        """
    def resources(self, /, *, limit: int = 256) -> ResourceList:
        """
        List the entries of the symbol-backed executive-resource list
        (`!locks`), at most `limit` of them.
        """
    def running(self, /, *, include_idle: bool = False, include_stacks: bool = False) -> RunningProcessors:
        """
        Show the thread that runs on each processor.
        
        -i includes idle threads, and -t adds a short kernel stack, with a frame
        limit, for each processor.
        """
    def security_descriptor(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> SecurityDescriptor:
        """
        Decode a SECURITY_DESCRIPTOR and its ACLs.
        
        Decodes a self-relative or absolute security descriptor, and decodes each
        SID and each ACE separately. The optional 1 adds the names of well-known
        SIDs.
        """
    def session_processes(self, /, session: int |None = None, *, image: str |None = None) -> SessionProcesses:
        """
        List the processes in a session.
        
        The session is a signed decimal number. -1 and -2 select the current
        session, and -4 selects all sessions. If you do not give a session, the
        command uses the session of the attached process, if it is known. Flags
        default to 0 (brief output), and any non-zero value selects detailed
        output. The optional image argument is a glob that ignores case.
        """
    def sessions(self, /, session: int |None = None) -> Sessions:
        """
        List the sessions and the processes in each session.
        
        The command reads session IDs from _EPROCESS.Session and
        _MM_SESSION_SPACE, or from the primary token if session space is opaque.
        Use -s -1 for the current session. The process walk stops at 4096 entries.
        """
    def set_global_flags(self, /, change: str) -> GlobalFlags:
        """
        Change nt!NtGlobalFlag and decode the flags as they now are (`!gflag
        +ust`). `change` is `+` or `-` and a value or a flag's three-letter
        abbreviation, which sets or clears those bits, or a value without a sign,
        which replaces nt!NtGlobalFlag. It is one 4-byte write to
        nt!NtGlobalFlag; the PEB copy does not change. The result's `change`
        has the value before and after.
        """
    def sid(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Sid:
        """
        Decode a SID in guest memory.
        """
    def smbios(self, /) -> SmbiosTable:
        """
        Read the SMBIOS table the kernel found at boot
        (`nt!WmipSMBiosTablePhysicalAddress`) from physical memory, with every
        structure it holds (`!sysinfo smbios`; `!sysinfo machineid` shows the
        identity strings of the same table).
        """
    def srb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Srb:
        """
        Decode an SRB: its function, status, command, address, data, and sense.
        
        Decodes a STORAGE_REQUEST_BLOCK (an extended SRB, which StorPort, classpnp,
        and miniports use on Windows 8 and later) or a legacy SCSI_REQUEST_BLOCK
        with storport's public PDB: the SRB function, the SRB status with
        QUEUE_FROZEN and AUTOSENSE_VALID, the SCSI status, the command its CDB holds
        with its LBA and block count, the port, path, target, and LUN, the data
        buffer and length, the IRP (OriginalRequest), the flags by SRB_FLAGS_ name,
        the timeout, tag, and priority, the sense data when AUTOSENSE_VALID says it
        is valid, the class, port, and miniport contexts, and an extended SRB's
        extended data blocks. An address whose Function and Signature, or Length,
        are not an SRB's is refused.
        """
    def ssdt(self, /) -> list[SsdtTable]:
        """
        Show the SSDT and the shadow SSDT.
        """
    def stacks(self, /, *, level: int = 0, filter: str |None = None) -> ThreadStacks:
        """
        Show the state, wait reason, and top stack symbol of each thread.
        
        Level 0 shows one frame. Levels 1 and 2 add the full stacks, with a frame
        limit. The optional filter matches process or stack symbols.
        """
    def storport_adapter(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> StorAdapter:
        """
        Read the StorPort adapter whose extension or FDO is at `address`
        (`!storagekd.storadapter <address>`).
        """
    def storport_adapters(self, /) -> StorDrivers:
        """
        List StorPort's drivers, their adapters, and their units
        (`!storagekd.storadapter`).
        """
    def storport_log(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> StorLog:
        """
        Show a StorPort adapter's internal log of requests, pauses, and resumes.
        
        Give the address of an adapter extension or of its FDO, as
        !storagekd.storadapter lists them. StorPort keeps a ring of its last 256
        events for each adapter (RaidLogList): requests it builds, starts, and sees
        completed, pauses and resumes of the adapter and its units, busy and ready
        notifications, timeouts, resets, and PnP and power IRPs. Each entry shows
        its number, its time (UTC), the event, and for a request its IRP, SRB,
        command, and SRB status, or else the four parameters StorPort logged, a code
        address by symbol. Without a range, the command shows the last 50 entries;
        <start> shows entries from that number, <start> <end> that range, and L
        <count> how many.
        """
    def storport_unit(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> StorUnit:
        """
        Show a StorPort logical unit, its queue, and the requests the miniport
        holds.
        
        Give the address of a unit extension (_RAID_UNIT_EXTENSION), as
        !storagekd.storadapter lists them, or of the unit's PDO. Shows the unit's
        bus/target/LUN, the inquiry vendor, product and revision, the adapter, the
        PnP and power state, the flags, the miniport's per-unit extension
        (StorPortGetLogicalUnit), and its device queue: the depth, whether it is
        frozen or locked, the pause and busy counts, and the requests waiting in
        storport. Then it lists each request that storport handed to the miniport
        and has not seen completed, from the unit's per-processor pending queues,
        with its _EXTENDED_REQUEST_BLOCK, IRP and SRB; use !irp on the IRP. It lists
        at most 256 requests and says why a list stopped early.
        """
    def system_ptes(self, /, *, free_runs: bool = False) -> SystemPtesDetail:
        """
        Show system PTE usage from the memory manager's bitmap allocators.
        
        Windows 10 and later allocate system PTEs from _MI_SYSTEM_PTE_TYPE bitmap
        allocators in MiState. These allocators are Vs.SystemPteInfo (the SystemPtes
        region) and the system-view, non-cached-mapping, and kernel-stack allocators
        of SystemPtes. For each allocator, the command shows the VA range that it
        serves, TotalSystemPtes, TotalFreeSystemPtes, the PTEs in use, and
        PteFailures, and from the bitmap, the number of free blocks and the largest
        free block. The command reads all of the bitmap, up to 2^27 bits, a limit
        that only a corrupt SizeOfBitMap exceeds. If the free count from the bitmap
        differs from the counter, the target made an allocation between the reads.
        All counts are in PTEs, and each bit of the system-view bitmap covers 16
        PTEs. The flags follow WinDbg. 0x1 lists each free block with its first PTE,
        the address that it maps, and its length, up to 256 free blocks for each
        allocator. 0x4 (PTEs that map locked pages) needs the TrackPtes tracking of
        the kernel, and shows which allocators track but does not list the tracked
        mappings. The command ignores 0x2, 0x8, and 0x10, which select Windows
        2000/XP/Vista lists that these allocators replaced. On a build without these
        allocators, the command gives an error.
        """
    def time(self, /) -> TargetTime:
        """
        Show the target UTC time and the system uptime.
        """
    def timer(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> KernelTimer:
        """
        Decode a `_KTIMER` and its DPC (`!timer address`).
        """
    def timers(self, /) -> TimerTable:
        """
        Read the kernel timer-table entries, up to a limit, and their DPCs
        (`!timer`).
        """
    def trap_frame(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> KtrapFrame:
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
        Show version information for the target, kernel, symbols, processor, and
        debugger.
        """
    def virtio(self, /) -> list[VirtioFunction]:
        """
        List the virtio PCI functions (`!virtio`), with the state of each
        queue where the driver's private PDB types it. A queue's `progress`
        counters only grow, so two calls show what moved in between.
        """
    def virtio_driver(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap, *, module: str |None = None) -> VirtioDriver:
        """
        Read the `virtio_device` at `address` as its virtio-win driver sees it,
        with its queues, named when its PCI function is found
        (`!virtio <address> [module]`). `module` names the driver whose PDB
        types it, by default the one that owns it.
        """
    def vm(self, /, *, include_processes: bool = True) -> VmDetail:
        """
        Show virtual-memory statistics.
        
        The command shows system memory, pool, PTE, page-file, and process usage.
        The flags follow WinDbg: bit 0 omits the per-process rows, and the command
        accepts bits 1, 2, and 3 but ignores them. If the command cannot read a
        counter, it still shows the other counters.
        """
    def vpb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> VpbDetail:
        """
        Decode a volume parameter block.
        
        Shows the VPB_* flags, the volume device of the mounted file system, and the
        storage device below it, with their object names. It also shows the
        reference count, the serial number, and the volume label. The Vpb field of a
        device object points to the VPB. If the Type at the address is not
        IO_TYPE_VPB, the command shows an error.
        """
    def vring(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap, *, module: str |None = None, kind: Literal["blk", "scsi", "scsi_control", "scsi_event", "net", "net_control", "gpu", "vsock"] |None = None) -> VirtioRing:
        """
        Read the virtio-win virtqueue at `address` (`!vring`): its ring, the
        buffers the device holds or returned, and the request each carries.
        `module` names the driver whose PDB types it, by default the one its
        `add_buf` routine is in. `kind` says what its buffers hold, by default
        what its device's type and the queue's index say.
        """
    def vring_raw(self, /, size: int, desc: int |str |Process |Thread |Module |Driver |Device |Heap, avail: int |str |Process |Thread |Module |Driver |Device |Heap, used: int |str |Process |Thread |Module |Driver |Device |Heap, *, kind: Literal["blk", "scsi", "scsi_control", "scsi_event", "net", "net_control", "gpu", "vsock"] |None = None) -> VirtioRing:
        """
        Read a split ring from its size and the kernel addresses of its
        descriptor table, avail ring and used ring (`!vring /r`), for a driver
        without a PDB. `kind` says what its buffers hold, for decoding their
        requests (`/t`).
        """
    def vtop(self, /, directory_base: int, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> VtopDetail:
        """
        Translate a virtual address with an explicit directory base.
        
        The command shows each AMD64 page-table level and the final physical
        address. A directory base of zero uses the current context, and for a large
        page, the walk stops at its leaf level.
        """
    def wdf_crash_drivers(self, /) -> list[WdfDumpDriver]:
        """
        List the KMDF client drivers that KMDF recorded in a crash dump, with
        their version and globals (`!wdfkd.wdfcrashdump loader`).
        """
    def wdf_crash_log(self, /) -> WdfLogDump:
        """
        Get the In-Flight Recorder log of the one KMDF client driver that
        KMDF copied into a crash dump (`!wdfkd.wdfcrashdump`): the driver
        that the bugcheck parameters point to, or one set to keep its log in
        minidumps, or else the last one that ran on the processor that
        crashed. A minidump has no other copy of it.
        """
    def wdf_device(self, /, handle: int) -> WdfDeviceDetail:
        """
        Show a WDFDEVICE and its device objects, state machines, queues, and I/O
        targets.
        
        Shows the kind of the device (FDO, filter, PDO, or control), its WDM device
        object, the device object that it is attached to, and the PDO of the stack.
        It also shows the current states of the PnP, power, and power policy state
        machines (_WDF_DEVICE_PNP_STATE, _WDF_DEVICE_POWER_STATE,
        _WDF_DEVICE_POWER_POLICY_STATE), and the device and system power states. For
        a PDO, it shows the parent device, and for an FDO, the child lists and the
        default and self I/O targets. For each queue of the I/O package, it shows
        the dispatch type, the power management, and the counts of pending and
        driver-owned requests, and it marks the default queue. For each I/O target
        of the device (m_IoTargetsList), it shows the WDFIOTARGET handle, the kind
        of target, its state, and the device object that it sends to, and it marks
        the default target. Pass a WDFQUEUE to !wdfkd.wdfqueue and a WDFIOTARGET to
        !wdfkd.wdfiotarget.
        """
    def wdf_driver_info(self, /, driver: str) -> WdfDriverInfo:
        """
        Show a KMDF client driver and its WDF devices.
        
        Give the driver name as !wdfkd.wdfldr lists it. The name is not
        case-sensitive, and `.sys` is optional. The command shows the DRIVER_OBJECT,
        the FxDriver, the WDFDRIVER handle, the _FX_DRIVER_GLOBALS, the KMDF
        version, the registry path, and the image. Then it shows each device object
        on the DeviceObject/NextDevice chain of the driver object, with the related
        WDFDEVICE and its kind and PnP state. A device object links to its WDFDEVICE
        through its DeviceExtension, which KMDF sets to point to the first context
        of the device. The command checks the context header, the type and owner of
        the object, and the device object of the FxDevice, and if a check fails, it
        lists the device object with the reason.
        """
    def wdf_handle(self, /, handle: int) -> WdfObject:
        """
        Decode a WDF handle and show its object.
        
        A handle is the address of its object, XORed with ~7. An offset handle has
        bit 0 set and points to a WDFOBJECT_OFFSET value inside the object, which
        the command subtracts from the address that the handle points to. The
        command shows the FxObject, its type (FX_OBJECT_TYPES), size, reference
        count, state (FxObjectState), flags, owning driver, and parent, and each
        context with its type name, size, and address. Then it names the command
        that shows the object in full: !wdfkd.wdfdevice, !wdfkd.wdfqueue,
        !wdfkd.wdfrequest, or !wdfkd.wdfiotarget for those types,
        !wdfkd.wdfdriverinfo for a WDFDRIVER, and !wdfkd.wdfobject, which adds the
        children of the object, for any other type. It shows an error if the value
        does not decode to a kernel address, or if the type, state, size, context
        header, or owning driver of the object is not valid.
        """
    def wdf_io_target(self, /, handle: int) -> WdfIoTargetDetail:
        """
        Show a WDFIOTARGET, the device object it sends to, and the requests sent to
        it.
        
        Shows the kind of the target: local (in the device's own stack, as the
        default target is), remote (a target that the driver opened with
        WdfIoTargetOpen), self, or a USB device or USB pipe, and whether it is the
        default I/O target of its device. It shows the state (_WDF_IO_TARGET_STATE),
        the open state of a remote target, the WDFDEVICE that the target belongs to,
        the device object that the target sends requests to and the driver of that
        device object, the PDO of that stack, the file object, the I/O count, and
        the stack size. Then it lists the requests on three lists: the requests sent
        to the target and not completed (m_SentIoListHead), the requests sent with
        WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE while the target was not started
        (m_IgnoredIoListHead), and the requests that the target holds until it
        starts (m_PendedQueue). For each request, it shows the WDFREQUEST handle,
        the FxRequest, and the IRP. A request without a handle is the framework's
        own, such as the request that a synchronous send builds. A list stops at a
        request whose m_Target is not this target, with the reason.
        """
    def wdf_loader(self, /) -> WdfLoader:
        """
        List the KMDF client drivers.
        
        Walks the list at Wdf01000!FxLibraryGlobals.FxDriverGlobalsList. For each
        client driver, it shows the name, the KMDF version that the driver bound to
        (WdfBindInfo), the _FX_DRIVER_GLOBALS, the WDFDRIVER handle, the
        DRIVER_OBJECT, and whether the driver has an In-Flight Recorder log. The
        command needs the PDB for Wdf01000. The walk continues only while the Blink
        of each entry points back to the entry before it. A client has an empty
        DriverName if it bound to KMDF but did not create an FxDriver, and the
        command then lists the client by the name of its DRIVER_OBJECT, which you
        also use with !wdfkd.wdfdriverinfo and !wdfkd.wdflogdump. When a client name
        is not printable, or the FxDriver of a client fails the checks of its type,
        owner, or handle, the command lists the client with the problem.
        """
    def wdf_log(self, /, driver: str) -> WdfLogDump:
        """
        Show the In-Flight Recorder log of a KMDF driver, oldest record first.
        
        Reads the IFR log of the driver (_FX_DRIVER_GLOBALS.WdfLogHeader). The
        command walks the records back from the newest record along PrevOffset, and
        stops at the first record written or at records that newer records
        overwrote. For each record, it shows the sequence number, the UTC time (only
        when the log keeps timestamps), the function, and the message. The command
        formats the message from the trace message format (TMF) annotations in the
        PDB for Wdf01000. For a record with a message that no loaded PDB declares,
        or with arguments that do not fit the message, it shows the message GUID,
        the message number, and the argument bytes. The command checks the header
        (its GUID, base, and size) and each record (signature, length, position, and
        sequence), and the walk stops at the first item that fails a check, with the
        reason.
        """
    def wdf_object(self, /, object: int) -> WdfObjectDetail:
        """
        Show a KMDF object's header, contexts, and children.
        
        Give a handle, as for !wdfkd.wdfhandle, or the address of an FxObject. The
        command shows what !wdfkd.wdfhandle shows: the handle, the type
        (FX_OBJECT_TYPES), size, reference count, state (FxObjectState), flags
        (FXOBJECT_FLAGS), owning driver, and parent, and each context with its type
        name, size, and address. Then it lists the children of the object
        (m_ChildListHead), each with its handle and type. The framework's own
        children, such as the packages of a device, have no handle. Use the command
        for an object whose type has no command of its own, such as a WDFMEMORY,
        WDFTIMER, or WDFWORKITEM. The object must pass the same checks as for
        !wdfkd.wdfhandle, and the list of children stops at a child whose
        m_ParentObject is not this object.
        """
    def wdf_queue(self, /, handle: int) -> WdfQueueDetail:
        """
        Show a WDFQUEUE and its configuration, state, callbacks, and requests.
        
        Shows the dispatch type of the queue, the state bits (_FX_IO_QUEUE_STATE),
        the power state, and the power management. It also shows the execution
        level, the synchronization scope, the request counts, and the Evt callbacks
        that the driver set. Then it shows the requests on three lists: the requests
        that wait in the queue, the requests that the driver marked cancelable, and
        the requests presented to the driver. For each request, it shows the
        WDFREQUEST handle, which you pass to !wdfkd.wdfrequest, the FxRequest, and
        the IRP. If a request is not valid, the command stops that list at the
        request and shows the reason.
        """
    def wdf_request(self, /, handle: int) -> WdfRequestDetail:
        """
        Show a WDFREQUEST, its IRP, its queue, and the I/O target it was sent to.
        
        Shows the FxRequest, its owning driver, parent, reference count, and object
        state. For the IRP of the request, it shows the current stack location: the
        major and minor function, the device object and its driver, and the buffer
        lengths of a read, a write, or a device control with its control code. It
        also shows the system buffer, the user buffer, and the MDL of the IRP; pass
        the IRP to !irp for all of its stack locations. If the IRP was freed or
        reused, the command shows why it is not a live IRP. The command shows
        whether the IRP came from the I/O manager or the framework or the driver
        allocated it (FxRequestAllocationSource), whether the request is completed
        or canceled, and whether its queue presented it to the driver. It shows the
        queue that the request came from or waits in (m_IoQueue) and the cancel-safe
        queue that holds the IRP: the requests that wait in the queue, the requests
        that the driver marked cancelable with its EvtRequestCancel routine, which
        the command shows, or the requests that an I/O target holds until it starts.
        A request that none of these holds cannot be canceled. For a request that
        the driver sent, it shows the I/O target (m_Target), the completion routine
        and its context, and the target flags (FxRequestTargetFlags). KMDF sets the
        verifier flags (FxRequestVerifierFlags) only when its verifier is on for the
        driver.
        """
    def work_queues(self, /, *, include_stacks: bool = False, queue_types: Sequence[Literal["critical", "delayed", "hypercritical"]] |None = None) -> WorkQueues:
        """
        Get the executive worker queues, their pending work items, and their
        worker threads (`!exqueue`). `include_stacks` adds the stack of each
        worker, and `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`)
        limits the listed items to the priorities of those types.
        """
    def zombies(self, /, *, flags: int = 1) -> Zombies:
        """
        List exited processes and threads that still have references.
        
        Scans nonpaged pool for process (`Proc`) and thread (`Thre`) objects, and
        finds the header of each object by its decoded type. The command lists
        the processes that have ExitTime set and the threads in the Terminated
        state. For each object, it shows the handle count and the pointer count:
        whatever still holds these references keeps the object in memory. Flag 1
        (the default) lists processes, 2 lists threads, and 3 lists both. The
        scan stops after 4096 processes or 4096 threads, or when you press
        Ctrl+C.
        """

class IoIntercepts(BaseRecord):
    """
    Which I/O instructions of a VTL exit (`!hvvmcs -io`), by its eVMCS's
    controls and I/O bitmaps: `never` (no I/O bitmaps and no
    unconditional I/O exiting), `every` (unconditional I/O exiting), or
    `bitmaps`.
    """
    @property
    def kind(self, /) -> Literal["never", "every", "bitmaps"]:
        """
        The variant: `never`, `every`, `bitmaps`.
        """
    @final
    class Bitmaps(IoIntercepts):
        """
        I/O bitmaps A (ports 0-0x7fff) and B: the port ranges whose
        accesses exit.
        """
        __match_args__: Final[tuple[Literal["ports"]]]
        @property
        def kind(self, /) -> Literal["bitmaps"]:
            """
            `bitmaps`.
            """
        @property
        def ports(self, /) -> list[PortRange]: ...
    @final
    class Every(IoIntercepts):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["every"]:
            """
            `every`.
            """
    @final
    class Never(IoIntercepts):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["never"]:
            """
            `never`.
            """

@final
class IoStackLocationInfo(BaseRecord):
    """
    An `_IO_STACK_LOCATION`, which is the part of an IRP for one driver.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["major_function"], Literal["minor_function"], Literal["flags"], Literal["control"], Literal["arguments"], Literal["device_object"], Literal["file_object"], Literal["completion_routine"], Literal["context"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def arguments(self, /) -> list[int]:
        """
        `Parameters.Others.Argument1` to `Argument4`: the first four
        words of the request's parameters, such as a read's length and
        offset or an IOCTL's buffer lengths and code.
        """
    @property
    def completion_routine(self, /) -> int:
        """
        The completion routine that the driver of the next location up
        set for when this location's driver completes the IRP.
        """
    @property
    def context(self, /) -> int:
        """
        The context argument of the completion routine.
        """
    @property
    def control(self, /) -> int:
        """
        `Control`: `SL_PENDING_RETURNED` (0x01) and when the completion
        routine runs, `SL_INVOKE_ON_CANCEL` (0x20), `SL_INVOKE_ON_SUCCESS`
        (0x40) and `SL_INVOKE_ON_ERROR` (0x80).
        """
    @property
    def device_object(self, /) -> int: ...
    @property
    def file_object(self, /) -> int: ...
    @property
    def flags(self, /) -> int:
        """
        `Flags`, the request's `SL_*` flags, such as
        `SL_OVERRIDE_VERIFY_VOLUME`.
        """
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
    @property
    def minor_function_name(self, /) -> str |None:
        """
        The name of the minor function (`IRP_MN_START_DEVICE`, ...), for
        Plug and Play, power, WMI, and SCSI requests.
        """

@final
class IoWorkItem(BaseRecord):
    """
    An `_IO_WORKITEM` that `IoQueueWorkItem` queued. Its work item runs
    `nt!IopProcessWorkItem`, which calls `routine`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["routine"], Literal["routine_symbol"], Literal["io_object"], Literal["context"]]]
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
class IpiField(BaseRecord):
    """
    A `_KPRCB` IPI field and its value.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["value"]]]
    @property
    def name(self, /) -> str: ...
    @property
    def value(self, /) -> Diagnostic[int]: ...

@final
class IpiProcessor(BaseRecord):
    """
    The IPI state of one processor.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["kprcb"], Literal["fields"], Literal["pending"], Literal["pending_truncated"], Literal["awaiting"]]]
    @property
    def awaiting(self, /) -> list[int]:
        """
        Processors whose pending list holds a request from this one.
        """
    @property
    def fields(self, /) -> list[IpiField]:
        """
        The IPI fields of [`IPI_FIELDS`] this build's `_KPRCB` has.
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
        Requests queued to this processor and not yet taken, in list order;
        unavailable on builds without per-sender mailboxes or when the list
        cannot be read.
        """
    @property
    def pending_truncated(self, /) -> bool:
        """
        Whether the pending walk stopped at its bound or a repeated mailbox.
        """
    @property
    def processor(self, /) -> int: ...

@final
class IpiRequest(BaseRecord):
    """
    A request that a sender put in the IPI mailbox list of a processor.
    """
    __match_args__: Final[tuple[Literal["mailbox"], Literal["sender"], Literal["request_summary"], Literal["worker_routine"], Literal["worker_symbol"], Literal["parameters"]]]
    @property
    def mailbox(self, /) -> int:
        """
        The `_REQUEST_MAILBOX` (the sender's slot in the receiver's
        `RequestMailbox` array).
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
        The type of the request summary, if the type is known.
        """
    @property
    def sender(self, /) -> int |None:
        """
        The sending processor, from the slot's index; `None` when the mailbox
        lies outside the receiver's array.
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
    __match_args__: Final[tuple[Literal["processors"], Literal["errors"]]]
    @property
    def errors(self, /) -> list[ProcessorError]: ...
    @property
    def processors(self, /) -> list[IpiProcessor]: ...

@final
class IrpDispatchRoutine(BaseRecord):
    """
    One slot in the `MajorFunction` dispatch table.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["routine"], Literal["symbol"]]]
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
    __match_args__: Final[tuple[Literal["name"], Literal["value"]]]
    @property
    def name(self, /) -> Literal["arg", "device", "fileobject", "mdlprocess", "thread", "userevent"]:
        """
        `arg`, `device`, `fileobject`, `mdlprocess`, `thread`, or
        `userevent`.
        """
    @property
    def value(self, /) -> int: ...

@final
class IrpFindDetail(BaseRecord):
    """
    One `!irpfind` pool scan.
    """
    __match_args__: Final[tuple[Literal["pool"], Literal["region_start"], Literal["region_end"], Literal["scan_start"], Literal["scanned_pages"], Literal["big_pool_status"], Literal["irps"], Literal["truncated"], Literal["interrupted"], Literal["restart"]]]
    @property
    def big_pool_status(self, /) -> str:
        """
        The result of the big-pool table scan.
        """
    @property
    def criteria(self, /) -> IrpFindCriteria |None:
        """
        The criteria the scan matched. None if the scan has no filter.
        """
    @property
    def interrupted(self, /) -> bool: ...
    @property
    def irps(self, /) -> list[IrpFindEntry]: ...
    @property
    def pool(self, /) -> Literal["nonpaged", "paged"]: ...
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
        check some big-pool allocations (`big_pool_status` counts them; no
        restart reaches those).
        """

@final
class IrpFindEntry(BaseRecord):
    """
    An IRP that `!irpfind` found in pool.
    """
    __match_args__: Final[tuple[Literal["irp"], Literal["pool_header"], Literal["tag"], Literal["original_file_object"], Literal["mdl_process"], Literal["driver"]]]
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
    def irp(self, /) -> IrpInfo: ...
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
class IrpHit(BaseRecord):
    """
    An in-flight IRP that ntoseye found on the `IrpList` of a thread or in the
    `CurrentIrp` of a device (`irps`).
    """
    __match_args__: Final[tuple[Literal["irp"], Literal["source"], Literal["stack_count"], Literal["current_location"], Literal["pid"], Literal["tid"], Literal["ethread"], Literal["state"], Literal["wait_reason"], Literal["driver"], Literal["device"]]]
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
    def source(self, /) -> Literal["thread", "device"]:
        """
        Where ntoseye found the IRP: `thread` or `device`.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def state(self, /) -> int |None:
        """
        The `_KTHREAD.State` of the thread. None if ntoseye found the IRP on a
        device.
        """
    @property
    def state_name(self, /) -> str |None:
        """
        The state name of the thread. None if ntoseye found the IRP on a device.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread that issued the IRP. None if ntoseye found the IRP on a device.
        """
    @property
    def wait_reason(self, /) -> int |None:
        """
        The `_KTHREAD.WaitReason` of the thread. None if ntoseye found the IRP
        on a device.
        """
    @property
    def wait_reason_name(self, /) -> str |None:
        """
        The wait-reason name of the thread. None if ntoseye found the IRP on a
        device.
        """

@final
class IrpHolder(BaseRecord):
    """
    Where an IRP is pending: the driver of its current stack location.
    """
    __match_args__: Final[tuple[Literal["location"], Literal["stack_count"], Literal["stack_location"], Literal["major_function"], Literal["minor_function"], Literal["state"], Literal["pending_returned"], Literal["device"], Literal["driver"]]]
    @property
    def device(self, /) -> int: ...
    @property
    def driver(self, /) -> Diagnostic[DeviceDriver]: ...
    @property
    def location(self, /) -> int:
        """
        `CurrentLocation`, counted from 1 as `!irp` does.
        """
    @property
    def major_function(self, /) -> int: ...
    @property
    def minor_function(self, /) -> int: ...
    @property
    def pending_returned(self, /) -> bool:
        """
        The location's driver returned `STATUS_PENDING` for it.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def stack_location(self, /) -> int: ...
    @property
    def state(self, /) -> PowerState |None:
        """
        The state that location's power request asks for.
        """

@final
class IrpInfo(BaseRecord):
    """
    An `_IRP` and its I/O stack locations (`!irp`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["type"], Literal["size"], Literal["stack_count"], Literal["current_location"], Literal["pending_returned"], Literal["requestor_mode"], Literal["io_status"], Literal["user_event"], Literal["user_buffer"], Literal["mdl_address"], Literal["system_buffer"], Literal["thread"], Literal["stack"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def current_location(self, /) -> int:
        """
        `CurrentLocation`, which is more than `stack_count` after the IRP
        completes.
        """
    @property
    def current_stack(self, /) -> IoStackLocationInfo |None:
        """
        The location that `CurrentLocation` names. None if the current
        location is out of range or ntoseye cannot read it.
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
    def stack(self, /) -> list[IoStackLocationInfo]:
        """
        Every stack location, from location 1 (the lowest driver's) to
        `stack_count`, ending early at one ntoseye cannot read; empty when
        `StackCount` is implausible.
        """
    @property
    def stack_count(self, /) -> int: ...
    @property
    def system_buffer(self, /) -> int:
        """
        `AssociatedIrp.SystemBuffer`, the copy of the data for buffered I/O.
        """
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
class Irql(BaseRecord):
    """
    The current IRQL of a processor (`!irql`).
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["value"], Literal["level_name"], Literal["note"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["job_id"], Literal["session_id"], Literal["accounting"], Literal["limits"], Literal["job_flags"], Literal["job_flag_names"], Literal["nesting_depth"], Literal["parent_job"], Literal["root_job"], Literal["child_jobs"], Literal["child_job_list_termination"], Literal["silo"], Literal["server_silo_globals"], Literal["processes"], Literal["unreadable_processes"], Literal["process_list_termination"]]]
    @property
    def accounting(self, /) -> JobAccounting: ...
    @property
    def address(self, /) -> int:
        """
        The `_EJOB`.
        """
    @property
    def child_job_list_termination(self, /) -> ListTermination: ...
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
    def process_list_termination(self, /) -> ListTermination: ...
    @property
    def processes(self, /) -> list[ProcessInfo]: ...
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
        True if the job is a silo (`JobFlags.Silo`).
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
    __match_args__: Final[tuple[Literal["total_user_time"], Literal["total_kernel_time"], Literal["total_cycle_time"], Literal["this_period_total_user_time"], Literal["this_period_total_kernel_time"], Literal["total_page_fault_count"], Literal["total_processes"], Literal["active_processes"], Literal["total_terminated_processes"], Literal["peak_process_memory_used"], Literal["peak_job_memory_used"], Literal["current_job_memory_used"]]]
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
    __match_args__: Final[tuple[Literal["limit_flags"], Literal["effective_limit_flags"], Literal["active_process_limit"], Literal["per_process_user_time_limit"], Literal["per_job_user_time_limit"], Literal["minimum_working_set_size"], Literal["maximum_working_set_size"], Literal["process_memory_limit"], Literal["job_memory_limit"], Literal["priority_class"], Literal["scheduling_class"], Literal["ui_restrictions_class"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["due_time"], Literal["period"], Literal["dpc_encoded"], Literal["dpc"], Literal["dpc_routine"], Literal["dpc_routine_symbol"]]]
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
class KmdfLogFinding(BaseRecord):
    """
    The client driver whose In-Flight Recorder log Wdf01000 copied into a
    crash dump, and how many records it holds (`!wdfkd.wdfcrashdump` shows
    them).
    """
    __match_args__: Final[tuple[Literal["driver"], Literal["records"]]]
    @property
    def driver(self, /) -> str: ...
    @property
    def records(self, /) -> int: ...

@final
class KtrapFrame(BaseRecord):
    """
    A decoded `_KTRAP_FRAME` (`.trap`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["frame"]]]
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

@final
class LargeAllocation(BaseRecord):
    """
    A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
    """
    __match_args__: Final[tuple[Literal["metadata"], Literal["address"], Literal["pages"], Literal["unused_bytes"], Literal["extra_present"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def extra_present(self, /) -> bool: ...
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
class LastError(BaseRecord):
    """
    A thread's Win32 last error and last NTSTATUS (`!gle`).
    """
    __match_args__: Final[tuple[Literal["teb"], Literal["last_error_value"], Literal["last_error_name"], Literal["last_status_value"], Literal["last_status_name"], Literal["teb32"]]]
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
    __match_args__: Final[tuple[Literal["teb"], Literal["last_error_value"], Literal["last_error_name"], Literal["last_status_value"], Literal["last_status_name"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["block_size"], Literal["block_count"], Literal["free_count"], Literal["bucket"], Literal["first_block"], Literal["bitmap"], Literal["blocks_per_word"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def bitmap(self, /) -> list[int]:
        """
        The `BlockBitmap` words (a qword on x64, a dword on x86), each
        holding `blocks_per_word` blocks: the low bit for a block is set
        while the block is busy.
        """
    @property
    def block_count(self, /) -> int: ...
    @property
    def block_size(self, /) -> int:
        """
        Bytes per block.
        """
    @property
    def blocks_per_word(self, /) -> int: ...
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

class ListTermination(BaseRecord):
    """
    The end condition of a guest linked-list walk.
    """
    @property
    def diagnostic(self, /) -> str |None:
        """
        Why the walk ended before the list head, if it did.
        """
    @property
    def kind(self, /) -> Literal["head", "null", "cycle", "bound", "corrupt"]:
        """
        The variant: `head`, `null`, `cycle`, `bound`, `corrupt`.
        """
    @final
    class Bound(ListTermination):
        """
        The walk reached its limit.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["bound"]:
            """
            `bound`.
            """
    @final
    class Corrupt(ListTermination):
        __match_args__: Final[tuple[Literal["error"]]]
        @property
        def error(self, /) -> str:
            """
            The problem with a corrupt link.
            """
        @property
        def kind(self, /) -> Literal["corrupt"]:
            """
            `corrupt`.
            """
    @final
    class Cycle(ListTermination):
        """
        A loop that does not go through the head.
        """
        __match_args__: Final[tuple[Literal["address"]]]
        @property
        def address(self, /) -> int:
            """
            The address where a cycle closed.
            """
        @property
        def kind(self, /) -> Literal["cycle"]:
            """
            `cycle`.
            """
    @final
    class Head(ListTermination):
        """
        The walk came back to the list head.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["head"]:
            """
            `head`.
            """
    @final
    class Null(ListTermination):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["null"]:
            """
            `null`.
            """

@final
class LoaderListHead(BaseRecord):
    """
    A `_PEB_LDR_DATA` list head.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["flink"], Literal["blink"]]]
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
    __match_args__: Final[tuple[Literal["in_load_order"], Literal["in_memory_order"], Literal["in_initialization_order"]]]
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
    __match_args__: Final[tuple[Literal["name"], Literal["short_name"], Literal["base_address"], Literal["size"], Literal["is_32bit"], Literal["entry_point"], Literal["time_date_stamp"], Literal["checksum"], Literal["file_version"], Literal["product_version"]]]
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
    The modules on a process's loader lists (`!dlls`), and how the native
    and WOW64 list walks ended.
    """
    __match_args__: Final[tuple[Literal["modules"], Literal["termination"], Literal["wow64_termination"]]]
    @property
    def modules(self, /) -> list[LoaderModule]: ...
    @property
    def termination(self, /) -> ListTermination: ...
    @property
    def wow64_termination(self, /) -> ListTermination |None:
        """
        `None` for a native process.
        """

@final
class LocalApic(BaseRecord):
    """
    A processor's local APIC (`!apic`), read through its x2APIC MSRs or
    its xAPIC registers.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["apic_base"], Literal["x2apic"], Literal["id"], Literal["version"], Literal["tpr"], Literal["ppr"], Literal["ldr"], Literal["svr"], Literal["esr"], Literal["icr"], Literal["lvt"], Literal["lvt_missing"], Literal["timer_initial"], Literal["timer_current"], Literal["timer_divide"], Literal["isr"], Literal["irr"], Literal["tmr"]]]
    @property
    def apic_base(self, /) -> int:
        """
        `IA32_APIC_BASE`.
        """
    @property
    def bootstrap_processor(self, /) -> bool: ...
    @property
    def enabled(self, /) -> bool: ...
    @property
    def esr(self, /) -> int |None:
        """
        `None` when the error status does not read.
        """
    @property
    def icr(self, /) -> ApicIcr: ...
    @property
    def id(self, /) -> int: ...
    @property
    def irr(self, /) -> list[int]: ...
    @property
    def isr(self, /) -> list[int]:
        """
        The vectors in service, requested, and level-triggered.
        """
    @property
    def ldr(self, /) -> int: ...
    @property
    def lvt(self, /) -> list[ApicLvt]:
        """
        The LVT entries the APIC implements, in [`LVT_NAMES`] order.
        """
    @property
    def lvt_missing(self, /) -> list[str]:
        """
        The ones it does not (the thermal or CMCI entry).
        """
    @property
    def ppr(self, /) -> int: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def software_enabled(self, /) -> bool: ...
    @property
    def svr(self, /) -> int:
        """
        The spurious-interrupt vector register.
        """
    @property
    def timer_current(self, /) -> int: ...
    @property
    def timer_divide(self, /) -> int:
        """
        The timer's divide configuration register.
        """
    @property
    def timer_divisor(self, /) -> int:
        """
        The divisor `timer_divide` selects.
        """
    @property
    def timer_initial(self, /) -> int: ...
    @property
    def tmr(self, /) -> list[int]: ...
    @property
    def tpr(self, /) -> int: ...
    @property
    def version(self, /) -> int: ...
    @property
    def x2apic(self, /) -> bool:
        """
        In x2APIC mode, read through MSRs; else through its registers.
        """

class LocalVariableLocation(BaseRecord):
    """
    The location of a local variable: `kind` is `register`,
    `register_relative`, `frame_relative`, or `unavailable`.
    """
    @property
    def kind(self, /) -> Literal["register", "register_relative", "frame_relative", "unavailable"]:
        """
        The variant: `register`, `register_relative`, `frame_relative`, `unavailable`.
        """
    @final
    class FrameRelative(LocalVariableLocation):
        """
        PDB frame-pointer-relative location without a safely decoded base register.
        """
        __match_args__: Final[tuple[Literal["offset"]]]
        @property
        def kind(self, /) -> Literal["frame_relative"]:
            """
            `frame_relative`.
            """
        @property
        def offset(self, /) -> int: ...
    @final
    class Register(LocalVariableLocation):
        """
        The variable's value is held directly in a register.
        """
        __match_args__: Final[tuple[Literal["register"]]]
        @property
        def kind(self, /) -> Literal["register"]:
            """
            `register`.
            """
        @property
        def register(self, /) -> str: ...
    @final
    class RegisterRelative(LocalVariableLocation):
        """
        The variable is stored in memory at register + signed offset.
        """
        __match_args__: Final[tuple[Literal["register"], Literal["offset"]]]
        @property
        def kind(self, /) -> Literal["register_relative"]:
            """
            `register_relative`.
            """
        @property
        def offset(self, /) -> int: ...
        @property
        def register(self, /) -> str: ...
    @final
    class Unavailable(LocalVariableLocation):
        """
        The PDB explicitly says the value is absent or uses an unsupported recipe.
        """
        __match_args__: Final[tuple[Literal["reason"]]]
        @property
        def kind(self, /) -> Literal["unavailable"]:
            """
            `unavailable`.
            """
        @property
        def reason(self, /) -> str: ...

@final
class LookasideDetail(BaseRecord):
    """
    A decoded `_GENERAL_LOOKASIDE` list (`!lookaside`). Each counter is
    read on its own, because stripped PDBs often omit some members.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["index"], Literal["tag"], Literal["size"], Literal["depth"], Literal["total_allocates"], Literal["total_frees"], Literal["allocate_misses"]]]
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
class LookasideListsDetail(BaseRecord):
    """
    The system lookaside lists (`!lookaside`).
    """
    __match_args__: Final[tuple[Literal["records"], Literal["nonpaged_count"], Literal["paged_count"], Literal["nonpaged_termination"], Literal["paged_termination"], Literal["interrupted"], Literal["truncated"]]]
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
    def records(self, /) -> list[LookasideDetail]: ...
    @property
    def truncated(self, /) -> bool:
        """
        Whether the walk stopped at its limit before the end.
        """

@final
class MdlDetail(BaseRecord):
    """
    A decoded `_MDL` header and the page-frame array that follows it
    (`!mdl`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["next"], Literal["size"], Literal["flags"], Literal["flag_names"], Literal["process"], Literal["mapped_system_va"], Literal["start_va"], Literal["byte_count"], Literal["byte_offset"], Literal["spanned_pages"], Literal["capacity"], Literal["pfn_array"], Literal["pfns"], Literal["truncated"]]]
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
        The number of pages that the described buffer spans
        (`ADDRESS_AND_SIZE_TO_SPAN_PAGES`).
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
    def describe(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> AddressDescription:
        """
        Describe what `address` belongs to (`!address <address>`): its kind (a
        kernel module, a user image, a kernel region, private or mapped user
        memory), the module or VAD that holds it, and its protection. On a
        user-mode minidump, `Debugger.user_dump.address_report(address)` reads
        the dump's memory-info list instead.
        """
    def disassemble(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, count: int) -> list[DisasmRow]:
        """
        Disassemble memory at a symbol or address.
        
        `L<count>` sets the number of instructions, 8 by default. If you give an
        end address, the command shows all instructions that start at or before
        that address. If you do not give an address, the command continues after
        the last instruction that the previous u showed. After the target runs or
        steps, or when you select another frame, thread, or process, it starts at
        the instruction pointer instead.
        """
    def disassemble_back(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, count: int) -> list[DisasmRow]:
        """
        Disassemble the instructions that end at an address.
        """
    def disassemble_function(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> FunctionDisassembly:
        """
        Disassemble the function that contains an address.
        
        The function's runtime function entry gives its extent. A leaf function
        has none, so uf reads it from its symbol for as far as its control flow
        reaches before the next symbol: it follows the branches inside the
        function, and treats a branch past the next symbol as a tail call.
        """
    @property
    def dtb(self, /) -> int:
        """
        The directory-table base that this space uses. A user-mode minidump
        has none, and raises `NtoseyeError`.
        """
    def function_entry(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> FunctionEntry:
        """
        Show the function table entry and unwind info of the function that
        contains an address.
        
        Shows the RUNTIME_FUNCTION that covers the address (the begin, end, and
        unwind info RVAs), then its unwind data. On AMD64, the unwind data is the
        UNWIND_INFO version, flags, prolog size, frame register, and frame offset,
        each unwind code with its operands, and the exception or termination
        handler. After a chained entry, .fnent shows the entry of each parent. On
        ARM64, it shows the fields of packed unwind data (flag, RegF, RegI, H, CR,
        frame size) and the prolog codes that they represent. For an .xdata
        record, it shows the header, the epilog scopes, each unwind code with the
        instruction that it undoes, and the exception handler. If a function table
        is paged out, .fnent reads it from the image file on disk.
        """
    def page_in(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> bool:
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
    def pte(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> PteWalk:
        """
        Show the page table entries for an address.
        """
    def ptov(self, /, physical: int) -> PtovDetail:
        """
        Find the virtual addresses in the current directory base that map a physical
        address.
        
        The command walks the page tables in reverse and detects cycles in them. The
        walk stops after 32 mappings or 65,536 table pages.
        """
    def read(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, n: int) -> bytes:
        """
        Read `n` bytes. A virtual read hides the breakpoint opcodes of this
        debugger.
        """
    def read_ansi_string(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, bits: int |None = None) -> str:
        """
        Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`). `bits`
        sets the layout, as in `read_unicode_string`.
        """
    def read_pointer(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int:
        """
        Read a pointer-sized value at `addr` (`poi`).
        """
    def read_string(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, max_len: int = 256) -> str:
        """
        Read a NUL-terminated ANSI string at `addr` (`da`).
        """
    def read_u16(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int:
        """
        Read a little-endian 16-bit integer.
        """
    def read_u32(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int:
        """
        Read a little-endian 32-bit integer.
        """
    def read_u64(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int:
        """
        Read a little-endian 64-bit integer.
        """
    def read_u8(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int:
        """
        Read a little-endian byte.
        """
    def read_unicode_string(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, bits: int |None = None) -> str:
        """
        Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`). `bits` sets
        the layout: 32 for the x86 descriptors of a WOW64 process and 64 for
        native descriptors. By default, the `.effmach` setting selects the
        layout.
        """
    def read_wstring(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, max_len: int = 256) -> str:
        """
        Read a NUL-terminated UTF-16 string at `addr` (`du`).
        """
    def search(self, /, pattern: bytes, start: int |str |Process |Thread |Module |Driver |Device |Heap, length: int) -> list[MemorySearchMatch]:
        """
        Find matches, including overlapping ones, with symbol/module/VAD
        context. In a virtual space, the search skips pages that it cannot read,
        the breakpoints of this session read as the code that they replaced, and
        the search returns a maximum of 4096 matches.
        """
    def translate(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> int |None:
        """
        Translate a virtual address with the page tables of this space (`!vtop`).
        """
    def translation(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> VtopDetail:
        """
        Get the page-table walk and the final translation of `addr` in this
        space's page tables (`!vtop` with this space's DTB). It works in every
        virtual space, VTL1 and roots outside NT included.
        """
    def write(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, data: bytes) -> None:
        """
        Write bytes to this address space.
        """
    def write_u16(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, value: int) -> None:
        """
        Write a little-endian 16-bit integer.
        """
    def write_u32(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, value: int) -> None:
        """
        Write a little-endian 32-bit integer.
        """
    def write_u64(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, value: int) -> None:
        """
        Write a little-endian 64-bit integer.
        """
    def write_u8(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap, value: int) -> None:
        """
        Write a little-endian byte.
        """

@final
class MemoryBasicInformation(BaseRecord):
    """
    The data that `VirtualQuery` reports for an address (`!vprot`). Each
    `MEM_*`/`PAGE_*` value has its name next to it.
    """
    __match_args__: Final[tuple[Literal["process"], Literal["address"], Literal["base_address"], Literal["allocation_base"], Literal["allocation_protect"], Literal["region_size"], Literal["state"], Literal["protect"], Literal["type"], Literal["vad"], Literal["truncated"]]]
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
    def process(self, /) -> ProcessInfo |None:
        """
        The process whose address space holds the address; `None` on a
        user-mode minidump, whose memory-info list gives the region.
        """
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
    def type(self, /) -> int:
        """
        The `MEM_*` type (`MEMORY_BASIC_INFORMATION.Type`).
        """
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
    `MINIDUMP_MEMORY_INFO`: one region of the address space, as
    `VirtualQueryEx` reported it.
    """
    __match_args__: Final[tuple[Literal["base"], Literal["allocation_base"], Literal["allocation_protect"], Literal["size"], Literal["state"], Literal["protect"], Literal["kind"]]]
    @property
    def allocation_base(self, /) -> int: ...
    @property
    def allocation_protect(self, /) -> int: ...
    @property
    def allocation_protect_name(self, /) -> str:
        """
        `allocation_protect` as `PAGE_*` names.
        """
    @property
    def base(self, /) -> int: ...
    @property
    def kind(self, /) -> int:
        """
        `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`, or 0 for a free region.
        """
    @property
    def kind_name(self, /) -> str:
        """
        `MEM_IMAGE`, `MEM_MAPPED`, or `MEM_PRIVATE`; empty for a free region.
        """
    @property
    def protect(self, /) -> int: ...
    @property
    def protect_name(self, /) -> str:
        """
        `protect` as `PAGE_*` names; empty for a free or reserved region.
        """
    @property
    def size(self, /) -> int: ...
    @property
    def state(self, /) -> int:
        """
        `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
        """
    @property
    def state_name(self, /) -> str:
        """
        `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
        """

@final
class MemoryRegionInfo(BaseRecord):
    """
    One VAD region of a process (`!vad`, `proc.regions` items, address
    context).
    """
    __match_args__: Final[tuple[Literal["node_address"], Literal["level"], Literal["start"], Literal["end"], Literal["private_memory"], Literal["commit_charge"], Literal["details"]]]
    @property
    def commit_charge(self, /) -> int |None:
        """
        The committed pages that are charged to the region.
        """
    @property
    def details(self, /) -> str |None:
        """
        A description: the mapped file.
        """
    @property
    def end(self, /) -> int:
        """
        The end of the region (exclusive).
        """
    @property
    def level(self, /) -> int:
        """
        The node's depth in the VAD tree.
        """
    @property
    def node_address(self, /) -> int:
        """
        The VAD's node in the process's VAD tree.
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
class MemorySearchMatch(BaseRecord):
    """
    A memory-search hit, with its symbol and location data.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["offset"], Literal["symbol"], Literal["kind"], Literal["module"], Literal["section"], Literal["va_type"], Literal["region"]]]
    @property
    def address(self, /) -> int:
        """
        The address of the match.
        """
    @property
    def kind(self, /) -> Literal["kernel_module", "user_image", "kernel_region", "private", "mapped", "unknown", "physical", "vtl1", "foreign"]:
        """
        The kind of address.
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
    def region(self, /) -> MemoryRegionInfo |None:
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
    def check_image(self, /, *, include_diffs: bool = False) -> ImageCheck:
        """
        Compare the executable sections of a module with the cached on-disk
        image.
        
        Compares the .text, PAGE*, and INIT executable sections after applying
        the DIR64/HIGHLOW relocations, and skips discardable and paged-out
        sections. The command counts known kernel self-patches separately:
        import optimization, retpoline, KiPatchSelf retargets, and the addresses
        of the kernel VA regions that the kernel moves at boot. With -nospec, the
        command does not show this breakdown and reports the self-patches as
        ordinary mismatches. -d prints byte diffs, up to a limit, and -v prints
        the results for each section.
        """
    @property
    def checksum(self, /) -> int |None: ...
    @property
    def end(self, /) -> int:
        """
        The address after the last byte of the image.
        """
    @property
    def entry_point(self, /) -> int |None: ...
    @property
    def exports(self, /) -> list[ModuleExportInfo]:
        """
        The exports from the mapped PE export directory.
        """
    def fetch_image(self, /) -> str:
        """
        Download the module's PE file into the symbol cache and return its path
        there (`.fetchimage`). The file is found by the TimeDateStamp and
        SizeOfImage values in the module's mapped PE header, the symbol-server
        key, so it is the same build that is running; a copy in a local
        directory on the symbol path is used before a symbol server.
        """
    @property
    def file_version(self, /) -> str |None:
        """
        The file version from the version resource of the image.
        """
    def headers(self, /, *, exports: bool = False, imports: bool = False) -> ImageHeaders:
        """
        Show the headers of a mapped PE image.
        
        The argument is a module name, an address, or an image base. A module name
        is `nt`, `hal`, `ntdll`, or the image name of the module, and ntoseye
        looks for it in the `.process` module list first, and then in the kernel
        module list. An address can be any address inside a loaded module. An
        image base can be the base of an image that no loader list contains, if
        that image starts with MZ. With no options, the command shows the file and
        section headers, as WinDbg does. -f: the file header, the optional header
        (entry point, image base, subsystem, DLL characteristics, stack and heap
        sizes), and the data directories (RVA and size). For the security
        directory, the value is a file offset. -s: the section table with decoded
        flags, and the debug directory with its CodeView PDB name, GUID, and age.
        -e: the export directory and all exports (ordinal, RVA, name or
        forwarder). -i: each import descriptor and its imports (hint and name or
        ordinal), with the address that the loader bound in the IAT. If a
        descriptor has no import name table, the command shows only the bound
        addresses, because its IAT no longer contains names. -a: all of these. You
        can combine options (`-fs`, `-f -i`). If ntoseye cannot read a directory,
        it shows the directory as unavailable and shows the other data. For
        example, the import table of a driver is in its INIT section, and Windows
        discards that section after load. The same applies to an import name or a
        module name that ntoseye cannot read. The command reads the headers from
        memory as they are mapped, so the values are the ones that the loader left
        there.
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
        Show the image identity, debug directory, and symbol state of a loaded
        module.
        
        The argument is a module name as for !dh (`nt`, `ntdll`, an image name),
        or any address inside the module. From the mapped headers, the command
        shows the base, image name and path, machine, time stamp, size, checksum,
        and characteristics. It also shows the debug directory with the CodeView
        PDB name, GUID, and age. Last, it shows whether symbols are loaded, where
        they come from, and the local PDB file.
        """
    @property
    def info(self, /) -> ModuleInfo:
        """
        The `ModuleInfo` record of this handle: its properties as one value.
        """
    def inspect(self, /) -> ModuleListing |LoaderModule:
        """
        The symbol status, load diagnostics, and PDB identity (`lmv`).
        """
    @property
    def is_32bit(self, /) -> bool:
        """
        From a WOW64 process's 32-bit loader list: x86 code, 4-byte pointers.
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
    def reload_symbols(self, /) -> ModuleSymbolLoadReport:
        """
        Force ntoseye to select the symbol source and index the symbols for one module.
        """
    @property
    def sections(self, /) -> list[Section]:
        """
        The PE sections and their mapped permissions.
        """
    @property
    def short_name(self, /) -> str:
        """
        The name without its extension, as `nt!` and `lm` name the module
        (`nt` for the kernel).
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
        The record (`info`) as a plain `dict`.
        """
    def verifier(self, /) -> VerifierDriver:
        """
        Get the verifier data for this driver module (`!verifier <module>`).
        """

@final
class ModuleEventPolicy(BaseRecord):
    """
    One module load or unload filter (`sx* ld[:<module>]` or
    `sx* ud[:<module>]`). Only `break` stops and only `notify` reports;
    `command` runs at a `break` stop.
    """
    __match_args__: Final[tuple[Literal["module"], Literal["mode"], Literal["command"]]]
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
    def mode(self, /) -> Literal["break", "second_chance", "notify", "ignore"]:
        """
        `break` stops at the event, and `notify` reports it.
        `second_chance` and `ignore` let the load or unload continue with
        no output.
        """
    @property
    def module(self, /) -> str |None:
        """
        The image-name glob that the filter matches (case-insensitive `*`
        and `?`), with or without extension. None for all modules (bare
        `ld` or `ud`).
        """

@final
class ModuleExportInfo(BaseRecord):
    """
    One PE export (`Module.exports`, `!dh -e`), recovered from a module's
    mapped export directory. An export has a name or only an ordinal, and a
    forwarder has no address.
    """
    __match_args__: Final[tuple[Literal["ordinal"], Literal["name"], Literal["rva"], Literal["address"], Literal["forwarder"]]]
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
        The RVA of the export. `None` for a forwarder.
        """

@final
class ModuleImageInfo(BaseRecord):
    """
    The image identity of a loaded module (`!lmi`): the file-header identity
    from its mapped headers, the debug directory, which includes the CodeView
    PDB name, GUID, and age, and the symbol state.
    """
    __match_args__: Final[tuple[Literal["info"], Literal["debug_directory"], Literal["symbols"], Literal["symbol_file"]]]
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
    def debug_directory(self, /) -> Diagnostic[list[DebugRecord]]: ...
    @property
    def info(self, /) -> ModuleInfo: ...
    @property
    def machine(self, /) -> int: ...
    @property
    def machine_name(self, /) -> str:
        """
        `X64`, `X86`, `ARM64`, ...
        """
    @property
    def size_of_image(self, /) -> int: ...
    @property
    def symbol_file(self, /) -> str |None:
        """
        The local PDB file, if a PDB is loaded.
        """
    @property
    def symbols(self, /) -> ModuleSymbols:
        """
        The symbol state, from the symbol store under the address space the
        module's symbols load in.
        """
    @property
    def time_date_stamp(self, /) -> int: ...

@final
class ModuleInfo(BaseRecord):
    """
    A loaded module (kernel or process image), as its loader list records it.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["short_name"], Literal["path"], Literal["base"], Literal["size"], Literal["is_32bit"], Literal["entry_point"], Literal["timestamp"], Literal["checksum"], Literal["file_version"], Literal["product_version"]]]
    @property
    def base(self, /) -> int:
        """
        The base address of the loaded image.
        """
    @property
    def checksum(self, /) -> int |None: ...
    @property
    def end(self, /) -> int:
        """
        The address after the last byte of the image.
        """
    @property
    def entry_point(self, /) -> int |None: ...
    @property
    def file_version(self, /) -> str |None:
        """
        The file version from the version resource of the image.
        """
    @property
    def is_32bit(self, /) -> bool:
        """
        From a WOW64 process's 32-bit loader list: x86 code, 4-byte pointers.
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
    @property
    def short_name(self, /) -> str:
        """
        The name without its extension, as `nt!` and `lm` name the module
        (`nt` for the kernel).
        """
    @property
    def size(self, /) -> int:
        """
        The size of the mapped image.
        """
    @property
    def timestamp(self, /) -> int |None:
        """
        The PE timestamp, if the loader record contains one.
        """

@final
class ModuleListing(BaseRecord):
    """
    A loaded module with its symbols' state (`lm`, a kernel module's
    `Module.inspect()`).
    """
    __match_args__: Final[tuple[Literal["info"], Literal["symbols"]]]
    @property
    def info(self, /) -> ModuleInfo: ...
    @property
    def symbols(self, /) -> ModuleSymbols: ...

@final
class ModuleSymbolDiagnostic(BaseRecord):
    """
    One problem that ntoseye found when it loaded the symbols of a module.
    """
    __match_args__: Final[tuple[Literal["module"], Literal["phase"], Literal["compiland"], Literal["message"]]]
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
class ModuleSymbolLoadReport(BaseRecord):
    """
    The result of a symbol reload. It counts the modules that loaded, had
    no PDB, were skipped, failed, or are still being fetched, and keeps the
    first diagnostics up to a limit.
    """
    __match_args__: Final[tuple[Literal["total"], Literal["loaded"], Literal["unloaded"], Literal["no_pdb"], Literal["skipped"], Literal["failed"], Literal["fetching"], Literal["diagnostic_count"], Literal["diagnostics"], Literal["breakpoint_error"]]]
    @property
    def breakpoint_error(self, /) -> str |None:
        """
        Why resolving the symbolic breakpoints again after the reload
        failed (`.reload`, `ld`); `None` if it did not fail or did not run.
        """
    @property
    def diagnostic_count(self, /) -> int:
        """
        The number of all diagnostics, including those after the limit of `diagnostics`.
        """
    @property
    def diagnostics(self, /) -> list[ModuleSymbolDiagnostic]: ...
    @property
    def failed(self, /) -> int: ...
    @property
    def fetching(self, /) -> int:
        """
        Handed to the background fetcher; not yet loaded or failed.
        """
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
class ModuleSymbols(BaseRecord):
    """
    The symbol status and PDB identity of a module (`lm v`, `Module.symbols`).
    """
    __match_args__: Final[tuple[()]]
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
    def status(self, /) -> Literal["loaded", "no_pdb", "skipped", "failed", "fetching", "unknown"]:
        """
        The symbol state of the module.
        """

@final
class Modules:
    """
    A collection of modules: `dbg.modules` (kernel), `proc.modules` (loader
    lists), or `dbg.secure_kernel.modules` (secure kernel), keyed by short
    name or by a `ModuleInfo` record (`stop.module`).
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: str |ModuleInfo, /) -> Module:
        """
        The module with a short name, ignoring case (`"nt"` is ntoskrnl),
        or the module loaded at the base of a `ModuleInfo` record
        (`stop.module`).
        """
    def __iter__(self, /) -> Iterator[Module]: ...
    def __len__(self, /) -> int: ...
    def at(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Module |None:
        """
        The module that contains `address`, or `None` if no module contains
        it.
        """
    def get(self, /, key: str |ModuleInfo) -> Module |None:
        """
        The module with a short name, ignoring case (`"nt"` is ntoskrnl),
        or the module loaded at the base of a `ModuleInfo` record
        (`stop.module`).
        """

class MsrIntercepts(BaseRecord):
    """
    Which RDMSRs and WRMSRs of a VTL exit (`!hvvmcs -msr`), by its eVMCS's
    controls and MSR bitmap. `kind` is `every` (the controls use no MSR
    bitmap: every RDMSR and WRMSR exits) or `bitmap`. MSRs outside the
    bitmap's 0x0-0x1fff and 0xc0000000-0xc0001fff always exit.
    """
    @property
    def every(self, /) -> bool:
        """
        Whether every RDMSR and WRMSR exits: the controls use no MSR
        bitmap.
        """
    @property
    def kind(self, /) -> Literal["every", "bitmap"]:
        """
        The variant: `every`, `bitmap`.
        """
    @property
    def read_without_exit(self, /) -> list[str]:
        """
        The MSRs ntoseye names that the VTL reads without an exit.
        """
    @property
    def write_without_exit(self, /) -> list[str]:
        """
        The MSRs ntoseye names that the VTL writes without an exit.
        """
    @final
    class Bitmap(MsrIntercepts):
        """
        The MSR bitmap at physical address `bitmap`, and the ranges of MSRs
        whose reads, and whose writes, exit.
        """
        __match_args__: Final[tuple[Literal["bitmap"], Literal["read"], Literal["write"]]]
        @property
        def bitmap(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["bitmap"]:
            """
            `bitmap`.
            """
        @property
        def read(self, /) -> list[MsrRange]: ...
        @property
        def write(self, /) -> list[MsrRange]: ...
    @final
    class Every(MsrIntercepts):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["every"]:
            """
            `every`.
            """

@final
class MsrRange(BaseRecord):
    """
    An inclusive range of MSRs whose accesses exit, with the architectural
    MSRs (or blocks, such as `x2APIC`) that ntoseye names in it.
    """
    __match_args__: Final[tuple[Literal["first"], Literal["last"]]]
    @property
    def first(self, /) -> int: ...
    @property
    def last(self, /) -> int: ...
    @property
    def names(self, /) -> list[str]:
        """
        The MSRs and blocks that ntoseye names in the range.
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
class NdisDriver(BaseRecord):
    """
    A miniport driver (`_NDIS_M_DRIVER_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["service_name"], Literal["image_name"], Literal["module"], Literal["driver_object"], Literal["ndis_version"], Literal["driver_version"], Literal["miniports"], Literal["miniports_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def driver_version(self, /) -> str |None:
        """
        The driver's own version, from its NDIS 6 characteristics.
        """
    @property
    def image_name(self, /) -> str: ...
    @property
    def miniports(self, /) -> list[int]:
        """
        The miniports on the driver's `MiniportQueue`.
        """
    @property
    def miniports_stopped(self, /) -> str |None: ...
    @property
    def module(self, /) -> str |None:
        """
        The loaded module the driver's code is in, the name its PDB's types
        go by.
        """
    @property
    def ndis_version(self, /) -> str:
        """
        The NDIS version it registered with (`6.50`).
        """
    @property
    def service_name(self, /) -> str: ...

@final
class NdisDriverList(BaseRecord):
    """
    The miniport drivers on `ndis!ndisMiniDriverList` (`!ndiskd.minidriver`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def drivers(self, /) -> list[NdisDriver]:
        """
        The drivers whose block reads.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the end of the list.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        The driver blocks that do not read.
        """

@final
class NdisFilter(BaseRecord):
    """
    A filter module on a miniport's stack (`_NDIS_FILTER_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["driver"], Literal["driver_image"], Literal["miniport"], Literal["miniport_name"], Literal["state"], Literal["context"], Literal["pending_oid"], Literal["pending_oid_error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def context(self, /) -> int:
        """
        `FilterModuleContext`, the filter driver's own context.
        """
    @property
    def driver(self, /) -> int:
        """
        The `_NDIS_FILTER_DRIVER_BLOCK`.
        """
    @property
    def driver_image(self, /) -> str |None:
        """
        The filter driver's `ImageName`.
        """
    @property
    def miniport(self, /) -> int:
        """
        The miniport the filter module is attached to.
        """
    @property
    def miniport_name(self, /) -> str |None:
        """
        That miniport's friendly name.
        """
    @property
    def name(self, /) -> str |None:
        """
        `FilterFriendlyName`.
        """
    @property
    def pending_oid(self, /) -> NdisOidRequest |None:
        """
        The OID request the filter has not completed.
        """
    @property
    def pending_oid_error(self, /) -> str |None:
        """
        Why `pending_oid` does not decode.
        """
    @property
    def state(self, /) -> str: ...

@final
class NdisFilterDetail(BaseRecord):
    """
    One filter module in detail (`!ndiskd.filter <address>`).
    """
    __match_args__: Final[tuple[Literal["filter"], Literal["listed"], Literal["driver_name"], Literal["higher"], Literal["lower"], Literal["media_connect"], Literal["xmit_link_speed"], Literal["rcv_link_speed"], Literal["if_index"], Literal["flags"], Literal["references"], Literal["dropped_receive_nbls"], Literal["dropped_send_nbls"], Literal["dropped_status_indications"]]]
    @property
    def driver_name(self, /) -> str |None:
        """
        The filter driver's friendly name.
        """
    @property
    def dropped_receive_nbls(self, /) -> int:
        """
        NBLs and status indications NDIS dropped because the filter was not
        running.
        """
    @property
    def dropped_send_nbls(self, /) -> int: ...
    @property
    def dropped_status_indications(self, /) -> int: ...
    @property
    def filter(self, /) -> NdisFilter: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def higher(self, /) -> int:
        """
        The filter modules above and below it on the miniport's stack; null
        at the top and at the bottom.
        """
    @property
    def if_index(self, /) -> int: ...
    @property
    def listed(self, /) -> bool:
        """
        Whether the filter is on `ndis!ndisGlobalFilterList`.
        """
    @property
    def lower(self, /) -> int: ...
    @property
    def media_connect(self, /) -> str:
        """
        The link the filter last saw indicated from below.
        """
    @property
    def rcv_link_speed(self, /) -> int: ...
    @property
    def references(self, /) -> int |None: ...
    @property
    def xmit_link_speed(self, /) -> int: ...

@final
class NdisFilterDriver(BaseRecord):
    """
    A filter driver (`_NDIS_FILTER_DRIVER_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["friendly_name"], Literal["unique_name"], Literal["service_name"], Literal["image_name"], Literal["module"], Literal["driver_object"], Literal["context"], Literal["flags"], Literal["ndis_version"], Literal["driver_version"], Literal["filters"], Literal["filters_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def context(self, /) -> int:
        """
        `FilterDriverContext`, the context the driver gave
        NdisFRegisterFilterDriver.
        """
    @property
    def driver_object(self, /) -> int: ...
    @property
    def driver_version(self, /) -> str: ...
    @property
    def filters(self, /) -> list[int]:
        """
        The filter modules on the driver's `FilterQueue`, one for each
        miniport it is attached to.
        """
    @property
    def filters_stopped(self, /) -> str |None: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def friendly_name(self, /) -> str:
        """
        `FriendlyName`, from the characteristics the driver registered.
        """
    @property
    def image_name(self, /) -> str: ...
    @property
    def module(self, /) -> str |None: ...
    @property
    def ndis_version(self, /) -> str: ...
    @property
    def service_name(self, /) -> str: ...
    @property
    def unique_name(self, /) -> str:
        """
        `UniqueName`, the filter's GUID.
        """

@final
class NdisFilterDriverDetail(BaseRecord):
    """
    A filter driver and its filter modules (`!ndiskd.filterdriver
    <address>`).
    """
    __match_args__: Final[tuple[Literal["driver"]]]
    @property
    def driver(self, /) -> NdisFilterDriver: ...
    @property
    def filters(self, /) -> list[NdisFilter]:
        """
        Its filter modules whose block reads.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        Its filter blocks that do not read.
        """

@final
class NdisFilterDriverList(BaseRecord):
    """
    The filter drivers on `ndis!ndisFilterDriverList`
    (`!ndiskd.filterdriver`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def drivers(self, /) -> list[NdisFilterDriver]:
        """
        The filter drivers whose block reads.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the end of the list.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        The driver blocks that do not read.
        """

@final
class NdisFilterList(BaseRecord):
    """
    The filter modules on `ndis!ndisGlobalFilterList` (`!ndiskd.filter`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def filters(self, /) -> list[NdisFilter]:
        """
        The filter modules whose block reads.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the end of the list.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        The filter blocks that do not read.
        """

@final
class NdisMinidriver(BaseRecord):
    """
    A miniport driver and its miniports (`!ndiskd.minidriver <address>`).
    """
    __match_args__: Final[tuple[Literal["driver"]]]
    @property
    def driver(self, /) -> NdisDriver: ...
    @property
    def miniports(self, /) -> list[NdisMiniport]:
        """
        Its miniports whose block reads.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        Its miniports whose block does not read.
        """

@final
class NdisMiniport(BaseRecord):
    """
    A miniport as `!ndiskd.miniports` lists it (`_NDIS_MINIPORT_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["friendly_name"], Literal["driver"], Literal["driver_name"], Literal["state"], Literal["pnp_state"], Literal["media_connect"], Literal["connected"], Literal["xmit_link_speed"], Literal["rcv_link_speed"], Literal["power"], Literal["if_index"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def connected(self, /) -> bool: ...
    @property
    def driver(self, /) -> int:
        """
        The `_NDIS_M_DRIVER_BLOCK`.
        """
    @property
    def driver_name(self, /) -> str |None:
        """
        The miniport driver's service name, from its `_NDIS_M_DRIVER_BLOCK`.
        """
    @property
    def friendly_name(self, /) -> str |None:
        """
        `pAdapterInstanceName`, the adapter's friendly name.
        """
    @property
    def if_index(self, /) -> int: ...
    @property
    def media_connect(self, /) -> str: ...
    @property
    def name(self, /) -> str:
        """
        `MiniportName`, the adapter's device name (its `{GUID}` in the
        `DEVICE` directory).
        """
    @property
    def pnp_state(self, /) -> str: ...
    @property
    def power(self, /) -> str:
        """
        The device power state (`D0`).
        """
    @property
    def rcv_link_speed(self, /) -> int: ...
    @property
    def state(self, /) -> str:
        """
        `Running`, `Pausing`, `Paused`, `Restarting`, `Initializing`, or
        `Halted`.
        """
    @property
    def xmit_link_speed(self, /) -> int:
        """
        Bits per second; `0xffffffffffffffff` when the miniport has not
        reported one.
        """

@final
class NdisMiniportDetail(BaseRecord):
    """
    One miniport in detail (`!ndiskd.miniport <address>`).
    """
    __match_args__: Final[tuple[Literal["miniport"], Literal["listed"], Literal["ndis_version"], Literal["adapter_context"], Literal["driver"], Literal["driver_error"], Literal["device_object"], Literal["pdo"], Literal["instance_id"], Literal["medium"], Literal["physical_medium"], Literal["duplex"], Literal["oper_status"], Literal["net_luid"], Literal["flags"], Literal["pnp_flags"], Literal["references"], Literal["reset_status"], Literal["internal_resets"], Literal["miniport_resets"], Literal["pending_oid"], Literal["pending_oid_error"], Literal["pending_return_nbls"], Literal["filters"], Literal["filters_stopped"], Literal["num_opens"], Literal["opens"], Literal["opens_stopped"]]]
    @property
    def adapter_context(self, /) -> int:
        """
        `MiniportAdapterContext`, the context the miniport driver gave
        NdisMSetMiniportAttributes.
        """
    @property
    def device_object(self, /) -> int:
        """
        The functional device object NDIS created; null for a virtual
        miniport.
        """
    @property
    def driver(self, /) -> NdisDriver |None: ...
    @property
    def driver_error(self, /) -> str |None:
        """
        Why `driver` is `None`.
        """
    @property
    def duplex(self, /) -> str: ...
    @property
    def filters(self, /) -> list[NdisFilter]:
        """
        The filter stack, top first.
        """
    @property
    def filters_stopped(self, /) -> str |None: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def instance_id(self, /) -> str |None: ...
    @property
    def internal_resets(self, /) -> int:
        """
        `InternalResetCount`.
        """
    @property
    def listed(self, /) -> bool:
        """
        Whether the miniport is on `ndis!ndisMiniportList`.
        """
    @property
    def medium(self, /) -> str: ...
    @property
    def miniport(self, /) -> NdisMiniport: ...
    @property
    def miniport_resets(self, /) -> int:
        """
        `MiniportResetCount`.
        """
    @property
    def ndis_version(self, /) -> str: ...
    @property
    def net_luid(self, /) -> int: ...
    @property
    def num_opens(self, /) -> int: ...
    @property
    def opens(self, /) -> list[NdisOpen]: ...
    @property
    def opens_stopped(self, /) -> str |None: ...
    @property
    def oper_status(self, /) -> str: ...
    @property
    def pdo(self, /) -> int: ...
    @property
    def pending_oid(self, /) -> NdisOidRequest |None:
        """
        The OID request the miniport has not completed.
        """
    @property
    def pending_oid_error(self, /) -> str |None:
        """
        Why `pending_oid` does not decode.
        """
    @property
    def pending_return_nbls(self, /) -> int:
        """
        `PendingReturnNBLCount`.
        """
    @property
    def physical_medium(self, /) -> str: ...
    @property
    def pnp_flags(self, /) -> int: ...
    @property
    def references(self, /) -> int |None: ...
    @property
    def reset_status(self, /) -> int:
        """
        `ResetStatus`, the NTSTATUS of the last reset.
        """

@final
class NdisMiniportList(BaseRecord):
    """
    The miniports on `ndis!ndisMiniportList` (`!ndiskd.miniports`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def miniports(self, /) -> list[NdisMiniport]:
        """
        The miniports whose block reads.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the end of the list.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        The miniports whose block does not read.
        """

@final
class NdisNbl(BaseRecord):
    """
    A `_NET_BUFFER_LIST` and its NET_BUFFERs (`!ndiskd.nbl`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["next"], Literal["parent"], Literal["context"], Literal["pool"], Literal["source_handle"], Literal["source"], Literal["flags"], Literal["nbl_flags"], Literal["child_ref_count"], Literal["status"], Literal["net_buffers"], Literal["net_buffers_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def child_ref_count(self, /) -> int: ...
    @property
    def context(self, /) -> int: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def nbl_flag_names(self, /) -> list[str]:
        """
        The `NDIS_NBL_FLAGS_*` names of `nbl_flags`, without the prefix.
        """
    @property
    def nbl_flags(self, /) -> int: ...
    @property
    def net_buffers(self, /) -> list[NdisNetBuffer]: ...
    @property
    def net_buffers_stopped(self, /) -> str |None: ...
    @property
    def next(self, /) -> int: ...
    @property
    def parent(self, /) -> int: ...
    @property
    def pool(self, /) -> int: ...
    @property
    def source(self, /) -> str |None:
        """
        What `source_handle` is, when it is a miniport, filter module, or
        binding NDIS knows.
        """
    @property
    def source_handle(self, /) -> int:
        """
        `SourceHandle`, the NDIS handle of the miniport, filter module, or
        binding that owns the NBL on its way.
        """
    @property
    def status(self, /) -> int:
        """
        `Status`, the NDIS_STATUS the NBL completes with.
        """
    @property
    def status_name(self, /) -> str |None:
        """
        The NTSTATUS name of `status`.
        """

@final
class NdisNblChain(BaseRecord):
    """
    The NBLs on a `Next` chain (`!ndiskd.nbl -chain`).
    """
    __match_args__: Final[tuple[Literal["nbls"], Literal["stopped"]]]
    @property
    def nbls(self, /) -> list[NdisNbl]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped short.
        """

@final
class NdisNetBuffer(BaseRecord):
    """
    A `_NET_BUFFER`: one frame of a NET_BUFFER_LIST.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["next"], Literal["current_mdl"], Literal["current_mdl_offset"], Literal["data_length"], Literal["data_offset"], Literal["mdl_chain"], Literal["data"], Literal["data_error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def current_mdl(self, /) -> int:
        """
        The MDL the data starts in, and where in it.
        """
    @property
    def current_mdl_offset(self, /) -> int: ...
    @property
    def data(self, /) -> bytes |None:
        """
        Its data, up to 64 KiB of it, read through the MDLs' PFNs, when
        asked for (`!ndiskd.nbl -data`).
        """
    @property
    def data_error(self, /) -> str |None:
        """
        Why the data asked for does not read.
        """
    @property
    def data_length(self, /) -> int: ...
    @property
    def data_offset(self, /) -> int:
        """
        Where the data starts from the start of `mdl_chain`; the bytes
        before it are the backfill.
        """
    @property
    def mdl_chain(self, /) -> int: ...
    @property
    def next(self, /) -> int: ...

@final
class NdisOidRequest(BaseRecord):
    """
    An `_NDIS_OID_REQUEST`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["request_type"], Literal["oid"], Literal["port"], Literal["timeout"], Literal["buffer"], Literal["buffer_length"], Literal["output_length"], Literal["method_id"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def buffer(self, /) -> int: ...
    @property
    def buffer_length(self, /) -> int:
        """
        `InformationBufferLength`, or a method request's `InputBufferLength`.
        """
    @property
    def method_id(self, /) -> int |None:
        """
        A method request's `MethodId`.
        """
    @property
    def oid(self, /) -> int: ...
    @property
    def oid_name(self, /) -> str |None:
        """
        The `ntddndis.h` name of the OID.
        """
    @property
    def output_length(self, /) -> int |None:
        """
        A method request's `OutputBufferLength`.
        """
    @property
    def port(self, /) -> int: ...
    @property
    def request_type(self, /) -> str:
        """
        `RequestType` without its `NdisRequest` prefix (`QueryInformation`,
        `SetInformation`, `Method`, ...).
        """
    @property
    def timeout(self, /) -> int:
        """
        `Timeout` in seconds; 0 lets NDIS pick one.
        """

@final
class NdisOpen(BaseRecord):
    """
    A protocol's binding to a miniport (`_NDIS_OPEN_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["protocol"], Literal["protocol_name"], Literal["context"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def context(self, /) -> int:
        """
        `ProtocolBindingContext`, the protocol driver's own context.
        """
    @property
    def protocol(self, /) -> int:
        """
        The `_NDIS_PROTOCOL_BLOCK`.
        """
    @property
    def protocol_name(self, /) -> str |None: ...

@final
class NdisPendingOid(BaseRecord):
    """
    An OID request a miniport or filter module has not completed.
    """
    __match_args__: Final[tuple[Literal["owner"], Literal["address"], Literal["name"], Literal["request"], Literal["error"]]]
    @property
    def address(self, /) -> int:
        """
        The miniport or filter block.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why `request` does not decode.
        """
    @property
    def name(self, /) -> str |None:
        """
        The miniport's friendly name, or the filter module's.
        """
    @property
    def owner(self, /) -> Literal["miniport", "filter"]: ...
    @property
    def request(self, /) -> NdisOidRequest |None: ...

@final
class NdisPendingOids(BaseRecord):
    """
    The pending OID requests of every miniport and filter module
    (`!ndiskd.oid`).
    """
    __match_args__: Final[tuple[Literal["pending"], Literal["miniports"], Literal["filters"], Literal["problems"]]]
    @property
    def filters(self, /) -> int: ...
    @property
    def miniports(self, /) -> int:
        """
        How many miniports and filter modules were checked.
        """
    @property
    def pending(self, /) -> list[NdisPendingOid]: ...
    @property
    def problems(self, /) -> list[str]:
        """
        Why a walk stopped short, or a block that did not read.
        """

@final
class NdisProtocol(BaseRecord):
    """
    A protocol driver (`_NDIS_PROTOCOL_BLOCK`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["name"], Literal["image_name"], Literal["ndis_version"], Literal["driver_version"], Literal["context"], Literal["flags"], Literal["bind_handler"], Literal["opens"], Literal["opens_stopped"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def bind_handler(self, /) -> int:
        """
        `BindAdapterHandlerEx`, which places the protocol's code.
        """
    @property
    def context(self, /) -> int:
        """
        `ProtocolDriverContext`, the context the driver gave
        NdisRegisterProtocolDriver.
        """
    @property
    def driver_version(self, /) -> str: ...
    @property
    def flags(self, /) -> int: ...
    @property
    def image_name(self, /) -> str |None: ...
    @property
    def name(self, /) -> str: ...
    @property
    def ndis_version(self, /) -> str: ...
    @property
    def opens(self, /) -> list[int]:
        """
        Its bindings (`_NDIS_OPEN_BLOCK`) on its `OpenQueue`, along
        `ProtocolNextOpen`.
        """
    @property
    def opens_stopped(self, /) -> str |None: ...

@final
class NdisProtocolBinding(BaseRecord):
    """
    A protocol's binding as the protocol sees it: the miniport it opened.
    """
    __match_args__: Final[tuple[Literal["open"], Literal["miniport"], Literal["miniport_name"], Literal["context"]]]
    @property
    def context(self, /) -> int:
        """
        `ProtocolBindingContext`, the protocol's own context for the binding.
        """
    @property
    def miniport(self, /) -> int: ...
    @property
    def miniport_name(self, /) -> str |None: ...
    @property
    def open(self, /) -> int:
        """
        The `_NDIS_OPEN_BLOCK`.
        """

@final
class NdisProtocolDetail(BaseRecord):
    """
    One protocol driver in detail (`!ndiskd.protocol <address>`).
    """
    __match_args__: Final[tuple[Literal["protocol"], Literal["listed"], Literal["bind_handler_name"], Literal["bindings"], Literal["bindings_stopped"]]]
    @property
    def bind_handler_name(self, /) -> str |None:
        """
        `BindAdapterHandlerEx` as a symbol.
        """
    @property
    def bindings(self, /) -> list[NdisProtocolBinding]: ...
    @property
    def bindings_stopped(self, /) -> str |None:
        """
        Why the binding walk stopped short.
        """
    @property
    def listed(self, /) -> bool:
        """
        Whether the protocol is on `ndis!ndisProtocolList`.
        """
    @property
    def protocol(self, /) -> NdisProtocol: ...

@final
class NdisProtocolList(BaseRecord):
    """
    The protocol drivers on `ndis!ndisProtocolList` (`!ndiskd.protocol`).
    """
    __match_args__: Final[tuple[Literal["stopped"]]]
    @property
    def protocols(self, /) -> list[NdisProtocol]:
        """
        The protocols whose block reads.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped before the end of the list.
        """
    @property
    def unreadable(self, /) -> list[NdisUnreadable]:
        """
        The protocol blocks that do not read.
        """

@final
class NdisUnreadable(BaseRecord):
    """
    A block a list names but that does not read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def error(self, /) -> str: ...

@final
class Notice(BaseRecord):
    """
    Something the debugger reported beside a command's result.
    """
    __match_args__: Final[tuple[Literal["level"], Literal["text"]]]
    @property
    def level(self, /) -> Literal["info", "warning"]:
        """
        `"info"` for status, such as a background symbol fetch
        finishing or a `ModLoad:` line of an `sxn ld` filter, or
        `"warning"` for something that did not work as it should, such as
        a breakpoint that failed to re-arm.
        """
    @property
    def text(self, /) -> str: ...

@final
class NotifyCallback(BaseRecord):
    """
    A process, thread, or image notification callback (`callbacks`).
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["index"], Literal["function"], Literal["symbol"], Literal["block"], Literal["raw"], Literal["context"]]]
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
    def kind(self, /) -> Literal["process", "thread", "image"]:
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
class NtEntry(BaseRecord):
    """
    An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["size"], Literal["previous_size"], Literal["flags"], Literal["unused_bytes"], Literal["granule"], Literal["checksum_ok"]]]
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
        The header size in bytes (see [`NtHeap::granule`]).
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
    def state(self, /) -> Literal["busy", "free"]:
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
class NtEntryDetail(BaseRecord):
    """
    An NT-heap entry with the legacy-LFH region it holds.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["lfh"], Literal["lfh_blocks"], Literal["lfh_truncated"], Literal["lfh_error"]]]
    @property
    def header(self, /) -> NtEntry: ...
    @property
    def lfh(self, /) -> NtUserBlocks |None:
        """
        The legacy-LFH user block region in this busy entry. `None` if the
        entry has no region or ntoseye cannot read it.
        """
    @property
    def lfh_blocks(self, /) -> list[HeapBlock]:
        """
        The blocks of the region.
        """
    @property
    def lfh_error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the LFH region of the entry.
        """
    @property
    def lfh_truncated(self, /) -> bool:
        """
        Whether `lfh_blocks` stops at the walk limit.
        """

@final
class NtHeap(BaseRecord):
    """
    An NT (`_HEAP`) heap.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["flags"], Literal["force_flags"], Literal["granule"], Literal["encoding"], Literal["total_free_units"], Literal["virtual_threshold"], Literal["front_end"], Literal["front_end_type"], Literal["virtual_blocks"]]]
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
        x64 (a private-data qword, then the metadata qword), 8 on x86 (the
        metadata qword alone). Block sizes are in this unit.
        """
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
class NtHeapDetail(BaseRecord):
    """
    An NT heap with its segments.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["segments"]]]
    @property
    def header(self, /) -> NtHeap: ...
    @property
    def segments(self, /) -> list[NtSegmentDetail]: ...

@final
class NtSegment(BaseRecord):
    """
    One `_HEAP_SEGMENT` of an NT heap.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["base"], Literal["pages"], Literal["uncommitted_pages"], Literal["first_entry"], Literal["last_valid_entry"], Literal["uncommitted"]]]
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
    def first_entry(self, /) -> int: ...
    @property
    def last_valid_entry(self, /) -> int: ...
    @property
    def pages(self, /) -> int: ...
    @property
    def uncommitted(self, /) -> list[NtUncommittedRange]:
        """
        The uncommitted ranges that the entry chain skips.
        """
    @property
    def uncommitted_pages(self, /) -> int: ...

@final
class NtSegmentDetail(BaseRecord):
    """
    An NT-heap segment with its entry chain.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["entries"], Literal["stopped"]]]
    @property
    def entries(self, /) -> list[NtEntryDetail]:
        """
        The entry chain of the segment. Empty unless the entries were listed.
        """
    @property
    def header(self, /) -> NtSegment: ...
    @property
    def stopped(self, /) -> HeapWalkStop |None:
        """
        Where the chain walk stopped before `last_valid_entry`, and why. None
        if the walk did not stop before `last_valid_entry`.
        """

@final
class NtUncommittedRange(BaseRecord):
    """
    An uncommitted range of an NT-heap segment.
    """
    __match_args__: Final[tuple[Literal["start"], Literal["end"]]]
    @property
    def end(self, /) -> int:
        """
        The first byte after the range.
        """
    @property
    def start(self, /) -> int: ...

@final
class NtUserBlocks(BaseRecord):
    """
    A legacy-LFH user block region in one busy NT-heap entry.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["subsegment"], Literal["block_size"], Literal["block_count"], Literal["first_block"], Literal["stride"], Literal["busy"]]]
    @property
    def block_count(self, /) -> int: ...
    @property
    def block_size(self, /) -> int:
        """
        Bytes per block.
        """
    @property
    def busy(self, /) -> bytes:
        """
        One bit for each block, set if the block is busy (`_RTL_BITMAP` bit
        order: block `i` is byte `i / 8`, bit `i % 8`).
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
class NtVirtualBlock(BaseRecord):
    """
    An NT-heap block with a separate allocation (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
    """
    __match_args__: Final[tuple[Literal["entry"], Literal["commit_size"], Literal["reserve_size"], Literal["user"]]]
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
    def reserve_size(self, /) -> int:
        """
        Reserved bytes.
        """
    @property
    def user(self, /) -> int:
        """
        First user byte: the header's `BusyBlock` is the last thing before
        it.
        """

@final
class NtfsRecord(BaseRecord):
    """
    One NTFS blackbox record.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["length"], Literal["irp"], Literal["scb"], Literal["thread"], Literal["break_reason"], Literal["owner_process_name"], Literal["breaking_process_name"]]]
    @property
    def break_reason(self, /) -> int |None:
        """
        An oplock break's reason: `1` `NtfsFsdSetInformation` to `5`
        `NtfsFsdWrite`.
        """
    @property
    def breaking_process_name(self, /) -> str |None: ...
    @property
    def irp(self, /) -> int: ...
    @property
    def kind(self, /) -> int:
        """
        `1` slow I/O timeout, `2` oplock break timeout.
        """
    @property
    def length(self, /) -> int: ...
    @property
    def owner_process_name(self, /) -> str |None: ...
    @property
    def scb(self, /) -> int: ...
    @property
    def thread(self, /) -> int |None:
        """
        A slow I/O timeout's waiting thread.
        """

@final
class ObjectDetail(BaseRecord):
    """
    An executive object with its header, type, and name, and the entries of
    a directory (`!object`).
    """
    __match_args__: Final[tuple[Literal["info"], Literal["entries"]]]
    @property
    def entries(self, /) -> list[ObjectDirectoryEntry] |None:
        """
        The entries of a directory, by name. None for all other objects.
        """
    @property
    def info(self, /) -> ObjectHeaderDetail: ...

@final
class ObjectDirectoryEntry(BaseRecord):
    """
    A named object in an object directory.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["object"], Literal["type"]]]
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
class ObjectHeaderDetail(BaseRecord):
    """
    An executive object's `_OBJECT_HEADER`, type, and name.
    """
    __match_args__: Final[tuple[Literal["input"], Literal["mode"], Literal["header"], Literal["body"], Literal["pointer_count"], Literal["handle_count"], Literal["type_index"], Literal["type_object"], Literal["type_name"], Literal["info_mask"], Literal["name_info"], Literal["name"]]]
    @property
    def body(self, /) -> int: ...
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
    def mode(self, /) -> Literal["body", "header"]:
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
class ObjectSecurity(BaseRecord):
    """
    The security descriptor of an object, from its header (`!objsd`).
    """
    __match_args__: Final[tuple[Literal["object"], Literal["header"], Literal["fast_reference"], Literal["descriptor_address"], Literal["descriptor"]]]
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
class OptionalHeader(BaseRecord):
    """
    `IMAGE_OPTIONAL_HEADER32`/`64` (PE32 or PE32+), widened to one shape.
    `base_of_data` exists only in the 32-bit header.
    """
    __match_args__: Final[tuple[Literal["magic"], Literal["size_of_code"], Literal["size_of_initialized_data"], Literal["size_of_uninitialized_data"], Literal["entry_point_rva"], Literal["base_of_code"], Literal["base_of_data"], Literal["image_base"], Literal["section_alignment"], Literal["file_alignment"], Literal["win32_version_value"], Literal["size_of_image"], Literal["size_of_headers"], Literal["checksum"], Literal["subsystem"], Literal["dll_characteristics"], Literal["size_of_stack_reserve"], Literal["size_of_stack_commit"], Literal["size_of_heap_reserve"], Literal["size_of_heap_commit"], Literal["loader_flags"], Literal["number_of_rva_and_sizes"]]]
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
    def entry_point_rva(self, /) -> int:
        """
        The RVA of the entry point; 0 if the image has none.
        """
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
class PackedQueueState(BaseRecord):
    """
    What the driver keeps of a packed queue.
    """
    __match_args__: Final[tuple[Literal["free"], Literal["last_used"], Literal["used_wrap"], Literal["next_avail"], Literal["avail_wrap"], Literal["desc"], Literal["desc_state"], Literal["driver_event"], Literal["device_event"], Literal["interrupts"], Literal["notifications"]]]
    @property
    def avail_wrap(self, /) -> bool: ...
    @property
    def desc(self, /) -> int:
        """
        The descriptor ring.
        """
    @property
    def desc_state(self, /) -> int:
        """
        The driver's per-buffer state (`desc_state`), by buffer ID.
        """
    @property
    def device_event(self, /) -> int: ...
    @property
    def driver_event(self, /) -> int:
        """
        The driver's and the device's event suppression structures.
        """
    @property
    def free(self, /) -> int:
        """
        `num_free`: free descriptors.
        """
    @property
    def interrupts(self, /) -> Signal:
        """
        When the driver wants interrupts, from its event suppression
        structure, and when the device wants notifications, from its own.
        """
    @property
    def last_used(self, /) -> int:
        """
        `last_used_idx`: the position where the driver takes used buffers
        back next, in the lap `used_wrap` names.
        """
    @property
    def next_avail(self, /) -> int:
        """
        `next_avail_idx`: the position the driver fills next, in the lap
        `avail_wrap` names.
        """
    @property
    def notifications(self, /) -> Signal: ...
    @property
    def used_wrap(self, /) -> bool: ...

@final
class PackedRing(BaseRecord):
    """
    A packed ring as guest memory holds it, read from the driver's last
    used position.
    """
    __match_args__: Final[tuple[Literal["returned"], Literal["with_device"], Literal["broken"]]]
    @property
    def broken(self, /) -> str |None:
        """
        Why the walk stopped before the driver's count of descriptors in
        flight.
        """
    @property
    def returned(self, /) -> int:
        """
        Buffers the device used that the driver has not taken back.
        """
    @property
    def with_device(self, /) -> int:
        """
        How many buffers the device holds.
        """

@final
class PageLocation(BaseRecord):
    """
    The `PageLocation` of a PFN, which is the list that holds the page.
    """
    __match_args__: Final[tuple[Literal["value"]]]
    @property
    def name(self, /) -> str:
        """
        The `_MMLISTS` name (`ActiveAndValid`, `StandbyPageList`, ...).
        """
    @property
    def value(self, /) -> int: ...

@final
class PageRange(BaseRecord):
    """
    A page range (`_HEAP_PAGE_RANGE_DESCRIPTOR`) of a page segment.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["units"], Literal["unit_size"], Literal["flags"], Literal["committed_pages"], Literal["unused_bytes"], Literal["kind"]]]
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
    def flags(self, /) -> int:
        """
        The descriptor's `RangeFlags`.
        """
    @property
    def kind(self, /) -> Literal["unused", "free", "page", "vs", "lfh"]: ...
    @property
    def size(self, /) -> int:
        """
        The size in bytes: `units * unit_size`.
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
class PageSegment(BaseRecord):
    """
    A page segment (`_HEAP_PAGE_SEGMENT`) of a segment context.
    """
    __match_args__: Final[tuple[Literal["address"]]]
    @property
    def address(self, /) -> int: ...

@final
class PartitionFilter(BaseRecord):
    """
    A partition breakpoint's filter: the guest partition of the Windows
    hypervisor (a Windows Sandbox, a Hyper-V VM) a hit must be on, and the VP
    index in it, if restricted.
    
    The breakpoint is a debug register of the target's processors, which
    traps whatever code a processor runs at its address: the partition's, or
    another partition's or the target's own mapped there. Which VP ran it is
    known only once the hit arrives, from the processor's current VP.
    """
    __match_args__: Final[tuple[Literal["id"], Literal["vp"]]]
    @property
    def id(self, /) -> int:
        """
        The partition ID.
        """
    @property
    def vp(self, /) -> int |None:
        """
        The VP index a hit must be on (`/c` in the view). None for any of
        the partition's VPs.
        """

@final
class PciBar(BaseRecord):
    """
    A base address register: its index, the raw register (both halves of a
    64-bit BAR), and the address it decodes to.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["raw"], Literal["kind"], Literal["address"], Literal["prefetchable"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def index(self, /) -> int:
        """
        The BAR number (0-5).
        """
    @property
    def kind(self, /) -> Literal["io", "mem32", "mem1m", "mem64"]: ...
    @property
    def prefetchable(self, /) -> bool: ...
    @property
    def raw(self, /) -> int: ...

@final
class PciBuses(BaseRecord):
    """
    The bus numbers of a type 1 or type 2 header.
    """
    __match_args__: Final[tuple[Literal["primary"], Literal["secondary"], Literal["subordinate"]]]
    @property
    def primary(self, /) -> int: ...
    @property
    def secondary(self, /) -> int: ...
    @property
    def subordinate(self, /) -> int: ...

@final
class PciCapability(BaseRecord):
    """
    A capability-list entry: its offset, ID, and (extended capabilities) the
    version.
    """
    __match_args__: Final[tuple[Literal["offset"], Literal["id"], Literal["version"]]]
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
        The version of an extended capability. `None` for a standard one.
        """

@final
class PciFunction(BaseRecord):
    """
    A function's configuration space as read (256 bytes, or 4 KiB with
    extended space), with where it is and its decoded header.
    """
    __match_args__: Final[tuple[Literal["segment"], Literal["bus"], Literal["device"], Literal["function"], Literal["header"], Literal["config"]]]
    @property
    def bus(self, /) -> int: ...
    @property
    def capabilities(self, /) -> list[PciCapability]:
        """
        The capability list.
        """
    @property
    def class_name(self, /) -> str |None:
        """
        The name of the class code, if it is known.
        """
    @property
    def config(self, /) -> bytes:
        """
        The configuration space as read.
        """
    @property
    def device(self, /) -> int: ...
    @property
    def extended_capabilities(self, /) -> list[PciCapability]:
        """
        The PCI Express extended capabilities. Empty for a conventional
        function, or if only 256 bytes were read.
        """
    @property
    def function(self, /) -> int: ...
    @property
    def header(self, /) -> PciHeader: ...
    @property
    def segment(self, /) -> int: ...

@final
class PciHeader(BaseRecord):
    """
    The decoded type 0/1/2 configuration header.
    """
    __match_args__: Final[tuple[Literal["vendor_id"], Literal["device_id"], Literal["command"], Literal["status"], Literal["revision"], Literal["prog_if"], Literal["sub_class"], Literal["base_class"], Literal["cache_line_size"], Literal["latency_timer"], Literal["header_type"], Literal["bist"], Literal["bars"], Literal["expansion_rom"], Literal["capabilities_pointer"], Literal["interrupt_line"], Literal["interrupt_pin"]]]
    @property
    def bars(self, /) -> list[PciBar]: ...
    @property
    def base_class(self, /) -> int: ...
    @property
    def bist(self, /) -> int: ...
    @property
    def buses(self, /) -> PciBuses |None:
        """
        Type 1 and 2 headers only.
        """
    @property
    def cache_line_size(self, /) -> int: ...
    @property
    def capabilities_pointer(self, /) -> int: ...
    @property
    def command(self, /) -> int: ...
    @property
    def command_flags(self, /) -> list[str]:
        """
        The names of the bits that are set in the command register.
        """
    @property
    def device_id(self, /) -> int: ...
    @property
    def expansion_rom(self, /) -> int |None:
        """
        Expansion ROM base register (type 0 at 0x30, type 1 at 0x38).
        """
    @property
    def header_type(self, /) -> int:
        """
        Layout in the low 7 bits; bit 7 marks a multi-function device.
        """
    @property
    def interrupt_line(self, /) -> int: ...
    @property
    def interrupt_pin(self, /) -> int:
        """
        0 for none, 1-4 for INTA#-INTD#.
        """
    @property
    def latency_timer(self, /) -> int: ...
    @property
    def multifunction(self, /) -> bool: ...
    @property
    def prog_if(self, /) -> int: ...
    @property
    def revision(self, /) -> int: ...
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
class PciRecord(BaseRecord):
    """
    One function's configuration header as pci.sys recorded it.
    """
    __match_args__: Final[tuple[Literal["bus"], Literal["device"], Literal["function"], Literal["vendor_id"], Literal["device_id"], Literal["command"], Literal["status"], Literal["revision"]]]
    @property
    def bus(self, /) -> int: ...
    @property
    def command(self, /) -> int: ...
    @property
    def device(self, /) -> int: ...
    @property
    def device_id(self, /) -> int: ...
    @property
    def function(self, /) -> int: ...
    @property
    def revision(self, /) -> int: ...
    @property
    def status(self, /) -> int: ...
    @property
    def vendor_id(self, /) -> int: ...

@final
class PciScan(BaseRecord):
    """
    The functions that a `!pci` scan found.
    """
    __match_args__: Final[tuple[Literal["functions"], Literal["interrupted"]]]
    @property
    def functions(self, /) -> list[PciFunction]: ...
    @property
    def interrupted(self, /) -> bool:
        """
        The scan stopped at a host interrupt.
        """

@final
class PciTree(BaseRecord):
    """
    pci.sys's view of the hierarchy: segments, their root buses, and each
    bus's functions and child buses (`!pcitree`).
    """
    __match_args__: Final[tuple[Literal["segments"], Literal["truncated"], Literal["errors"]]]
    @property
    def errors(self, /) -> list[str]:
        """
        Each bus or function that could not be read, and why; the walk
        skipped the rest of the list it was on.
        """
    @property
    def segments(self, /) -> list[PciTreeSegment]: ...
    @property
    def truncated(self, /) -> bool:
        """
        The walk stopped at [`MAX_TREE_NODES`] or a nesting/link limit.
        """

@final
class PciTreeBus(BaseRecord):
    """
    A bus that pci.sys enumerated, with the devices on it and the buses
    behind its bridges.
    """
    __match_args__: Final[tuple[Literal["extension"], Literal["number"], Literal["subordinate"], Literal["bridge_pdo"], Literal["devices"], Literal["child_buses"]]]
    @property
    def bridge_pdo(self, /) -> int:
        """
        The PDO of the bridge that produces this bus (the root bus's comes
        from ACPI).
        """
    @property
    def child_buses(self, /) -> list[PciTreeBus]: ...
    @property
    def devices(self, /) -> list[PciTreeDevice]: ...
    @property
    def extension(self, /) -> int:
        """
        The bus FDO's extension (`pci!_PCI_BUS`).
        """
    @property
    def number(self, /) -> int: ...
    @property
    def subordinate(self, /) -> int: ...

@final
class PciTreeDevice(BaseRecord):
    """
    A device that pci.sys enumerated.
    """
    __match_args__: Final[tuple[Literal["extension"], Literal["device_object"], Literal["bus"], Literal["device"], Literal["function"], Literal["vendor_id"], Literal["device_id"], Literal["revision"], Literal["base_class"], Literal["sub_class"], Literal["prog_if"], Literal["subsystem_vendor_id"], Literal["subsystem_id"], Literal["header_type"], Literal["instance_path"]]]
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
    def device_object(self, /) -> int:
        """
        The PDO, bottom of the function's device stack.
        """
    @property
    def extension(self, /) -> int:
        """
        The function PDO's extension (`pci!_PCI_DEVICE`).
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
class PciTreeSegment(BaseRecord):
    """
    A PCI segment and its root buses.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["number"], Literal["root_buses"]]]
    @property
    def address(self, /) -> int:
        """
        The `pci!_PCI_SEGMENT`.
        """
    @property
    def number(self, /) -> int: ...
    @property
    def root_buses(self, /) -> list[PciTreeBus]: ...

@final
class Pcr(BaseRecord):
    """
    The main KPCR and KPRCB data of a processor (`!pcr`). A field is a
    diagnostic if its read can fail separately from the other reads.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["kpcr"], Literal["kprcb"], Literal["kd_version_block"], Literal["current_prcb"], Literal["irql"], Literal["self_pcr"], Literal["current_thread"], Literal["next_thread"], Literal["idle_thread"], Literal["idtr"], Literal["gdtr"], Literal["tss_base"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["image_base_address"], Literal["ldr"], Literal["process_parameters"], Literal["process_parameters_detail"], Literal["process_heap"], Literal["number_of_heaps"], Literal["process_heaps"], Literal["being_debugged"], Literal["os_major_version"], Literal["os_minor_version"], Literal["os_build_number"], Literal["session_id"], Literal["number_of_processors"], Literal["api_set_map"], Literal["loader_lists"], Literal["peb32"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["image_base_address"], Literal["ldr"], Literal["process_parameters"], Literal["process_parameters_detail"], Literal["process_heap"], Literal["number_of_heaps"], Literal["process_heaps"], Literal["being_debugged"], Literal["os_major_version"], Literal["os_minor_version"], Literal["os_build_number"], Literal["session_id"], Literal["number_of_processors"], Literal["loader_lists"]]]
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
class PfnDetail(BaseRecord):
    """
    A decoded `_MMPFN` record (`!pfn`). A member the layout lacks is decoded
    from the record's raw bits at its known offset, so only `page_color`,
    which has no such fallback, can be unavailable. Union members that the
    page state does not use are `None`: the list links when the page is not
    on a list, `share_count` and `ws_index` when the page is not active, and
    `event` when the page is not in transition.
    """
    __match_args__: Final[tuple[Literal["selector"], Literal["pfn"], Literal["record"], Literal["physical_address"], Literal["pte_address"], Literal["original_pte"], Literal["reference_count"], Literal["flink"], Literal["blink"], Literal["node_flink_low"], Literal["node_blink_low"], Literal["share_count"], Literal["ws_index"], Literal["event"], Literal["used_entry_count"], Literal["page_color"], Literal["pte_frame"], Literal["page_location"], Literal["modified"], Literal["cache_attribute"], Literal["priority"]]]
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

class PfnSelector(BaseRecord):
    """
    What `!pfn` decodes: a page-frame number, or the frame of a physical
    address (shifted by the page size before indexing the PFN database).
    """
    @property
    def kind(self, /) -> Literal["pfn", "physical_address"]:
        """
        The variant: `pfn`, `physical_address`.
        """
    @final
    class Pfn(PfnSelector):
        __match_args__: Final[tuple[Literal["value"]]]
        @property
        def kind(self, /) -> Literal["pfn"]:
            """
            `pfn`.
            """
        @property
        def value(self, /) -> int:
            """
            The page-frame number or physical address given.
            """
    @final
    class PhysicalAddress(PfnSelector):
        __match_args__: Final[tuple[Literal["value"]]]
        @property
        def kind(self, /) -> Literal["physical_address"]:
            """
            `physical_address`.
            """
        @property
        def value(self, /) -> int:
            """
            The page-frame number or physical address given.
            """

@final
class PnpBlackbox(BaseRecord):
    """
    The PnP event in progress, or the last one.
    """
    __match_args__: Final[tuple[Literal["activity_id"], Literal["activity_time"], Literal["event_information"], Literal["event_in_progress"], Literal["problem_code"], Literal["veto_type"], Literal["device_id"], Literal["veto_string"]]]
    @property
    def activity_id(self, /) -> str:
        """
        The activity GUID, braced and in upper case.
        """
    @property
    def activity_time(self, /) -> int: ...
    @property
    def device_id(self, /) -> str: ...
    @property
    def event_in_progress(self, /) -> int: ...
    @property
    def event_information(self, /) -> int: ...
    @property
    def problem_code(self, /) -> int: ...
    @property
    def veto_string(self, /) -> str |None: ...
    @property
    def veto_type(self, /) -> int: ...

@final
class PnpTriageDetail(BaseRecord):
    """
    PnP triage groups from one limited walk of the device tree
    (`!pnptriage`).
    """
    __match_args__: Final[tuple[Literal["problems"], Literal["not_started"], Literal["pending_irps"], Literal["total"], Literal["started"], Literal["truncated"]]]
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
class PoolBlockDetail(BaseRecord):
    """
    A `_POOL_HEADER` block in a pool page.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["body"], Literal["size"], Literal["previous_size"], Literal["pool_type"], Literal["tag"], Literal["tag_name"], Literal["allocated"], Literal["marked"], Literal["state"], Literal["target_offset"]]]
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
    def state(self, /) -> Literal["allocated", "free", "allocated_unverified"]: ...
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
class PoolFindDetail(BaseRecord):
    """
    A pool-tag search (`!poolfind`).
    """
    __match_args__: Final[tuple[Literal["tag"], Literal["pool_type"], Literal["matches"], Literal["found"], Literal["ranges"], Literal["big_status"], Literal["truncated"], Literal["interrupted"]]]
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
    def matches(self, /) -> list[PoolFindMatch]: ...
    @property
    def pool_type(self, /) -> Literal["nonpaged", "paged"] |None:
        """
        The pool that the search was limited to, if any.
        """
    @property
    def ranges(self, /) -> list[PoolFindRange]: ...
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
class PoolFindMatch(BaseRecord):
    """
    A pool allocation with the search tag (`!poolfind`).
    """
    __match_args__: Final[tuple[Literal["source"], Literal["address"], Literal["size"], Literal["tag"], Literal["tag_name"], Literal["allocated"], Literal["state"], Literal["pool_type"], Literal["table_entry"], Literal["index"]]]
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
    def pool_type(self, /) -> Literal["nonpaged", "paged"] |None:
        """
        The pool, when known.
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
    def state(self, /) -> Literal["allocated", "free", "allocated_unverified"]: ...
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
class PoolFindRange(BaseRecord):
    """
    How far `!poolfind` scanned one virtual pool range.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["start"], Literal["end"], Literal["pages"], Literal["scanned_pages"], Literal["stopped_at"]]]
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
class PoolPageDetail(BaseRecord):
    """
    The pool page holding an address (`!pool`).
    """
    __match_args__: Final[tuple[Literal["target"], Literal["page"], Literal["page_kind"], Literal["region"], Literal["blocks"], Literal["target_index"], Literal["big"], Literal["segment_heap_hint"], Literal["near_symbol"], Literal["message"]]]
    @property
    def big(self, /) -> BigPoolDetail |None:
        """
        The large allocation that holds the address, if the address is in one.
        """
    @property
    def blocks(self, /) -> list[PoolBlockDetail]: ...
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
    def region(self, /) -> PoolRegionDetail |None:
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
    __match_args__: Final[tuple[Literal["header"], Literal["message"]]]
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
class PoolRegionDetail(BaseRecord):
    """
    A virtual pool range.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["start"], Literal["end"]]]
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
class PoolTag(BaseRecord):
    """
    A pool tag.
    """
    __match_args__: Final[tuple[Literal["value"]]]
    @property
    def name(self, /) -> str:
        """
        The tag as its four characters.
        """
    @property
    def value(self, /) -> int: ...

@final
class PoolUsageDetail(BaseRecord):
    """
    Pool usage by tag, from the pool tracker (`!poolused`).
    """
    __match_args__: Final[tuple[Literal["rows"], Literal["rows_truncated"], Literal["tracker_status"], Literal["big_status"], Literal["sort"], Literal["tag_filter"]]]
    @property
    def big_status(self, /) -> str:
        """
        The read status of the big-pool table.
        """
    @property
    def rows(self, /) -> list[PoolUsageRow]: ...
    @property
    def rows_truncated(self, /) -> bool:
        """
        Whether more tags matched than are listed.
        """
    @property
    def sort(self, /) -> Literal["tag", "nonpaged", "paged"]: ...
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
class PoolUsageRow(BaseRecord):
    """
    The pool usage of one tag (`!poolused`), summed over the processors'
    tracker tables and the big-pool table. A value is `None` if no source
    has an entry for that pool.
    """
    __match_args__: Final[tuple[Literal["tag"], Literal["nonpaged_allocs"], Literal["nonpaged_frees"], Literal["nonpaged_bytes"], Literal["paged_allocs"], Literal["paged_frees"], Literal["paged_bytes"]]]
    @property
    def nonpaged_allocs(self, /) -> int |None: ...
    @property
    def nonpaged_bytes(self, /) -> int |None:
        """
        In bytes.
        """
    @property
    def nonpaged_frees(self, /) -> int |None: ...
    @property
    def paged_allocs(self, /) -> int |None: ...
    @property
    def paged_bytes(self, /) -> int |None:
        """
        In bytes.
        """
    @property
    def paged_frees(self, /) -> int |None: ...
    @property
    def tag(self, /) -> int: ...
    @property
    def tag_name(self, /) -> str:
        """
        The tag as its four characters.
        """

@final
class PoolValidationDetail(BaseRecord):
    """
    The blocks of the pool page that holds an address, with a check of
    header consistency (`!poolval`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["page"], Literal["region"], Literal["layout"], Literal["blocks"], Literal["problem"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def blocks(self, /) -> list[PoolBlockDetail]: ...
    @property
    def layout(self, /) -> Literal["chained", "segment_heap"]: ...
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
    def region(self, /) -> PoolRegionDetail |None:
        """
        The pool range holding the page, when known.
        """
    @property
    def valid(self, /) -> bool:
        """
        Whether the headers are consistent (`problem` is `None`).
        """

@final
class PortRange(BaseRecord):
    """
    An inclusive range of I/O ports whose accesses exit.
    """
    __match_args__: Final[tuple[Literal["first"], Literal["last"]]]
    @property
    def first(self, /) -> int: ...
    @property
    def last(self, /) -> int: ...

@final
class PowerAction(BaseRecord):
    """
    The system power action (`nt!PopAction`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["updates"], Literal["state"], Literal["shutdown"], Literal["action"], Literal["lightest_state"], Literal["flags"], Literal["status"], Literal["irp_minor"], Literal["waking"], Literal["system_state"], Literal["next_system_state"], Literal["effective_system_state"], Literal["current_system_state"], Literal["hiber_context"], Literal["action_worker_thread"], Literal["devices"]]]
    @property
    def action(self, /) -> PowerEnum: ...
    @property
    def action_worker_thread(self, /) -> int: ...
    @property
    def address(self, /) -> int: ...
    @property
    def current_system_state(self, /) -> PowerEnum: ...
    @property
    def devices(self, /) -> Diagnostic[DeviceNotifyState] |None:
        """
        The device notification pass in progress, when there is one.
        """
    @property
    def effective_system_state(self, /) -> PowerEnum: ...
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `POWER_ACTION_*` flags, such as `QUERY_ALLOWED`.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def hiber_context(self, /) -> int: ...
    @property
    def irp_minor(self, /) -> int: ...
    @property
    def lightest_state(self, /) -> PowerEnum: ...
    @property
    def next_system_state(self, /) -> PowerEnum: ...
    @property
    def shutdown(self, /) -> bool: ...
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str |None:
        """
        `Idle`, `NewRequest`, `Callout`, or `SetSystemState`.
        """
    @property
    def status(self, /) -> int: ...
    @property
    def system_state(self, /) -> PowerEnum:
        """
        The system state being entered.
        """
    @property
    def updates(self, /) -> int: ...
    @property
    def waking(self, /) -> bool: ...

@final
class PowerActionDetail(BaseRecord):
    """
    `!poaction`: the power action, the power IRPs, and the IRP worker
    threads.
    """
    __match_args__: Final[tuple[Literal["record"], Literal["irps"], Literal["workers"]]]
    @property
    def irps(self, /) -> Diagnostic[PowerIrpList]:
        """
        The power IRPs on `nt!PopIrpList`.
        """
    @property
    def record(self, /) -> PowerAction: ...
    @property
    def workers(self, /) -> Diagnostic[PowerWorkerList]:
        """
        The IRP worker threads on `nt!PopIrpThreadList`.
        """

@final
class PowerButton(BaseRecord):
    """
    The power button section of the boot status data.
    """
    __match_args__: Final[tuple[Literal["last_press_time"], Literal["cumulative_press_count"], Literal["last_press_boot_id"], Literal["last_power_watchdog_stage"], Literal["watchdog_armed"], Literal["shutdown_in_progress"], Literal["last_release_time"], Literal["cumulative_release_count"], Literal["last_release_boot_id"], Literal["error_count"], Literal["current_connected_standby_phase"], Literal["transition_latest_checkpoint_id"], Literal["transition_latest_checkpoint_type"], Literal["transition_latest_checkpoint_sequence_number"]]]
    @property
    def cumulative_press_count(self, /) -> int: ...
    @property
    def cumulative_release_count(self, /) -> int: ...
    @property
    def current_connected_standby_phase(self, /) -> int: ...
    @property
    def error_count(self, /) -> int: ...
    @property
    def last_power_watchdog_stage(self, /) -> int: ...
    @property
    def last_press_boot_id(self, /) -> int: ...
    @property
    def last_press_time(self, /) -> int: ...
    @property
    def last_release_boot_id(self, /) -> int: ...
    @property
    def last_release_time(self, /) -> int: ...
    @property
    def shutdown_in_progress(self, /) -> bool: ...
    @property
    def transition_latest_checkpoint_id(self, /) -> int: ...
    @property
    def transition_latest_checkpoint_sequence_number(self, /) -> int: ...
    @property
    def transition_latest_checkpoint_type(self, /) -> int: ...
    @property
    def watchdog_armed(self, /) -> bool: ...

@final
class PowerCulprit(BaseRecord):
    """
    The driver a DRIVER_POWER_STATE_FAILURE names, and why.
    """
    __match_args__: Final[tuple[Literal["driver"], Literal["device"], Literal["reason"]]]
    @property
    def device(self, /) -> int:
        """
        The device object that ties the driver to the failure.
        """
    @property
    def driver(self, /) -> DeviceDriver: ...
    @property
    def reason(self, /) -> str: ...

@final
class PowerEnum(BaseRecord):
    """
    A value of one of the kernel's power enums, with its name when the PDB
    has one, less the enum's common prefix (`Working` for
    `PowerSystemWorking`, `D3` for `PowerDeviceD3`).
    """
    __match_args__: Final[tuple[Literal["value"], Literal["name"]]]
    @property
    def label(self, /) -> str:
        """
        The name, or the value in hex.
        """
    @property
    def name(self, /) -> str |None:
        """
        The name; `None` when the PDB has no name for the value.
        """
    @property
    def value(self, /) -> int: ...

@final
class PowerFailure(BaseRecord):
    """
    What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck, by subtype
    (parameter 1).
    """
    __match_args__: Final[tuple[Literal["subtype"], Literal["description"], Literal["device"], Literal["blocked_irp"], Literal["irps"], Literal["workers"], Literal["pnp_lock_owner"], Literal["timeout_seconds"], Literal["culprit"], Literal["notes"]]]
    @property
    def blocked_irp(self, /) -> BlockedIrp |None:
        """
        0x3: the blocked IRP.
        """
    @property
    def culprit(self, /) -> PowerCulprit |None: ...
    @property
    def description(self, /) -> str: ...
    @property
    def device(self, /) -> int |None:
        """
        The device object the parameters name: the PDO for 0x3 and 0x5, the
        device for 0x1, 0x2, and 0x500.
        """
    @property
    def device_stack(self, /) -> Diagnostic[DeviceStackDetail] |None:
        """
        The stack of `device`, or why it is unknown.
        """
    @property
    def irps(self, /) -> PowerIrpList |None:
        """
        0x3: the power IRPs, from the list `TRIAGE_9F_POWER` names.
        """
    @property
    def notes(self, /) -> list[str]:
        """
        What could not be read, and why.
        """
    @property
    def pnp_lock_owner(self, /) -> int |None:
        """
        0x4: the thread that holds the PnP lock.
        """
    @property
    def subtype(self, /) -> int:
        """
        Parameter 1.
        """
    @property
    def timeout_seconds(self, /) -> int |None:
        """
        0x4: the timeout, in seconds.
        """
    @property
    def workers(self, /) -> PowerWorkerList |None:
        """
        0x3: the IRP worker threads, from the list `TRIAGE_9F_POWER` names.
        """

@final
class PowerFailureFinding(BaseRecord):
    """
    What a DRIVER_POWER_STATE_FAILURE (0x9F) names, read from the target,
    and the stacks of the threads involved.
    """
    __match_args__: Final[tuple[Literal["record"], Literal["threads"]]]
    @property
    def record(self, /) -> PowerFailure: ...
    @property
    def threads(self, /) -> list[PowerFailureThread]: ...

@final
class PowerFailureThread(BaseRecord):
    """
    A thread that a DRIVER_POWER_STATE_FAILURE names, with its stack.
    """
    __match_args__: Final[tuple[Literal["role"], Literal["thread"]]]
    @property
    def role(self, /) -> PowerThreadRole: ...
    @property
    def stack(self, /) -> Diagnostic[list[StackFrame]]:
        """
        The thread's stack, or why it did not unwind.
        """
    @property
    def thread(self, /) -> int:
        """
        The `_ETHREAD`.
        """

@final
class PowerIrp(BaseRecord):
    """
    A power IRP the power manager allocated (`_POP_IRP_DATA`).
    """
    __match_args__: Final[tuple[Literal["data"], Literal["irp"], Literal["pdo"], Literal["target_device"], Literal["current_device"], Literal["minor_function"], Literal["state"], Literal["system_transition"], Literal["watchdog"], Literal["pending"], Literal["holder"]]]
    @property
    def current_device(self, /) -> int:
        """
        The device the power manager passed it to last, or 0.
        """
    @property
    def data(self, /) -> int: ...
    @property
    def holder(self, /) -> Diagnostic[IrpHolder]:
        """
        Where the IRP is now, or why that is unknown.
        """
    @property
    def irp(self, /) -> int: ...
    @property
    def minor_function(self, /) -> int: ...
    @property
    def minor_name(self, /) -> str |None:
        """
        `IRP_MN_SET_POWER`, `IRP_MN_QUERY_POWER`, `IRP_MN_WAIT_WAKE`, or
        `IRP_MN_POWER_SEQUENCE`.
        """
    @property
    def pdo(self, /) -> int: ...
    @property
    def pending(self, /) -> int |None:
        """
        How long ago the watchdog was armed, in 100 ns units: how long the
        drivers have had the IRP. `None` when the watchdog never ran or the
        current time is unreadable.
        """
    @property
    def pending_ms(self, /) -> int |None:
        """
        How long ago the watchdog was armed, in milliseconds.
        """
    @property
    def state(self, /) -> PowerState: ...
    @property
    def system_transition(self, /) -> bool:
        """
        The IRP is part of a system power transition.
        """
    @property
    def target_device(self, /) -> int:
        """
        The device `PoRequestPowerIrp` sent the IRP to, the top of the PDO's
        stack.
        """
    @property
    def watchdog(self, /) -> PowerEnum:
        """
        `WatchdogState`: whether the watchdog for the IRP runs.
        """

@final
class PowerIrpEntry(BaseRecord):
    """
    An entry on a list of `_POP_IRP_DATA`: the power IRP, or why it does
    not decode.
    """
    __match_args__: Final[tuple[Literal["data"], Literal["power_irp"]]]
    @property
    def data(self, /) -> int:
        """
        The `_POP_IRP_DATA`.
        """
    @property
    def power_irp(self, /) -> Diagnostic[PowerIrp]: ...

@final
class PowerIrpList(BaseRecord):
    """
    The power IRPs on a list of `_POP_IRP_DATA`, normally `nt!PopIrpList`.
    """
    __match_args__: Final[tuple[Literal["head"], Literal["head_name"], Literal["entries"], Literal["stopped"]]]
    @property
    def entries(self, /) -> list[PowerIrpEntry]: ...
    @property
    def head(self, /) -> int: ...
    @property
    def head_name(self, /) -> str |None:
        """
        The symbol of the head, such as `nt!PopIrpList`, when it is one.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk stopped short of the head.
        """

class PowerState(BaseRecord):
    """
    The power state a power IRP or a stack location asks for: a `system`
    or a `device` state.
    """
    @property
    def kind(self, /) -> Literal["system", "device"]:
        """
        The variant: `system`, `device`.
        """
    @final
    class Device(PowerState):
        __match_args__: Final[tuple[Literal["device"]]]
        @property
        def device(self, /) -> PowerEnum: ...
        @property
        def kind(self, /) -> Literal["device"]:
            """
            `device`.
            """
    @final
    class System(PowerState):
        __match_args__: Final[tuple[Literal["system"]]]
        @property
        def kind(self, /) -> Literal["system"]:
            """
            `system`.
            """
        @property
        def system(self, /) -> PowerEnum: ...

class PowerThreadRole(BaseRecord):
    """
    Why a DRIVER_POWER_STATE_FAILURE names a thread: `kind` `irp_worker`
    (a power IRP worker thread, passing `irp` to `device`, or waiting for
    work when both are 0) or `pnp_lock_owner` (the thread that holds the PnP
    lock, 0x4).
    """
    @property
    def kind(self, /) -> Literal["irp_worker", "pnp_lock_owner"]:
        """
        The variant: `irp_worker`, `pnp_lock_owner`.
        """
    @final
    class IrpWorker(PowerThreadRole):
        """
        A power IRP worker thread, passing `irp` to `device`, or waiting for
        work when both are 0.
        """
        __match_args__: Final[tuple[Literal["irp"], Literal["device"]]]
        @property
        def device(self, /) -> int: ...
        @property
        def irp(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["irp_worker"]:
            """
            `irp_worker`.
            """
    @final
    class PnpLockOwner(PowerThreadRole):
        """
        The thread that holds the PnP lock (0x4).
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["pnp_lock_owner"]:
            """
            `pnp_lock_owner`.
            """

@final
class PowerTransition(BaseRecord):
    """
    The power transition section of the boot status data.
    """
    __match_args__: Final[tuple[Literal["power_button_timestamp"], Literal["system_running"], Literal["connected_standby_in_progress"], Literal["user_shutdown_in_progress"], Literal["system_shutdown_in_progress"], Literal["sleep_in_progress"], Literal["connected_standby_scenario_instance_id"], Literal["connected_standby_entry_reason"], Literal["connected_standby_exit_reason"], Literal["system_sleep_transitions_to_on"], Literal["last_reference_time"], Literal["last_reference_time_checksum"], Literal["last_update_boot_id"]]]
    @property
    def connected_standby_entry_reason(self, /) -> int: ...
    @property
    def connected_standby_exit_reason(self, /) -> int: ...
    @property
    def connected_standby_in_progress(self, /) -> bool: ...
    @property
    def connected_standby_scenario_instance_id(self, /) -> int: ...
    @property
    def last_reference_time(self, /) -> int: ...
    @property
    def last_reference_time_checksum(self, /) -> int: ...
    @property
    def last_update_boot_id(self, /) -> int: ...
    @property
    def power_button_timestamp(self, /) -> int: ...
    @property
    def sleep_in_progress(self, /) -> int: ...
    @property
    def system_running(self, /) -> bool: ...
    @property
    def system_shutdown_in_progress(self, /) -> bool: ...
    @property
    def system_sleep_transitions_to_on(self, /) -> int: ...
    @property
    def user_shutdown_in_progress(self, /) -> bool: ...

@final
class PowerWorker(BaseRecord):
    """
    A thread that passes power IRPs to drivers (`_POP_IRP_WORKER_ENTRY`).
    """
    __match_args__: Final[tuple[Literal["thread"], Literal["irp"], Literal["device"], Literal["driver"], Literal["is_static"]]]
    @property
    def device(self, /) -> int: ...
    @property
    def driver(self, /) -> str |None: ...
    @property
    def irp(self, /) -> int:
        """
        The IRP it is passing to a driver, or 0 while it waits for work.
        """
    @property
    def is_static(self, /) -> bool:
        """
        The power manager keeps the thread when it runs out of work.
        """
    @property
    def thread(self, /) -> int: ...

@final
class PowerWorkerEntry(BaseRecord):
    """
    An entry on a list of `_POP_IRP_WORKER_ENTRY`: the worker, or why it
    does not decode.
    """
    __match_args__: Final[tuple[Literal["entry"], Literal["worker"]]]
    @property
    def entry(self, /) -> int: ...
    @property
    def worker(self, /) -> Diagnostic[PowerWorker]: ...

@final
class PowerWorkerList(BaseRecord):
    """
    The IRP worker threads on a list, normally `nt!PopIrpThreadList`.
    """
    __match_args__: Final[tuple[Literal["head"], Literal["head_name"], Literal["entries"], Literal["stopped"]]]
    @property
    def entries(self, /) -> list[PowerWorkerEntry]: ...
    @property
    def head(self, /) -> int: ...
    @property
    def head_name(self, /) -> str |None: ...
    @property
    def stopped(self, /) -> str |None: ...

@final
class Prcb(BaseRecord):
    """
    Selected `_KPRCB` fields of a processor (`!prcb`).
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["kprcb"], Literal["number"], Literal["current_thread"], Literal["next_thread"], Literal["idle_thread"], Literal["dpc_routine_active"], Literal["interrupt_count"], Literal["processor_state"]]]
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
    __match_args__: Final[tuple[Literal["name"], Literal["type_name"], Literal["byte_size"], Literal["parameter"], Literal["location"]]]
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
    def decode_peb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Peb:
        """
        Decode the process environment block and process parameters of the
        current process.
        
        If you do not give an address, the command uses EPROCESS.Peb of the
        current process: the one that .process selected, else the owner of the
        current thread. On a user-mode minidump it uses the PEB that the selected
        thread's TEB names, and the layouts of the dump's ntdll. It decodes the
        process parameters with their PDB layouts. To list the loader modules,
        use !dlls.
        """
    @property
    def dtb(self, /) -> int:
        """
        The directory table base (page-table root).
        """
    @property
    def eprocess(self, /) -> int:
        """
        The `_EPROCESS` address.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in the symbol scope of this process.
        """
    def handle(self, /, value: int) -> HandleEntry:
        """
        Decode a handle in the handle table of this process.
        """
    def handle_traces(self, /, handle: int |None = None, *, max_traces: int |None = None) -> HandleTraces:
        """
        Show the stacks that handle tracing recorded for the handles of a process.
        
        Reads the ring of traces (open, close, bad reference) in the DebugInfo of
        the process handle table and shows the newest trace first. If handle is 0
        or not given, the command shows the traces of all handles, and if
        max-traces is 0 or not given, it shows all traces. The process can be an
        EPROCESS address, a PID, or a name, and the default is the current
        process. Handle tracing must be on for the process before you use the
        command. The Handles check of Application Verifier or
        NtSetInformationProcess(ProcessHandleTracing) turns tracing on, and if it
        is off, !htrace shows a message. User-mode frames resolve after the
        modules of the process are loaded (.process /p). The command does not
        have the user-mode forms that change tracing (-enable, -disable,
        -snapshot, -diff).
        """
    def handles(self, /, *, limit: int = 256) -> HandleTable:
        """
        List a maximum of `limit` handles in the handle table of this process.
        """
    @property
    def heaps(self, /) -> Heaps:
        """
        The heaps in the PEB of this process.
        """
    @property
    def info(self, /) -> ProcessInfo:
        """
        The `ProcessInfo` record of this handle: its properties as one value.
        """
    def inspect(self, /) -> ProcessDetail:
        """
        List or inspect Windows processes.
        
        `!process 0 0` lists all processes. Bit 1 adds process details, bit 2
        adds threads, and bit 4 adds the stack of each thread. An image name in
        place of the process shows every process whose name contains it or
        matches it as a glob, as the last argument filters: `!process
        explorer.exe` shows explorer.exe, and `!process svchost 0` lists each
        svchost.exe. `ps` keeps its short legacy list format.
        """
    def loader_modules(self, /, *, containing: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> LoaderModules:
        """
        List the modules in the loader lists of the current process.
        
        The current process is the one that .process selected, else the owner of
        the current thread; on a user-mode minidump, its one process, as far as
        the dump captured the loader's lists (lm lists the dump's own module
        list). With -c <address>, the command shows only the module that
        contains that address. The module walk has a limit, and also stops if it
        finds a cycle in a list.
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
    def protection(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> MemoryBasicInformation:
        """
        Show the VirtualQuery data for a user address.
        
        The command shows the region, state, protection, and type of a user
        address, as VirtualQuery reports them. It looks up the address in the
        current process context, which you can select with `.process /p <pid>`.
        The VAD that holds the address gives AllocationBase, AllocationProtect,
        and Type, and the state and protection of each page come from its PTE.
        For a page without a PTE, they come from the VAD (private memory) or
        from its prototype PTE (a section view). RegionSize runs from the page of
        the address to the first page that differs. An address that is not in a
        VAD is MEM_FREE up to the next VAD. The scan stops after 262,144
        page-table steps. On a user-mode minidump the command reads the region
        from the dump's memory-info list, which records what VirtualQuery
        returned when the dump was written; RegionSize runs from the page of the
        address to the end of that region.
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
        The record (`info`) as a plain `dict`.
        """
    def token(self, /) -> Token:
        """
        Show the primary token of the selected or current process.
        
        The command shows the token IDs, user and groups, privileges, type,
        impersonation level, and flags. It gets each field independently, and if
        the metadata or memory for a field is missing, it shows this in that field.
        """
    @property
    def types(self, /) -> Types:
        """
        The PDB types and cursors, bound to the address space of this process.
        """
    @property
    def wow64(self, /) -> bool:
        """
        True if it is a 32-bit process that runs under WOW64.
        """
    @property
    def wow64_peb(self, /) -> int |None:
        """
        The 32-bit PEB of a WOW64 process (`_EPROCESS.WoW64Process`), `None`
        for a native process.
        """

@final
class ProcessDetail(BaseRecord):
    """
    A process as `!process` shows it: its identity and the layout-sensitive
    `_EPROCESS` fields. Each field is `None` when this build's layout lacks
    it or its read failed.
    """
    __match_args__: Final[tuple[Literal["info"], Literal["session_id"], Literal["peb"], Literal["parent_pid"], Literal["directory_table_base"], Literal["object_table"], Literal["handle_count"], Literal["vad_root"], Literal["token"], Literal["create_time"], Literal["user_time"], Literal["kernel_time"], Literal["quota_paged_pool"], Literal["quota_nonpaged_pool"], Literal["working_set_size"], Literal["commit_charge"], Literal["peak_virtual_size"], Literal["private_page_count"], Literal["debug_port"], Literal["job"]]]
    @property
    def commit_charge(self, /) -> int |None: ...
    @property
    def create_time(self, /) -> int |None:
        """
        `CreateTime` as a FILETIME.
        """
    @property
    def debug_port(self, /) -> int |None: ...
    @property
    def directory_table_base(self, /) -> int |None: ...
    @property
    def handle_count(self, /) -> int |None: ...
    @property
    def info(self, /) -> ProcessInfo: ...
    @property
    def job(self, /) -> int |None: ...
    @property
    def kernel_time(self, /) -> int |None: ...
    @property
    def object_table(self, /) -> int |None: ...
    @property
    def parent_pid(self, /) -> int |None: ...
    @property
    def peak_virtual_size(self, /) -> int |None: ...
    @property
    def peb(self, /) -> int |None:
        """
        The `_PEB`.
        """
    @property
    def private_page_count(self, /) -> int |None: ...
    @property
    def quota_nonpaged_pool(self, /) -> int |None: ...
    @property
    def quota_paged_pool(self, /) -> int |None: ...
    @property
    def session_id(self, /) -> int |None: ...
    @property
    def token(self, /) -> int |None: ...
    @property
    def user_time(self, /) -> int |None: ...
    @property
    def vad_root(self, /) -> int |None: ...
    @property
    def working_set_size(self, /) -> int |None: ...

@final
class ProcessInfo(BaseRecord):
    """
    The identity of a process (`ps`, `!process 0 0`) and the root (`dtb`) of
    its address space.
    """
    __match_args__: Final[tuple[Literal["pid"], Literal["name"], Literal["dtb"], Literal["eprocess"], Literal["wow64_peb"]]]
    @property
    def dtb(self, /) -> int:
        """
        The directory table base (page-table root).
        """
    @property
    def eprocess(self, /) -> int:
        """
        The `_EPROCESS` address.
        """
    @property
    def name(self, /) -> str:
        """
        The image name.
        """
    @property
    def pid(self, /) -> int:
        """
        The process identifier.
        """
    @property
    def wow64(self, /) -> bool:
        """
        True if it is a 32-bit process that runs under WOW64.
        """
    @property
    def wow64_peb(self, /) -> int |None:
        """
        The 32-bit PEB of a WOW64 process (`_EPROCESS.WoW64Process`), `None`
        for a native process.
        """

@final
class ProcessMemoryUsage(BaseRecord):
    """
    One process's memory counters, in bytes.
    """
    __match_args__: Final[tuple[Literal["process"], Literal["virtual_size"], Literal["peak_virtual_size"], Literal["working_set_size"], Literal["peak_working_set_size"], Literal["pagefile_usage"], Literal["peak_pagefile_usage"], Literal["private_usage"]]]
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
    def process(self, /) -> ProcessInfo: ...
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
    __match_args__: Final[tuple[Literal["address"], Literal["command_line"], Literal["image_path_name"], Literal["current_directory"], Literal["dll_path"], Literal["window_title"], Literal["desktop_info"], Literal["shell_info"], Literal["runtime_data"], Literal["environment"], Literal["environment_size"]]]
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
    names. A `ProcessInfo` record (`stop.process`) is a key too: it names the
    listed process it describes.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: int |ProcessInfo, /) -> Process:
        """
        The process with a PID, or the process a `ProcessInfo` record
        describes (`dbg.processes[stop.process]`).
        """
    def __iter__(self, /) -> Iterator[Process]: ...
    def __len__(self, /) -> int: ...
    def find(self, /, name: str) -> list[Process]:
        """
        The processes whose image name is an exact match, ignoring case.
        """
    def get(self, /, key: int |ProcessInfo) -> Process |None:
        """
        The process with a PID, or the process a `ProcessInfo` record
        describes (`dbg.processes[stop.process]`).
        """

@final
class ProcessorError(BaseRecord):
    """
    A processor whose state ntoseye could not read.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["message"]]]
    @property
    def message(self, /) -> str: ...
    @property
    def processor(self, /) -> int: ...

@final
class ProcessorStateArea(BaseRecord):
    """
    The `_KPROCESSOR_STATE` embedded in a `_KPRCB`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["size"], Literal["name"], Literal["context_frame"], Literal["special_registers"]]]
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
class PteAttributes(BaseRecord):
    """
    A page-table entry decoded at its level; see
    [`PageTableEntry::attributes`]. For an entry pointing at a lower table,
    `writable`, `user`, and `nx` are the restrictions it places on what lies
    below.
    """
    __match_args__: Final[tuple[Literal["present"], Literal["large_page"], Literal["writable"], Literal["user"], Literal["nx"], Literal["pfn"], Literal["flags"]]]
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
    def writable(self, /) -> bool: ...

@final
class PteLevel(BaseRecord):
    """
    One page-table level of a walk (`!pte`, `!vtop`): where its entry is,
    the entry as read, and the entry decoded at its level.
    """
    __match_args__: Final[tuple[Literal["level"], Literal["address"], Literal["value"], Literal["attributes"]]]
    @property
    def address(self, /) -> int:
        """
        The entry's address: virtual through NT's self-map, physical in an
        explicit walk.
        """
    @property
    def attributes(self, /) -> PteAttributes: ...
    @property
    def level(self, /) -> Literal["pxe", "ppe", "pde", "pte"]: ...
    @property
    def value(self, /) -> int:
        """
        The entry as read.
        """

@final
class PteWalk(BaseRecord):
    """
    The page-table entries that map an address, read through NT's self-map
    (`!pte`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["dtb"], Literal["pxe"], Literal["ppe"], Literal["pde"], Literal["pte"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def dtb(self, /) -> int:
        """
        The address space the walk was performed in (the attached process DTB
        when attached, else the kernel), so callers know what was walked.
        """
    @property
    def pde(self, /) -> PteLevel |None: ...
    @property
    def ppe(self, /) -> PteLevel |None:
        """
        The levels below the PXE, each present only when the one above it
        points at a table.
        """
    @property
    def pte(self, /) -> PteLevel |None: ...
    @property
    def pxe(self, /) -> PteLevel: ...

@final
class PtovDetail(BaseRecord):
    """
    The virtual addresses that map a physical address (`!ptov`).
    """
    __match_args__: Final[tuple[Literal["physical"], Literal["dtb"], Literal["mappings"], Literal["table_pages"], Literal["bounded"], Literal["interrupted"]]]
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
    def mappings(self, /) -> list[PtovMapping]: ...
    @property
    def physical(self, /) -> int: ...
    @property
    def table_pages(self, /) -> int:
        """
        The number of page-table pages that the walk read.
        """

@final
class PtovMapping(BaseRecord):
    """
    A virtual address that maps a physical page (`!ptov`).
    """
    __match_args__: Final[tuple[Literal["virtual_address"], Literal["large"]]]
    @property
    def large(self, /) -> bool:
        """
        Whether a large page maps it.
        """
    @property
    def virtual_address(self, /) -> int: ...

@final
class QueueProgress(BaseRecord):
    """
    Where a queue's traffic stood at one look, as counters that only grow,
    modulo `modulus`: the buffers the driver handed the device, the ones the
    device returned (split rings, whose used index says so), and the ones
    the driver took back; with how many were with the device and returned
    but not taken back.
    """
    __match_args__: Final[tuple[Literal["published"], Literal["completed"], Literal["taken_back"], Literal["modulus"], Literal["with_device"], Literal["returned"]]]
    @property
    def completed(self, /) -> int |None:
        """
        Buffers the device returned (split rings).
        """
    @property
    def modulus(self, /) -> int: ...
    @property
    def published(self, /) -> int:
        """
        Buffers the driver handed the device.
        """
    @property
    def returned(self, /) -> int:
        """
        Buffers the device returned that the driver has not taken back.
        """
    @property
    def taken_back(self, /) -> int:
        """
        Buffers the driver took back.
        """
    @property
    def with_device(self, /) -> int:
        """
        Buffers the device holds.
        """

@final
class QueuedLock(BaseRecord):
    """
    A numbered queued spinlock and the processors that own it or wait for it.
    """
    __match_args__: Final[tuple[Literal["number"], Literal["name"], Literal["lock"], Literal["holders"]]]
    @property
    def holders(self, /) -> list[QueuedLockHolder]: ...
    @property
    def lock(self, /) -> int |None:
        """
        The spinlock itself, from the first processor entry that names it.
        """
    @property
    def name(self, /) -> str:
        """
        The `_KSPIN_LOCK_QUEUE_NUMBER` name without its `LockQueue` prefix and
        `Lock` suffix (`IoCancel`), from the PDB or else the WDK's list when
        the array has its 17 entries; `LockQueue[n]` otherwise.
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
    __match_args__: Final[tuple[Literal["processor"]]]
    @property
    def processor(self, /) -> int: ...
    @property
    def reason(self, /) -> str |None:
        """
        How a corrupt entry does not agree with the queue links. `None` for
        other entries.
        """
    @property
    def state(self, /) -> Literal["owner", "waiting", "corrupt"]:
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
    __match_args__: Final[tuple[Literal["processors"], Literal["locks"], Literal["errors"]]]
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
class RcdrDriver(BaseRecord):
    """
    A driver the WPP recorder serves (`_WPP_AUTOLOG_CONTEXT`).
    """
    __match_args__: Final[tuple[Literal["context"], Literal["name"], Literal["image"], Literal["image_size"], Literal["logs"], Literal["logs_stopped"], Literal["default_log"], Literal["sequence"]]]
    @property
    def context(self, /) -> int: ...
    @property
    def default_log(self, /) -> int:
        """
        `DefaultAutoLogHeader`, the log `WppRecorderLogGetDefault` returns.
        """
    @property
    def image(self, /) -> int: ...
    @property
    def image_size(self, /) -> int: ...
    @property
    def logs(self, /) -> list[int]:
        """
        The `_WPP_AUTOLOG_HEADER` of each of its logs (its `LogListHead`).
        """
    @property
    def logs_stopped(self, /) -> str |None: ...
    @property
    def name(self, /) -> str:
        """
        `FileBaseName`: the driver's image name without its extension.
        """
    @property
    def sequence(self, /) -> int:
        """
        The context's `Sequence`: the last sequence number a record of any of
        its logs took.
        """

@final
class RcdrDriverList(BaseRecord):
    """
    The drivers the recorder serves (`!rcdrkd.rcdrloglist`).
    """
    __match_args__: Final[tuple[Literal["drivers"], Literal["unreadable"], Literal["stopped"]]]
    @property
    def drivers(self, /) -> list[RcdrDriver]: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the bugcheck callback list stopped short.
        """
    @property
    def unreadable(self, /) -> list[RcdrUnreadable]:
        """
        The contexts that do not read.
        """

@final
class RcdrEntry(BaseRecord):
    """
    A record of a log's partition, formatted.
    """
    __match_args__: Final[tuple[Literal["log"], Literal["partition"], Literal["entry"]]]
    @property
    def entry(self, /) -> WdfLogEntry: ...
    @property
    def log(self, /) -> int:
        """
        The index of its log in `RcdrLogDump.logs`.
        """
    @property
    def partition(self, /) -> Literal["normal", "error"]:
        """
        `normal` or `error`.
        """

@final
class RcdrLog(BaseRecord):
    """
    A recorder log (`_WPP_AUTOLOG_HEADER`).
    """
    __match_args__: Final[tuple[Literal["header"], Literal["identifier"], Literal["id_number"], Literal["size"], Literal["deleted"], Literal["timestamps"], Literal["default"], Literal["partitions"]]]
    @property
    def default(self, /) -> bool:
        """
        Whether it is the driver's default log.
        """
    @property
    def deleted(self, /) -> bool: ...
    @property
    def header(self, /) -> int: ...
    @property
    def id_number(self, /) -> int: ...
    @property
    def identifier(self, /) -> str:
        """
        `LogIdentifier`, with `LogIdentifierAppendValue` after it when the
        driver set one.
        """
    @property
    def partitions(self, /) -> list[RcdrPartition]: ...
    @property
    def size(self, /) -> int: ...
    @property
    def timestamps(self, /) -> bool:
        """
        Records are 'L2', with a timestamp.
        """

@final
class RcdrLogDump(BaseRecord):
    """
    A driver's records from its logs, merged in the order the driver logged
    them, oldest first (`!rcdrkd.rcdrlogdump`).
    """
    __match_args__: Final[tuple[Literal["driver"], Literal["logs"], Literal["entries"], Literal["ends"]]]
    @property
    def driver(self, /) -> RcdrDriver: ...
    @property
    def ends(self, /) -> list[RcdrWalkEnd]:
        """
        How each walk of a partition ended.
        """
    @property
    def entries(self, /) -> list[RcdrEntry]: ...
    @property
    def logs(self, /) -> list[RcdrLog]: ...

@final
class RcdrLogs(BaseRecord):
    """
    A driver's logs (`!rcdrkd.rcdrloglist <driver>`).
    """
    __match_args__: Final[tuple[Literal["driver"], Literal["logs"], Literal["unreadable"]]]
    @property
    def driver(self, /) -> RcdrDriver: ...
    @property
    def logs(self, /) -> list[RcdrLog]: ...
    @property
    def unreadable(self, /) -> list[RcdrUnreadable]:
        """
        The log headers that do not read.
        """

@final
class RcdrPartition(BaseRecord):
    """
    A partition of a recorder log: the ring its records go to.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["base"], Literal["size"], Literal["current"], Literal["previous"]]]
    @property
    def base(self, /) -> int: ...
    @property
    def current(self, /) -> int:
        """
        `Offset.Current`, where the next record goes.
        """
    @property
    def name(self, /) -> Literal["normal", "error"]:
        """
        `normal` or `error`.
        """
    @property
    def previous(self, /) -> int:
        """
        `Offset.Previous`, the newest record.
        """
    @property
    def size(self, /) -> int: ...

@final
class RcdrUnreadable(BaseRecord):
    """
    A recorder context or log header that does not read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def error(self, /) -> str: ...

@final
class RcdrWalkEnd(BaseRecord):
    """
    How the walk of one partition ended.
    """
    __match_args__: Final[tuple[Literal["log"], Literal["partition"], Literal["end"]]]
    @property
    def end(self, /) -> IfrEnd: ...
    @property
    def log(self, /) -> int:
        """
        The index of its log in `RcdrLogDump.logs`.
        """
    @property
    def partition(self, /) -> Literal["normal", "error"]:
        """
        `normal` or `error`.
        """

@final
class ReadyQueue(BaseRecord):
    """
    The ready list of one processor for one priority.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["priority"], Literal["entries"], Literal["termination"]]]
    @property
    def entries(self, /) -> list[ReadyThread]: ...
    @property
    def priority(self, /) -> int: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def termination(self, /) -> ListTermination:
        """
        How the list walk ended.
        """

@final
class ReadyQueues(BaseRecord):
    """
    The dispatcher ready queues (`!ready`).
    """
    __match_args__: Final[tuple[Literal["queues"], Literal["total"], Literal["truncated"], Literal["errors"]]]
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
    __match_args__: Final[tuple[Literal["kthread"], Literal["thread"]]]
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` linked on the queue.
        """
    @property
    def thread(self, /) -> Diagnostic[ThreadInfo]:
        """
        The decoded thread.
        """

@final
class RegKey(BaseRecord):
    """
    A key with its subkeys and values (`!reg querykey`, `!reg keyinfo`).
    """
    __match_args__: Final[tuple[Literal["path"], Literal["hive"], Literal["cell"], Literal["node"], Literal["name"], Literal["flags"], Literal["last_write"], Literal["links"], Literal["subkey_count"], Literal["value_count"], Literal["problems"]]]
    @property
    def cell(self, /) -> int |None:
        """
        Its cell; `None` for a key given by the address of its node.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `KEY_*` names of `flags`.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def hive(self, /) -> int: ...
    @property
    def last_write(self, /) -> int:
        """
        A FILETIME.
        """
    @property
    def last_write_utc(self, /) -> str |None:
        """
        `last_write` as UTC.
        """
    @property
    def links(self, /) -> list[RegLink]:
        """
        The symbolic links the path went through.
        """
    @property
    def name(self, /) -> str: ...
    @property
    def node(self, /) -> int: ...
    @property
    def path(self, /) -> str:
        """
        Its full path, with the names as the hives store them.
        """
    @property
    def problems(self, /) -> list[str]:
        """
        Subkey indexes and value lists that do not read, and counts that do
        not match.
        """
    @property
    def subkey_count(self, /) -> int:
        """
        The subkeys and values the key node counts.
        """
    @property
    def subkeys(self, /) -> list[RegSubkey]:
        """
        The subkeys that read.
        """
    @property
    def unreadable_subkeys(self, /) -> list[RegistryCellError]:
        """
        The subkey cells that do not read.
        """
    @property
    def unreadable_values(self, /) -> list[RegistryCellError]:
        """
        The value cells that do not read.
        """
    @property
    def value_count(self, /) -> int: ...
    @property
    def values(self, /) -> list[RegValue]:
        """
        The values that read.
        """

@final
class RegLink(BaseRecord):
    """
    A symbolic link a path went through: the link's path and the path
    its `SymbolicLinkValue` holds.
    """
    __match_args__: Final[tuple[Literal["path"], Literal["target"]]]
    @property
    def path(self, /) -> str: ...
    @property
    def target(self, /) -> str: ...

@final
class RegSubkey(BaseRecord):
    """
    A subkey as its parent lists it.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["cell"], Literal["node"], Literal["flags"], Literal["last_write"], Literal["subkey_count"], Literal["value_count"]]]
    @property
    def cell(self, /) -> int: ...
    @property
    def flags(self, /) -> int:
        """
        `_CM_KEY_NODE.Flags`.
        """
    @property
    def last_write(self, /) -> int:
        """
        A FILETIME.
        """
    @property
    def last_write_utc(self, /) -> str |None:
        """
        `last_write` as UTC.
        """
    @property
    def mount_point(self, /) -> bool:
        """
        A hive is mounted at the key.
        """
    @property
    def name(self, /) -> str: ...
    @property
    def node(self, /) -> int:
        """
        Its key node (`_CM_KEY_NODE`).
        """
    @property
    def subkey_count(self, /) -> int: ...
    @property
    def symbolic_link(self, /) -> bool:
        """
        The key is a symbolic link.
        """
    @property
    def value_count(self, /) -> int: ...
    @property
    def volatile(self, /) -> bool:
        """
        The cell is in volatile storage.
        """

@final
class RegValue(BaseRecord):
    """
    A value (`_CM_KEY_VALUE`).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["cell"], Literal["node"], Literal["type"], Literal["length"], Literal["storage"], Literal["raw"]]]
    @property
    def cell(self, /) -> int: ...
    @property
    def data(self, /) -> Diagnostic[str |list[str] |int |bytes]:
        """
        The data decoded by the value's type.
        """
    @property
    def length(self, /) -> int:
        """
        The data's length in bytes.
        """
    @property
    def name(self, /) -> str:
        """
        Empty for the key's default value.
        """
    @property
    def node(self, /) -> int: ...
    @property
    def raw(self, /) -> Diagnostic[bytes]:
        """
        The data's bytes.
        """
    @property
    def storage(self, /) -> Literal["inline", "cell", "big"]: ...
    @property
    def type(self, /) -> int:
        """
        `REG_*`.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The type's name; `None` for a type Windows does not define.
        """

@final
class Regions:
    """
    The VAD regions of a process (`!vad`), keyed by an address they hold.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: int, /) -> MemoryRegionInfo:
        """
        The VAD region that contains `address`.
        """
    def __iter__(self, /) -> Iterator[MemoryRegionInfo]: ...
    def __len__(self, /) -> int: ...
    def get(self, /, key: int) -> MemoryRegionInfo |None:
        """
        The VAD region that contains `address`.
        """

@final
class RegisterValue(BaseRecord):
    """
    A register of the exception's context.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["value"]]]
    @property
    def name(self, /) -> str: ...
    @property
    def value(self, /) -> int: ...

@final
class Registers:
    """
    A register file that is bound to a vCPU or to a recovered frame context.
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getattr__(self, name: str, /) -> int: ...
    def __getitem__(self, name: str, /) -> int: ...
    def __iter__(self, /) -> Iterator[str]: ...
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
class RegistryCellError(BaseRecord):
    """
    A subkey or value cell that does not read.
    """
    __match_args__: Final[tuple[Literal["cell"], Literal["error"]]]
    @property
    def cell(self, /) -> int: ...
    @property
    def error(self, /) -> str: ...

@final
class RegistryUnreadable(BaseRecord):
    """
    A hive that does not read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["error"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def error(self, /) -> str: ...

@final
class ReloadStop(BaseRecord):
    """
    A reboot the debugger rebuilt its state for.
    """
    __match_args__: Final[tuple[Literal["kernel_base"], Literal["coherent"]]]
    @property
    def coherent(self, /) -> bool:
        """
        Whether the kernel's module list exists yet.
        """
    @property
    def kernel_base(self, /) -> int |None:
        """
        The new kernel's base.
        """

@final
class ResourceList(BaseRecord):
    """
    The executive-resource list of the kernel (`!locks`).
    """
    __match_args__: Final[tuple[Literal["head"], Literal["resources"], Literal["termination"]]]
    @property
    def head(self, /) -> int:
        """
        `nt!ExpSystemResourcesList`.
        """
    @property
    def resources(self, /) -> list[ExecutiveResource]: ...
    @property
    def termination(self, /) -> ListTermination: ...

@final
class ResourceOwner(BaseRecord):
    """
    A thread that owns an executive resource.
    """
    __match_args__: Final[tuple[Literal["thread"], Literal["count"]]]
    @property
    def count(self, /) -> int:
        """
        The number of times that the thread acquired the resource.
        """
    @property
    def thread(self, /) -> int: ...

@final
class RunStatus(BaseRecord):
    """
    Whether the target runs, and where it stopped: the read-only status
    surface. `coherent` is false after a reboot until the kernel's
    loaded-module list exists, so a host knows process/module enumeration is
    not yet meaningful.
    """
    __match_args__: Final[tuple[Literal["running"], Literal["current_thread"], Literal["rip"], Literal["symbol"], Literal["saved_vtl"], Literal["serving"], Literal["running_vp"], Literal["attached_process"], Literal["stopped_process"], Literal["stopped_thread"], Literal["coherent"], Literal["kernel_base"], Literal["partition"]]]
    @property
    def attached_process(self, /) -> ProcessInfo |None:
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
        The `nt` base that ntoseye found again. It changes across a reboot,
        so a host can cache it to notice one.
        """
    @property
    def partition(self, /) -> int |None:
        """
        The hypervisor partition whose Windows guest is inspected in place
        of the target (`.partition`), or None while the target is. Every
        other field is then that guest's.
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer when halted. None while the target runs.
        """
    @property
    def running(self, /) -> bool: ...
    @property
    def running_vp(self, /) -> str |None:
        """
        The guest partition's virtual processor that the halted vCPU runs
        (`partition 0x5 VP 2`), whose registers and code the vCPU then
        shows, or None.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtl]:
        """
        For a vCPU halted in the Windows hypervisor, the VTL states that the
        hypervisor saved for the vCPU's virtual processor, VTL0 first.
        """
    @property
    def serving(self, /) -> ServedVp |None:
        """
        For a vCPU halted in the Windows hypervisor, the guest partition's
        virtual processor whose exit it handles, when it is not the root's.
        """
    @property
    def stopped_process(self, /) -> ProcessInfo |None:
        """
        The process whose page tables the stopped vCPU has loaded (from
        CR3), refreshed at every stop.
        """
    @property
    def stopped_thread(self, /) -> ThreadInfo |None:
        """
        The Windows thread that the stopped vCPU runs, walked from its KPRCB
        at this stop. Its owner can be different from `stopped_process`
        (`KeStackAttachProcess`).
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
    __match_args__: Final[tuple[Literal["index"], Literal["kpcr"], Literal["prcb"], Literal["current_thread"], Literal["next_thread"], Literal["idle_thread"], Literal["short_stack"]]]
    @property
    def current_thread(self, /) -> Diagnostic[ThreadInfo |None]:
        """
        The thread that runs on the processor. The value inside is `None` if
        no thread runs.
        """
    @property
    def idle_thread(self, /) -> Diagnostic[ThreadInfo |None]:
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
    def next_thread(self, /) -> Diagnostic[ThreadInfo |None]:
        """
        The thread selected to run next. The value inside is `None` if there
        is no next thread.
        """
    @property
    def prcb(self, /) -> Diagnostic[int]: ...
    @property
    def short_stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The first frames of the running thread; `None` if stacks were not
        requested.
        """

@final
class RunningProcessors(BaseRecord):
    """
    The running threads of all processors (`!running`).
    """
    __match_args__: Final[tuple[Literal["processors"]]]
    @property
    def processors(self, /) -> list[RunningProcessor]: ...

@final
class RuntimeFunction(BaseRecord):
    """
    One function-table entry and its unwind data. Addresses are absolute,
    and the `*_rva` fields hold the raw image-relative values.
    """
    __match_args__: Final[tuple[Literal["begin"], Literal["end"], Literal["begin_rva"], Literal["end_rva"], Literal["unwind_info"], Literal["unwind_data"], Literal["symbol"], Literal["unwind"]]]
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
        the packed unwind data on ARM64 when its low two bits (the flag) are
        not zero.
        """
    @property
    def unwind_info(self, /) -> int |None:
        """
        The address of the unwind info. None for ARM64 packed unwind data.
        """

@final
class SavedVtl(BaseRecord):
    """
    One VTL of a virtual processor, as the Windows hypervisor last saved it
    in the VTL's Enlightened VMCS, with the symbol where it left off. A VMCS
    holds no general-purpose register other than `rsp`; `general_registers`
    has the others when they are known.
    """
    __match_args__: Final[tuple[()]]
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
    def general_registers(self, /) -> dict[str, int] |None:
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
    __match_args__: Final[tuple[Literal["processor"], Literal["queue"], Literal["message"]]]
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
    One PE section with its name, RVA, mapped size, and `rwx` permissions
    (`Module.sections`).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["rva"], Literal["size"], Literal["permissions"]]]
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
class SectionHeader(BaseRecord):
    """
    One `IMAGE_SECTION_HEADER`.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["virtual_size"], Literal["virtual_address"], Literal["size_of_raw_data"], Literal["pointer_to_raw_data"], Literal["pointer_to_relocations"], Literal["pointer_to_linenumbers"], Literal["number_of_relocations"], Literal["number_of_linenumbers"], Literal["characteristics"]]]
    @property
    def characteristics(self, /) -> int: ...
    @property
    def characteristics_names(self, /) -> list[str]:
        """
        The `IMAGE_SCN_*` flags that are set, then the alignment and the
        access, as WinDbg lists them.
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
    __match_args__: Final[tuple[Literal["address"], Literal["revision"], Literal["control"], Literal["control_names"], Literal["self_relative"], Literal["owner"], Literal["group"], Literal["dacl"], Literal["sacl"], Literal["unsupported_revision"]]]
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
class SegContext(BaseRecord):
    """
    A segment context (`_HEAP_SEG_CONTEXT`) of a segment heap.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["unit_shift"], Literal["segment_mask"], Literal["max_allocation_size"]]]
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
class SegmentContextDetail(BaseRecord):
    """
    A segment context with its page segments.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["segments"]]]
    @property
    def header(self, /) -> SegContext: ...
    @property
    def segments(self, /) -> list[SegmentPageDetail]: ...

@final
class SegmentDetail(BaseRecord):
    """
    A control area's `_SEGMENT`.
    """
    __match_args__: Final[tuple[Literal["total_ptes"], Literal["size"], Literal["committed_pages"], Literal["prototype_ptes"]]]
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
class SegmentHeap(BaseRecord):
    """
    A segment heap (`_SEGMENT_HEAP`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["global_flags"], Literal["reserved_pages"], Literal["committed_pages"], Literal["free_committed_pages"], Literal["lfh_free_committed_pages"], Literal["vs_free_committed_pages"], Literal["large_reserved_pages"], Literal["large_committed_pages"], Literal["large_allocations"], Literal["keys"], Literal["granule"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def committed_pages(self, /) -> int: ...
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
        chunk: 16 on x64, 8 on x86. Chunk sizes are in this unit.
        """
    @property
    def keys(self, /) -> SegmentKeys:
        """
        `ntdll!RtlpHpHeapGlobals`: the VS header key and the LFH offsets key.
        """
    @property
    def large_allocations(self, /) -> list[LargeAllocation]: ...
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
class SegmentHeapDetail(BaseRecord):
    """
    A segment heap with its segment contexts.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["contexts"]]]
    @property
    def contexts(self, /) -> list[SegmentContextDetail]: ...
    @property
    def header(self, /) -> SegmentHeap: ...

@final
class SegmentKeys(BaseRecord):
    """
    `ntdll!RtlpHpHeapGlobals`: the encoding keys of a segment heap.
    """
    __match_args__: Final[tuple[Literal["heap_key"], Literal["lfh_key"]]]
    @property
    def heap_key(self, /) -> int:
        """
        The VS chunk header key (`HeapKey`).
        """
    @property
    def lfh_key(self, /) -> int:
        """
        The LFH block-offsets key (`LfhKey`).
        """

@final
class SegmentPageDetail(BaseRecord):
    """
    A page segment with its page ranges.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["ranges"]]]
    @property
    def header(self, /) -> PageSegment: ...
    @property
    def ranges(self, /) -> list[SegmentRangeDetail]: ...

@final
class SegmentRangeDetail(BaseRecord):
    """
    A page range with its decoded subsegment.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["subsegment"], Literal["blocks"], Literal["error"], Literal["truncated"]]]
    @property
    def blocks(self, /) -> list[HeapBlock]:
        """
        The VS chunks or LFH blocks of the subsegment. Empty unless the
        entries were listed.
        """
    @property
    def error(self, /) -> str |None:
        """
        The reason that ntoseye could not read the subsegment.
        """
    @property
    def header(self, /) -> PageRange: ...
    @property
    def subsegment(self, /) -> VsSubsegment |LfhSubsegment |None:
        """
        The VS or LFH subsegment in the range. `None` for other kinds, or if
        ntoseye cannot read the subsegment.
        """
    @property
    def truncated(self, /) -> bool:
        """
        Whether the subsegment has more blocks than the walk limit.
        """

@final
class ServedVp(BaseRecord):
    """
    The guest partition's virtual processor that a processor in the
    Windows hypervisor runs or last ran: the VP whose exit it handles, or
    which it is about to enter, rather than one of the root's.
    """
    __match_args__: Final[tuple[Literal["partition_id"], Literal["vp_index"], Literal["vtl"]]]
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
    def general_registers(self, /) -> dict[str, int] |None:
        """
        The guest's general-purpose registers other than `rsp` at the last
        exit, as `SavedVtl.general_registers`. None when they are not
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
    __match_args__: Final[tuple[Literal["id"], Literal["processes"]]]
    @property
    def id(self, /) -> int |None:
        """
        `None` for processes whose session is unknown.
        """
    @property
    def processes(self, /) -> list[ProcessInfo]:
        """
        The processes in the session.
        """

@final
class SessionProcess(BaseRecord):
    """
    A process and its session (`!sprocess`).
    """
    __match_args__: Final[tuple[Literal["process"], Literal["session"]]]
    @property
    def process(self, /) -> ProcessInfo: ...
    @property
    def session(self, /) -> int |None:
        """
        `None` if the session is unknown.
        """

@final
class SessionProcesses(BaseRecord):
    """
    The processes of a session, filtered by an image glob (`!sprocess`).
    """
    __match_args__: Final[tuple[Literal["selected_session"], Literal["processes"], Literal["process_count"], Literal["truncated"]]]
    @property
    def process_count(self, /) -> int: ...
    @property
    def processes(self, /) -> list[SessionProcess]: ...
    @property
    def selected_session(self, /) -> int |None:
        """
        The selected session. `None` if you selected all sessions, or if the
        session of the process is unknown.
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
    __match_args__: Final[tuple[Literal["selected_session"], Literal["sessions"], Literal["process_count"], Literal["truncated"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["text"], Literal["revision"], Literal["authority"], Literal["sub_authorities"], Literal["well_known"]]]
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
    def sub_authorities(self, /) -> list[int]: ...
    @property
    def text(self, /) -> str:
        """
        The canonical string form (`S-1-5-18`).
        """
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
    __match_args__: Final[tuple[Literal["sid"], Literal["attributes"]]]
    @property
    def attributes(self, /) -> int: ...
    @property
    def sid(self, /) -> str: ...

class Signal(BaseRecord):
    """
    When one side of a queue asks the other to signal it: the driver asks
    the device for interrupts, the device asks the driver for
    notifications (kicks).
    """
    @property
    def kind(self, /) -> Literal["on", "off", "after", "at"]:
        """
        The variant: `on`, `off`, `after`, `at`.
        """
    @final
    class After(Signal):
        """
        Once a split ring's index passes this one (`used_event` or
        `avail_event`, with the event index feature).
        """
        __match_args__: Final[tuple[Literal["value"]]]
        @property
        def kind(self, /) -> Literal["after"]:
            """
            `after`.
            """
        @property
        def value(self, /) -> int: ...
    @final
    class At(Signal):
        """
        Once a packed ring reaches this position in this lap.
        """
        __match_args__: Final[tuple[Literal["value"], Literal["lap"]]]
        @property
        def kind(self, /) -> Literal["at"]:
            """
            `at`.
            """
        @property
        def lap(self, /) -> bool: ...
        @property
        def value(self, /) -> int: ...
    @final
    class Off(Signal):
        """
        Never: the side set the flag that turns signals off.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["off"]:
            """
            `off`.
            """
    @final
    class On(Signal):
        """
        After every buffer.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["on"]:
            """
            `on`.
            """

@final
class SmbiosField(BaseRecord):
    """
    A field of an SMBIOS structure, by the specification's name.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["value"]]]
    @property
    def name(self, /) -> str: ...
    @property
    def value(self, /) -> str: ...

@final
class SmbiosStructure(BaseRecord):
    """
    One SMBIOS structure: its header, its formatted area, and its strings.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["handle"], Literal["formatted"], Literal["strings"]]]
    @property
    def fields(self, /) -> list[SmbiosField]:
        """
        The fields `!sysinfo smbios` decodes for its type.
        """
    @property
    def formatted(self, /) -> list[int]:
        """
        The formatted area, header included, so offsets are the
        specification's.
        """
    @property
    def handle(self, /) -> int: ...
    @property
    def kind(self, /) -> int:
        """
        The structure type (0 BIOS, 1 system, 4 processor, 17 memory
        device, ...).
        """
    @property
    def kind_name(self, /) -> str:
        """
        The DMTF name of the type.
        """
    @property
    def strings(self, /) -> list[str]:
        """
        The strings, string 1 first.
        """

@final
class SmbiosTable(BaseRecord):
    """
    The SMBIOS table the kernel found at boot (`!sysinfo smbios`).
    """
    __match_args__: Final[tuple[Literal["physical_address"], Literal["length"], Literal["structures"], Literal["stopped"]]]
    @property
    def length(self, /) -> int: ...
    @property
    def physical_address(self, /) -> int: ...
    @property
    def stopped(self, /) -> str |None:
        """
        Why the parse stopped before End-of-Table.
        """
    @property
    def structures(self, /) -> list[SmbiosStructure]: ...
    @property
    def version(self, /) -> str:
        """
        The version the entry point gave (`2.8`).
        """

@final
class SourceLocation(BaseRecord):
    """
    PDB source metadata for an address.
    """
    __match_args__: Final[tuple[Literal["file"], Literal["line"], Literal["column"]]]
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
    def local_state(self, /) -> Literal["found", "missing", "differs"] |None:
        """
        `found`, `missing`, or `differs`. `found` means that the file is
        there and, if the PDB records a checksum, that it is the compiled
        file. `differs` means that the file is there but its checksum does
        not match the compiled file. `None` if `local_path` is `None`.
        """

@final
class SourcePath(BaseRecord):
    """
    The ordered local source path mappings (`.srcpath`).
    """
    __match_args__: Final[tuple[Literal["mappings"]]]
    @property
    def mappings(self, /) -> list[str]: ...

@final
class SpecialRegistersArea(BaseRecord):
    """
    The location of `_KSPECIAL_REGISTERS` in a processor state.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["size"], Literal["name"]]]
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
class SplitRing(BaseRecord):
    """
    A split ring as guest memory holds it.
    """
    __match_args__: Final[tuple[Literal["size"], Literal["desc"], Literal["avail"], Literal["used"], Literal["avail_flags"], Literal["avail_idx"], Literal["used_flags"], Literal["used_idx"], Literal["used_event"], Literal["avail_event"]]]
    @property
    def avail(self, /) -> int:
        """
        The avail ring.
        """
    @property
    def avail_event(self, /) -> int |None: ...
    @property
    def avail_flags(self, /) -> int: ...
    @property
    def avail_idx(self, /) -> int: ...
    @property
    def desc(self, /) -> int:
        """
        The descriptor table.
        """
    @property
    def size(self, /) -> int: ...
    @property
    def used(self, /) -> int:
        """
        The used ring.
        """
    @property
    def used_event(self, /) -> int |None:
        """
        With the event index feature: the used index after which the
        driver wants an interrupt (the slot after the avail ring's entries),
        and the avail index after which the device wants a notification
        (the slot after the used ring's). `None` where unreadable.
        """
    @property
    def used_flags(self, /) -> int: ...
    @property
    def used_idx(self, /) -> int: ...

@final
class Srb(BaseRecord):
    """
    A decoded SRB (`!storagekd.storsrb`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["extended"], Literal["function"], Literal["srb_status"], Literal["scsi_status"], Literal["flags"], Literal["port"], Literal["path"], Literal["target"], Literal["lun"], Literal["data_transfer_length"], Literal["data_buffer"], Literal["timeout"], Literal["original_request"], Literal["next_srb"], Literal["request_tag"], Literal["priority"], Literal["cdb"], Literal["sense_buffer"], Literal["sense_length"], Literal["sense"], Literal["class_context"], Literal["port_context"], Literal["miniport_context"], Literal["ex_data"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def cdb(self, /) -> list[int]: ...
    @property
    def class_context(self, /) -> int |None:
        """
        The contexts an extended SRB keeps for the class driver, the port
        driver, and the miniport; a legacy one has none.
        """
    @property
    def command(self, /) -> str |None:
        """
        The CDB's command, with its LBA and block count when it has them.
        """
    @property
    def data_buffer(self, /) -> int: ...
    @property
    def data_transfer_length(self, /) -> int: ...
    @property
    def ex_data(self, /) -> list[SrbExData]: ...
    @property
    def extended(self, /) -> bool:
        """
        A `STORAGE_REQUEST_BLOCK`, rather than a `SCSI_REQUEST_BLOCK`.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `SRB_FLAGS_*` names of the flags.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def function(self, /) -> int:
        """
        `SrbFunction` of an extended SRB, else `Function`.
        """
    @property
    def function_name(self, /) -> str |None:
        """
        The function by `SRB_FUNCTION_*` name, without the prefix.
        """
    @property
    def lun(self, /) -> int |None: ...
    @property
    def miniport_context(self, /) -> int |None: ...
    @property
    def next_srb(self, /) -> int: ...
    @property
    def original_request(self, /) -> int:
        """
        `OriginalRequest`: the IRP the SRB carries.
        """
    @property
    def path(self, /) -> int |None:
        """
        The path, target, and LUN, when the SRB has a BTL8 address.
        """
    @property
    def port(self, /) -> int |None:
        """
        An extended SRB's port; a legacy one has none.
        """
    @property
    def port_context(self, /) -> int |None: ...
    @property
    def priority(self, /) -> int |None: ...
    @property
    def request_tag(self, /) -> int |None: ...
    @property
    def scsi_status(self, /) -> int |None: ...
    @property
    def sense(self, /) -> str |None:
        """
        The sense data, decoded, when `SRB_STATUS_AUTOSENSE_VALID` says it
        holds some.
        """
    @property
    def sense_buffer(self, /) -> int: ...
    @property
    def sense_length(self, /) -> int: ...
    @property
    def srb_status(self, /) -> int: ...
    @property
    def srb_status_text(self, /) -> str:
        """
        The status by name, with `QUEUE_FROZEN` and `AUTOSENSE_VALID`.
        """
    @property
    def target(self, /) -> int |None: ...
    @property
    def timeout(self, /) -> int:
        """
        Seconds.
        """

@final
class SrbExData(BaseRecord):
    """
    One block of an extended SRB's extended data (`SRBEX_DATA`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["kind"], Literal["length"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def kind(self, /) -> str:
        """
        `_SRBEXDATATYPE` without its `SrbExDataType` prefix (`ScsiCdb16`).
        """
    @property
    def length(self, /) -> int: ...

@final
class SsdtEntry(BaseRecord):
    """
    A slot in a system-service table.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["target"], Literal["symbol"], Literal["module"]]]
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
    __match_args__: Final[tuple[Literal["label"], Literal["base"], Literal["limit"], Literal["entries"]]]
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
    __match_args__: Final[tuple[Literal["ip"], Literal["sp"], Literal["symbol"], Literal["inline"], Literal["source"], Literal["source_location"]]]
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
    def source(self, /) -> Literal["current", "seed", "unwind", "prolog", "scan"]:
        """
        How ntoseye recovered the frame.
        """
    @property
    def source_location(self, /) -> SourceLocation |None:
        """
        The source line of the frame, if line information resolves it. For
        an inline frame this is the line in the inlined function, and for a
        caller it is the line of the call (see
        [`SymbolStore::frame_source_location`]).
        """
    @property
    def sp(self, /) -> int:
        """
        The stack pointer.
        """
    @property
    def symbol(self, /) -> str:
        """
        The symbol at `ip` (`module!procedure+offset`). For an inline frame,
        `module!function`, the function inlined. Empty if no symbol
        resolves.
        """

@final
class StateHistoryEntry(BaseRecord):
    """
    A nonzero entry in the `StateHistory` ring of a device node.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["state"], Literal["state_name"]]]
    @property
    def index(self, /) -> int:
        """
        Its slot in the ring.
        """
    @property
    def state(self, /) -> int: ...
    @property
    def state_name(self, /) -> str: ...

class Stop(BaseRecord):
    """
    Why the target stopped, with the context it stopped in, snapshotted at
    the stop. Each kind is a subclass with that kind's own parts:
    `Stop.Breakpoint` (`breakpoint`), `Stop.Exception` (`exception`),
    `Stop.ModuleLoad` and `Stop.ModuleUnload` (`module`), `Stop.Bugcheck`
    (`bugcheck`), `Stop.Reload` (`reload`), `Stop.Step`, `Stop.Interrupt`
    and `Stop.Entry`; `isinstance` and `match` tell them apart, as `kind`
    does.
    
    The parts are records, not live handles; the collections take them as
    keys: `dbg.threads[stop.thread]`, `dbg.processes[stop.process]`,
    `dbg.modules[stop.module]`; `dbg.cpus[stop.cpu]` is the processor.
    """
    __match_args__: Final[tuple[Literal["kind"], Literal["cpu"], Literal["rip"], Literal["symbol"], Literal["process"], Literal["thread"], Literal["inspection_process"], Literal["vtl"], Literal["partition"]]]
    @property
    def cpu(self, /) -> int |None:
        """
        The zero-based number of the processor that stopped, as `dbg.cpus`
        numbers them in the current view; `None` on a user-mode minidump,
        whose threads are no processors.
        """
    def hit(self, /, bp: Breakpoint) -> bool:
        """
        Whether breakpoint `bp` is the one that stopped the target. `bp`
        may be deleted since (a one-shot breakpoint that fired).
        """
    @property
    def inspection_process(self, /) -> ProcessInfo |None:
        """
        The `.process` inspection scope at the stop, which can differ from
        `process`.
        """
    @property
    def kind(self, /) -> Literal["breakpoint", "exception", "interrupt", "step", "module_load", "module_unload", "bugcheck", "reload", "entry"]:
        """
        The kind of stop, in snake case.
        """
    @property
    def partition(self, /) -> int |None:
        """
        The hypervisor partition whose view (`.partition`) shows the stop.
        """
    @property
    def process(self, /) -> ProcessInfo |None:
        """
        The process whose page tables the stopped vCPU has loaded (its CR3).
        """
    @property
    def rip(self, /) -> int |None:
        """
        Where it stopped. A bugcheck's fault site is in `bugcheck`, a
        breakpoint's address in `breakpoint`, an exception's in `exception`.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol to `rip`, named in the stopped vCPU's own address
        space.
        """
    @property
    def thread(self, /) -> ThreadInfo |None:
        """
        The Windows thread the stopped vCPU runs.
        """
    @property
    def vtl(self, /) -> int |None:
        """
        The VTL the stopped vCPU runs in (1: the secure kernel); `None` for a
        user dump.
        """
    @final
    class Breakpoint(Stop):
        """
        A breakpoint or watchpoint hit.
        """
        __match_args__: Final[tuple[Literal["breakpoint"]]]
        @property
        def breakpoint(self, /) -> BreakpointHit: ...
        @property
        def kind(self, /) -> Literal["breakpoint"]:
            """
            `breakpoint`.
            """
    @final
    class Bugcheck(Stop):
        """
        The guest is in a bugcheck. `bugcheck` is the code and parameters
        when the transport decoded them (`None` otherwise);
        `dbg.inspect.bugcheck()` reads and analyzes the bugcheck from guest
        memory (`!analyze`).
        """
        __match_args__: Final[tuple[Literal["bugcheck"]]]
        @property
        def bugcheck(self, /) -> BugcheckInfo |None: ...
        @property
        def kind(self, /) -> Literal["bugcheck"]:
            """
            `bugcheck`.
            """
    @final
    class Entry(Stop):
        """
        Nothing stopped the target since the debugger attached: it was found
        halted (a dump, a target attached halted).
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["entry"]:
            """
            `entry`.
            """
    @final
    class Exception(Stop):
        """
        A Windows exception.
        """
        __match_args__: Final[tuple[Literal["exception"]]]
        @property
        def exception(self, /) -> ExceptionStop: ...
        @property
        def kind(self, /) -> Literal["exception"]:
            """
            `exception`.
            """
    @final
    class Interrupt(Stop):
        """
        A requested break-in, or a stop with no exception code.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["interrupt"]:
            """
            `interrupt`.
            """
    @final
    class ModuleLoad(Stop):
        """
        A kernel image loaded, and a `ld` filter set to `break` names it
        (`dbg.exceptions.set_module_event("ld", ...)`, `sxe ld`). The module
        is listed with its symbols and breakpoints, and its entry point has
        not run.
        """
        __match_args__: Final[tuple[Literal["module"]]]
        @property
        def kind(self, /) -> Literal["module_load"]:
            """
            `module_load`.
            """
        @property
        def module(self, /) -> ModuleInfo: ...
    @final
    class ModuleUnload(Stop):
        """
        A kernel image is unloading, and a `ud` filter set to `break` names
        it (`sxe ud`). Its unload routine has run, and it is still listed.
        """
        __match_args__: Final[tuple[Literal["module"]]]
        @property
        def kind(self, /) -> Literal["module_unload"]:
            """
            `module_unload`.
            """
        @property
        def module(self, /) -> ModuleInfo: ...
    @final
    class Reload(Stop):
        """
        The guest rebooted and the debugger rebuilt its state; earlier
        handles are stale.
        """
        __match_args__: Final[tuple[Literal["reload"]]]
        @property
        def kind(self, /) -> Literal["reload"]:
            """
            `reload`.
            """
        @property
        def reload(self, /) -> ReloadStop: ...
    @final
    class Step(Stop):
        """
        A completed step, or a run to an address that reached it.
        """
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["step"]:
            """
            `step`.
            """

@final
class StorAdapter(BaseRecord):
    """
    A StorPort adapter (`_RAID_ADAPTER_EXTENSION`), the FDO storport creates
    for each device the miniport drives.
    """
    __match_args__: Final[tuple[Literal["extension"], Literal["driver"], Literal["driver_object"], Literal["driver_name"], Literal["fdo"], Literal["pdo"], Literal["lower"], Literal["device_name"], Literal["port_number"], Literal["miniport_name"], Literal["adapter_id"], Literal["state"], Literal["flags"], Literal["interface"], Literal["virtual_miniport"], Literal["hw_device_extension"], Literal["hw_device_extension_size"], Literal["lu_extension_size"], Literal["system_power"], Literal["device_power"], Literal["paging_paths"], Literal["dump_paths"], Literal["hiber_paths"], Literal["pause_count"], Literal["busy_count"], Literal["gateways"], Literal["gateways_error"], Literal["units"], Literal["units_stopped"]]]
    @property
    def adapter_id(self, /) -> str |None: ...
    @property
    def busy_count(self, /) -> int:
        """
        `StorPortBusy` calls not yet readied.
        """
    @property
    def device_name(self, /) -> str:
        """
        The FDO's full name, its `Device` directory included
        (`RaidPort0` in the `Device` directory).
        """
    @property
    def device_power(self, /) -> StorEnumValue: ...
    @property
    def driver(self, /) -> int:
        """
        The `_RAID_DRIVER_EXTENSION`.
        """
    @property
    def driver_name(self, /) -> str: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def dump_paths(self, /) -> int: ...
    @property
    def extension(self, /) -> int: ...
    @property
    def fdo(self, /) -> int: ...
    @property
    def flags(self, /) -> list[str]: ...
    @property
    def gateways(self, /) -> list[StorGateway]: ...
    @property
    def gateways_error(self, /) -> str |None:
        """
        Why the gateways are not all shown.
        """
    @property
    def hiber_paths(self, /) -> int: ...
    @property
    def hw_device_extension(self, /) -> int:
        """
        The miniport's own device extension, the one StorPort passes to every
        Hw routine: the structure its private PDB describes.
        """
    @property
    def hw_device_extension_size(self, /) -> int |None: ...
    @property
    def interface(self, /) -> StorEnumValue: ...
    @property
    def io(self, /) -> str:
        """
        What holds the adapter's requests, as `!storagekd.storadapter` says
        it: `idle`, `2 with the miniport`, `paused`, ...
        """
    @property
    def lower(self, /) -> int: ...
    @property
    def lu_extension_size(self, /) -> int |None:
        """
        The size of the per-unit extension the miniport asked for.
        """
    @property
    def miniport_name(self, /) -> str |None: ...
    @property
    def paging_paths(self, /) -> int: ...
    @property
    def pause_count(self, /) -> int:
        """
        `StorPortPause` calls not yet resumed.
        """
    @property
    def pci_location(self, /) -> str |None:
        """
        `bb:dd.f` of a PCI adapter.
        """
    @property
    def pdo(self, /) -> int: ...
    @property
    def port_number(self, /) -> int:
        """
        The SCSI port number (the `0` of the `Scsi0:` DOS device).
        """
    @property
    def state(self, /) -> StorEnumValue: ...
    @property
    def system_power(self, /) -> StorEnumValue: ...
    @property
    def units(self, /) -> list[StorUnitEntry]: ...
    @property
    def units_stopped(self, /) -> str |None:
        """
        Why the walk of the unit list stopped short of its head.
        """
    @property
    def virtual_miniport(self, /) -> bool:
        """
        The miniport registered as a virtual miniport.
        """

@final
class StorAdapterEntry(BaseRecord):
    """
    One entry of a driver's adapter list: a StorPort adapter, or why it is
    not shown.
    """
    __match_args__: Final[tuple[Literal["extension"]]]
    @property
    def adapter(self, /) -> StorAdapter |None:
        """
        The adapter, when it reads.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the adapter is not shown.
        """
    @property
    def extension(self, /) -> int: ...

@final
class StorDriver(BaseRecord):
    """
    A driver that called `StorPortInitialize` (`_RAID_DRIVER_EXTENSION`).
    """
    __match_args__: Final[tuple[Literal["extension"], Literal["driver_object"], Literal["name"], Literal["adapters"], Literal["stopped"]]]
    @property
    def adapters(self, /) -> list[StorAdapterEntry]: ...
    @property
    def driver_object(self, /) -> int: ...
    @property
    def extension(self, /) -> int: ...
    @property
    def name(self, /) -> str:
        """
        The service name (`storahci`), from the driver object's name.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the adapter list stopped short of its head.
        """

@final
class StorDrivers(BaseRecord):
    """
    storport's drivers and their adapters, from `RaidpPortData`
    (`!storagekd.storadapter`).
    """
    __match_args__: Final[tuple[Literal["port_data"], Literal["drivers"], Literal["stopped"]]]
    @property
    def drivers(self, /) -> list[StorDriver]: ...
    @property
    def port_data(self, /) -> int:
        """
        `storport!RaidpPortData`.
        """
    @property
    def stopped(self, /) -> str |None:
        """
        Why the walk of the driver list stopped short of its head.
        """

@final
class StorEnumValue(BaseRecord):
    """
    A value of one of storport's enums, with its name when the PDB has one.
    """
    __match_args__: Final[tuple[Literal["value"], Literal["name"]]]
    @property
    def name(self, /) -> str |None: ...
    @property
    def value(self, /) -> int: ...

@final
class StorGateway(BaseRecord):
    """
    An adapter's I/O gateway (`_STOR_IO_GATEWAY`): what limits the requests
    the adapter sends to the miniport.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["outstanding"], Literal["outstanding_max"], Literal["pending"], Literal["busy"], Literal["paused"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def busy(self, /) -> int: ...
    @property
    def outstanding(self, /) -> int:
        """
        Requests the miniport holds.
        """
    @property
    def outstanding_max(self, /) -> int:
        """
        The most the gateway lets the miniport hold.
        """
    @property
    def paused(self, /) -> int: ...
    @property
    def pending(self, /) -> int:
        """
        Requests waiting for the gateway to let them through.
        """

@final
class StorLog(BaseRecord):
    """
    A StorPort adapter's internal log (`!storagekd.storloglist`): a ring of
    `RaidLogListSize` entries that storport writes as it starts, completes,
    pauses, and resumes requests.
    """
    __match_args__: Final[tuple[Literal["adapter"], Literal["driver_name"], Literal["ring"], Literal["size"], Literal["newest"], Literal["entries"]]]
    @property
    def adapter(self, /) -> int: ...
    @property
    def driver_name(self, /) -> str: ...
    @property
    def entries(self, /) -> list[StorLogEntry]:
        """
        The entries still in the ring, oldest first.
        """
    @property
    def newest(self, /) -> int:
        """
        The number of the newest entry, which is how many storport wrote.
        """
    @property
    def ring(self, /) -> int:
        """
        The ring (`RaidLogList`) and its size.
        """
    @property
    def size(self, /) -> int: ...

@final
class StorLogEntry(BaseRecord):
    """
    An entry of an adapter's internal log (`_RAID_LOG_ENTRY`).
    """
    __match_args__: Final[tuple[Literal["number"], Literal["time"], Literal["parameters"]]]
    @property
    def command(self, /) -> str |None:
        """
        For an entry of the request path: the command its operation code
        names.
        """
    @property
    def event(self, /) -> str |None:
        """
        `_DBG_LOG_REASON` without its `Log` prefix.
        """
    @property
    def event_value(self, /) -> int: ...
    @property
    def irp(self, /) -> int |None:
        """
        For an entry of the request path: its IRP.
        """
    @property
    def number(self, /) -> int:
        """
        The entry's number: storport numbers them from 1 as it writes them.
        """
    @property
    def opcode(self, /) -> int |None:
        """
        For an entry of the request path: its CDB's operation code.
        """
    @property
    def parameters(self, /) -> list[int]: ...
    @property
    def srb(self, /) -> int |None:
        """
        For an entry of the request path: its SRB.
        """
    @property
    def srb_status(self, /) -> str |None:
        """
        For an entry of the request path: its SRB status, by name.
        """
    @property
    def time(self, /) -> int:
        """
        When storport wrote it, as a FILETIME (UTC).
        """
    @property
    def time_utc(self, /) -> str |None:
        """
        `time` as text (UTC).
        """

@final
class StorQueue(BaseRecord):
    """
    A unit's device queue (`_EXTENDED_DEVICE_QUEUE`).
    """
    __match_args__: Final[tuple[Literal["depth"], Literal["pause_count"], Literal["busy_count"], Literal["frozen"], Literal["locked"], Literal["untagged"], Literal["power_locked"], Literal["bypass_count"], Literal["waiting"], Literal["bypass_waiting"], Literal["waiting_stopped"]]]
    @property
    def busy_count(self, /) -> int:
        """
        `StorPortDeviceBusy` calls not yet readied.
        """
    @property
    def bypass_count(self, /) -> int:
        """
        Requests that bypass the queue.
        """
    @property
    def bypass_waiting(self, /) -> int:
        """
        Requests waiting to bypass the queue.
        """
    @property
    def depth(self, /) -> int:
        """
        How many requests the queue lets the miniport hold.
        """
    @property
    def frozen(self, /) -> bool:
        """
        Frozen after an error until the class driver releases it.
        """
    @property
    def locked(self, /) -> bool:
        """
        Locked by the class driver (`SRB_FUNCTION_LOCK_QUEUE`).
        """
    @property
    def pause_count(self, /) -> int:
        """
        `StorPortPauseDevice` calls not yet resumed.
        """
    @property
    def power_locked(self, /) -> bool: ...
    @property
    def untagged(self, /) -> bool: ...
    @property
    def waiting(self, /) -> int:
        """
        Requests waiting because the queue is full or held.
        """
    @property
    def waiting_stopped(self, /) -> list[str]:
        """
        Why a count of waiting requests is short.
        """

@final
class StorRequest(BaseRecord):
    """
    A request the miniport holds: storport's `_EXTENDED_REQUEST_BLOCK` and
    the IRP and SRB it carries.
    """
    __match_args__: Final[tuple[Literal["xrb"], Literal["irp"], Literal["srb"], Literal["processor"]]]
    @property
    def irp(self, /) -> int: ...
    @property
    def processor(self, /) -> int:
        """
        The processor whose pending queue holds it.
        """
    @property
    def srb(self, /) -> int: ...
    @property
    def xrb(self, /) -> int: ...

@final
class StorUnit(BaseRecord):
    """
    A logical unit (`_RAID_UNIT_EXTENSION`), the PDO storport creates for
    each LUN the miniport reports.
    """
    __match_args__: Final[tuple[Literal["extension"], Literal["device_object"], Literal["adapter"], Literal["path"], Literal["target"], Literal["lun"], Literal["vendor"], Literal["product"], Literal["revision"], Literal["state"], Literal["device_power"], Literal["flags"], Literal["lu_extension"], Literal["max_queue_depth"], Literal["queue"], Literal["requests"], Literal["requests_stopped"]]]
    @property
    def adapter(self, /) -> int: ...
    @property
    def device_object(self, /) -> int: ...
    @property
    def device_power(self, /) -> StorEnumValue: ...
    @property
    def extension(self, /) -> int: ...
    @property
    def flags(self, /) -> list[str]: ...
    @property
    def io(self, /) -> str:
        """
        What holds the unit's requests, as `!storagekd.storunit` says it:
        `idle`, `1 with the miniport`, `frozen`, ...
        """
    @property
    def lu_extension(self, /) -> int:
        """
        The miniport's per-unit extension (`StorPortGetLogicalUnit`); null
        when the miniport asked for none.
        """
    @property
    def lun(self, /) -> int: ...
    @property
    def max_queue_depth(self, /) -> int: ...
    @property
    def path(self, /) -> int:
        """
        The unit's SCSI address.
        """
    @property
    def product(self, /) -> str: ...
    @property
    def queue(self, /) -> StorQueue: ...
    @property
    def requests(self, /) -> list[StorRequest]:
        """
        The requests the miniport holds for the unit, from storport's pending
        queue.
        """
    @property
    def requests_stopped(self, /) -> list[str]:
        """
        Why the requests are not all listed.
        """
    @property
    def revision(self, /) -> str: ...
    @property
    def state(self, /) -> StorEnumValue: ...
    @property
    def target(self, /) -> int: ...
    @property
    def vendor(self, /) -> str: ...

@final
class StorUnitEntry(BaseRecord):
    """
    One entry of an adapter's unit list.
    """
    __match_args__: Final[tuple[Literal["extension"]]]
    @property
    def error(self, /) -> str |None:
        """
        Why the unit is not shown.
        """
    @property
    def extension(self, /) -> int: ...
    @property
    def unit(self, /) -> StorUnit |None:
        """
        The unit, when it reads.
        """

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
class SubsectionDetail(BaseRecord):
    """
    A `_SUBSECTION` after a control area.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["base_pte"], Literal["ptes"], Literal["unused_ptes"], Literal["starting_sector"], Literal["sectors"], Literal["protection"]]]
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
class SummaryRow(BaseRecord):
    """
    Count and total size of the regions in one summary row.
    """
    __match_args__: Final[tuple[Literal["label"], Literal["regions"], Literal["size"]]]
    @property
    def label(self, /) -> str: ...
    @property
    def regions(self, /) -> int: ...
    @property
    def size(self, /) -> int: ...

@final
class Symbol(BaseRecord):
    """
    The symbol nearest below an address (`ln`, `Symbols.nearest()`).
    """
    __match_args__: Final[tuple[Literal["module"], Literal["name"], Literal["address"], Literal["offset"]]]
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
    __match_args__: Final[tuple[Literal["module"], Literal["address"], Literal["visibility"], Literal["compiland"]]]
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
    def visibility(self, /) -> Literal["public", "private"]:
        """
        `public` or `private`.
        """

@final
class SymbolPath(BaseRecord):
    """
    The ordered symbol source path (`.sympath`): local directories and
    symbol servers, tried in order.
    """
    __match_args__: Final[tuple[Literal["sources"]]]
    @property
    def sources(self, /) -> list[str]: ...

@final
class SymbolSearchMatch(BaseRecord):
    """
    A symbol that a name search matched.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["address"], Literal["module"]]]
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
    def locals_at(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> list[ProcedureLocal]:
        """
        List the PDB layouts of the locals and parameters of the innermost frame
        at `addr`, which are those of the inlined call if the compiler inlined a
        call there. This method does not evaluate the values.
        """
    def nearest(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Symbol |None:
        """
        List the symbol nearest to an address.
        """
    @property
    def path(self, /) -> list[str]:
        """
        The ordered symbol sources (`.sympath`). An assignment replaces the full path.
        """
    @path.setter
    def path(self, /, sources: Sequence[str]) -> None: ...
    def reload(self, /, *, scope: Literal["current", "kernel", "user"] |None = None, module: str |None = None) -> ModuleSymbolLoadReport:
        """
        Reload symbols for the modules in the current scope, or for the modules a name or pattern names.
        
        Asks the symbol path again for each module's PDB, whatever failed before,
        and loads it at once. The current scope's modules are the selected
        process's user-mode modules, else the kernel's; /n reloads the kernel's
        and /user the selected process's. A module is a name such as nt or
        viostor.sys, or a pattern with * and ? such as vio*. /f and /v are
        accepted as in WinDbg: ntoseye always loads at once, and lm shows each
        module's symbol status.
        """
    def reset_path(self, /) -> SymbolPath:
        """
        Set the symbol source path back to the defaults, the ntoseye cache and the Microsoft symbol server.
        """
    def search(self, /, query: str, limit: int = 50) -> list[SymbolSearchMatch]:
        """
        Search symbol names by fuzzy match. Use `module!query` to search in one module.
        """
    def source_addresses(self, /, file: str, line: int) -> list[int]:
        """
        Get all loaded addresses that match a source file and line.
        """
    def source_location(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> SourceLocation |None:
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
class SystemMemorySummary(BaseRecord):
    """
    System memory counters and per-process usage (`!memusage`).
    """
    __match_args__: Final[tuple[Literal["physical_pages"], Literal["available_pages"], Literal["committed_pages"], Literal["commit_limit_pages"], Literal["paged_pool_pages"], Literal["nonpaged_pool_bytes"], Literal["processes"], Literal["process_count"], Literal["truncated"]]]
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
    __match_args__: Final[tuple[Literal["pte"], Literal["va"], Literal["ptes"]]]
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
class SystemPteTypeDetail(BaseRecord):
    """
    One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are in
    PTEs; the bitmap may cover several PTEs per bit (`ptes_per_bit`).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["address"], Literal["va_type"], Literal["flags"], Literal["ptes_per_bit"], Literal["base_pte"], Literal["base_va"], Literal["bitmap"], Literal["bitmap_bits"], Literal["total"], Literal["free"], Literal["failures"], Literal["bitmap_free"], Literal["unreadable_bitmap_bytes"], Literal["unscanned_bitmap_bits"], Literal["free_run_count"], Literal["largest_free_run"], Literal["free_runs"], Literal["free_runs_truncated"], Literal["tracking"]]]
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
        The free PTEs, counted from the clear bits of the bitmap. It differs
        from `free` only when the target allocated between the two reads.
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
        The free runs in address order, if the list was requested; bounded.
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
        `TotalSystemPtes`, the number of PTEs made available so far; the rest
        of the bitmap is reserved (its bits set) until the allocator expands.
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
        The bits past the read limit for one bitmap (a corrupt
        `SizeOfBitMap`), which no count includes.
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
class SystemPtesDetail(BaseRecord):
    """
    Every system-PTE bitmap allocator in `MiState` (`!sysptes`). Counts
    are in PTEs.
    """
    __match_args__: Final[tuple[Literal["types"], Literal["total"], Literal["free"]]]
    @property
    def free(self, /) -> int: ...
    @property
    def total(self, /) -> int: ...
    @property
    def types(self, /) -> list[SystemPteTypeDetail]: ...
    @property
    def used(self, /) -> int:
        """
        `total` minus `free`.
        """

@final
class TaggedBlock(BaseRecord):
    """
    A tagged data block of a crash dump.
    """
    __match_args__: Final[tuple[Literal["tag"], Literal["size"], Literal["owner"], Literal["holds"]]]
    @property
    def holds(self, /) -> str |None:
        """
        For a tag Windows writes, what the block holds.
        """
    @property
    def owner(self, /) -> str |None:
        """
        For a tag Windows writes, the global that holds it, such as
        `nt!PopBlackBoxPnpGuid`.
        """
    @property
    def size(self, /) -> int:
        """
        The data's size in bytes.
        """
    @property
    def tag(self, /) -> str:
        """
        The GUID tag, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
        """

@final
class TargetDump(BaseRecord):
    """
    The data that a crash dump header records.
    """
    __match_args__: Final[tuple[Literal["is_triage"], Literal["directory_table_base"], Literal["bugcheck_code"], Literal["bugcheck_parameters"], Literal["number_processors"], Literal["major_version"], Literal["minor_version"], Literal["product_type"], Literal["machine_image_type"], Literal["service_pack_build"], Literal["system_time"], Literal["uptime_seconds"], Literal["exception_code"], Literal["triage_overflowed"], Literal["kernel_base"], Literal["tagged_blocks"]]]
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
    def tagged_blocks(self, /) -> list[TaggedBlock]:
        """
        The blocks that bugcheck callbacks added to the dump (`.enumtag`);
        `Inspect.read_tagged` reads one.
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
    __match_args__: Final[tuple[Literal["name"], Literal["short_name"], Literal["base"], Literal["size"], Literal["file_version"], Literal["product_version"], Literal["pdb_guid"], Literal["pdb_age"]]]
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
    The UTC time and uptime of the target (`.time`). A user-mode minidump
    records neither: its `user_dump` says when it was written instead.
    """
    __match_args__: Final[tuple[Literal["system_time"], Literal["system_time_iso"], Literal["interrupt_time"], Literal["uptime_seconds"], Literal["uptime"], Literal["user_dump"]]]
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
    @property
    def user_dump(self, /) -> UserDumpTime |None:
        """
        When a user-mode minidump was written, and its process's times.
        `None` for a kernel target.
        """

@final
class TargetUserDump(BaseRecord):
    """
    A user-mode minidump's process and header.
    """
    __match_args__: Final[tuple[Literal["process_name"], Literal["process_id"], Literal["processor_level"], Literal["processor_revision"], Literal["service_pack"], Literal["flags"], Literal["flag_names"], Literal["threads"], Literal["modules"], Literal["exception_code"]]]
    @property
    def exception_code(self, /) -> int |None:
        """
        The code of the exception the dump was written for.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        `flags` as `MINIDUMP_TYPE` names (`MiniDumpWithFullMemory`, ...).
        """
    @property
    def flags(self, /) -> int:
        """
        The `MINIDUMP_TYPE` flags the dump was written with.
        """
    @property
    def modules(self, /) -> int: ...
    @property
    def process_id(self, /) -> int |None: ...
    @property
    def process_name(self, /) -> str |None: ...
    @property
    def processor_level(self, /) -> int:
        """
        `ProcessorLevel`: on AMD64, the processor family.
        """
    @property
    def processor_revision(self, /) -> int:
        """
        `ProcessorRevision`: on AMD64, the model (high byte) and stepping
        (low byte).
        """
    @property
    def service_pack(self, /) -> str |None: ...
    @property
    def threads(self, /) -> int: ...

@final
class TargetVersion(BaseRecord):
    """
    The version data of the target (`vertarget`), with the build,
    architecture, kernel, symbols, debugger version, time, and dump
    metadata.
    """
    __match_args__: Final[tuple[Literal["major_version"], Literal["minor_version"], Literal["build_number"], Literal["build_lab"], Literal["architecture"], Literal["processors"], Literal["product"], Literal["kernel"], Literal["symbol_status"], Literal["debugger_version"], Literal["symbol_path"], Literal["time"], Literal["backend"], Literal["dump"], Literal["user_dump"]]]
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
    @property
    def user_dump(self, /) -> TargetUserDump |None:
        """
        What a user-mode minidump records of its process and how it was
        written. `None` for a kernel target.
        """

@final
class Teb(BaseRecord):
    """
    A thread's `_TEB` (`!teb`). ntoseye reads each field separately.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["stack_base"], Literal["stack_limit"], Literal["tls_pointer"], Literal["last_error_value"], Literal["last_status_value"], Literal["count_of_owned_critical_sections"], Literal["peb"], Literal["wow_teb_offset"], Literal["wow64_reserved"], Literal["activation_context"], Literal["client_id_unique_process"], Literal["client_id_unique_thread"], Literal["teb32"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["stack_base"], Literal["stack_limit"], Literal["tls_pointer"], Literal["last_error_value"], Literal["last_status_value"], Literal["count_of_owned_critical_sections"], Literal["peb"], Literal["client_id_unique_process"], Literal["client_id_unique_thread"]]]
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
    def base_priority(self, /) -> int |None: ...
    @property
    def cpu(self, /) -> Cpu |None:
        """
        The processor that runs the thread, or `None` if the thread is not running.
        """
    def decode_teb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Teb:
        """
        Decode a thread environment block.
        
        If you do not give an address, the command uses the teb pseudo-register
        of the current thread. On a user-mode minidump it uses the TEB of the
        selected thread (~<n>s), and the layouts of the dump's ntdll.
        """
    @property
    def eprocess(self, /) -> int |None:
        """
        The owning `_EPROCESS`.
        """
    @property
    def ethread(self, /) -> int:
        """
        The `_ETHREAD` address, which identifies the thread.
        """
    @property
    def info(self, /) -> ThreadInfo:
        """
        The `ThreadInfo` record of this handle: its properties as one value.
        """
    def inspect(self, /) -> ThreadDetail:
        """
        Show a Windows thread and, optionally, its kernel stack.
        
        You can also use the legacy `thread <tid> k|r [count]` forms. A numeric
        flags value selects the detail and stack output, and count sets the
        maximum number of stack frames (32 by default, or 16 for `k`). The command
        shows `-` for a field that is not available. If the vCPU of a running
        thread is halted in the Windows hypervisor (VBS), the command shows the
        thread from the VTL0 state that the hypervisor saved, and `.thread`
        selects the thread in the same way. While the target runs, the command
        shows the thread but does not select it, and a thread that runs on a
        processor has no stack.
        """
    @property
    def kernel_stack(self, /) -> int |None:
        """
        `_KTHREAD.KernelStack`, the saved stack pointer of a thread that is
        not running.
        """
    @property
    def kernel_stack_resident(self, /) -> bool |None: ...
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` address.
        """
    def last_error(self, /) -> LastError:
        """
        Show the last Win32 error value and the last NT status value of the
        current thread.
        """
    @property
    def object(self, /) -> Struct:
        """
        The typed `_ETHREAD` object.
        """
    @property
    def pending_irps(self, /) -> list[int] |None:
        """
        The IRPs on the thread's `IrpList`.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The ID of the process that owns the thread.
        """
    @property
    def priority(self, /) -> int |None:
        """
        The current scheduling priority.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process that owns the thread.
        """
    @property
    def process_name(self, /) -> str |None:
        """
        The image name of the owning process.
        """
    @property
    def stack_base(self, /) -> int |None: ...
    @property
    def stack_limit(self, /) -> int |None: ...
    @property
    def start_address(self, /) -> int |None: ...
    @property
    def state(self, /) -> int |None:
        """
        The scheduler state, as a `_KTHREAD_STATE` member (`IntEnum`).
        """
    @property
    def state_name(self, /) -> str |None:
        """
        The name of the state (`Running`, `Waiting`, ...).
        """
    @property
    def teb(self, /) -> Struct |None:
        """
        The `_TEB`, bound to the process, or `None` for kernel threads.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread ID, or `None` if the thread has no ID (for example, an
        idle thread).
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """
    def trap_frame(self, /) -> KtrapFrame:
        """
        Decode the saved `_KTRAP_FRAME` (`!trap`).
        """
    @property
    def wait_irql(self, /) -> int |None: ...
    @property
    def wait_reason(self, /) -> int |None:
        """
        The reason the thread waits, as a `_KWAIT_REASON` member (`IntEnum`).
        """
    @property
    def wait_reason_name(self, /) -> str |None:
        """
        The name of the wait reason (`Executive`, `UserRequest`, ...).
        """
    @property
    def win32_start_address(self, /) -> int |None: ...

@final
class ThreadDetail(BaseRecord):
    """
    A thread as `!thread` shows it: the thread, the vCPU running it, and the
    `_ETHREAD`/`_KTHREAD` fields the listing adds. Each field is `None` when
    this build's layout lacks it or its read failed.
    """
    __match_args__: Final[tuple[Literal["info"], Literal["win32_thread"], Literal["user_time"], Literal["kernel_time"], Literal["wait_time"], Literal["ready_time"], Literal["quantum_target"]]]
    @property
    def cpu(self, /) -> int |None:
        """
        The processor running the thread, or `None` when it is not running.
        """
    @property
    def info(self, /) -> ThreadInfo: ...
    @property
    def kernel_time(self, /) -> int |None: ...
    @property
    def quantum_target(self, /) -> int |None: ...
    @property
    def ready_time(self, /) -> int |None: ...
    @property
    def user_time(self, /) -> int |None: ...
    @property
    def wait_time(self, /) -> int |None: ...
    @property
    def win32_thread(self, /) -> int |None: ...

@final
class ThreadInfo(BaseRecord):
    """
    A Windows thread, as `threads`, `!thread`, and all scheduler listings
    show it. A field that the walk could not read is `None`.
    """
    __match_args__: Final[tuple[Literal["ethread"], Literal["kthread"], Literal["tid"], Literal["pid"], Literal["process_name"], Literal["eprocess"], Literal["state"], Literal["wait_reason"], Literal["priority"], Literal["base_priority"], Literal["wait_irql"], Literal["kernel_stack_resident"], Literal["start_address"], Literal["win32_start_address"], Literal["teb"], Literal["kernel_stack"], Literal["stack_base"], Literal["stack_limit"], Literal["trap_frame"], Literal["pending_irps"]]]
    @property
    def base_priority(self, /) -> int |None: ...
    @property
    def eprocess(self, /) -> int |None:
        """
        The owning `_EPROCESS`.
        """
    @property
    def ethread(self, /) -> int:
        """
        The `_ETHREAD` address, which identifies the thread.
        """
    @property
    def kernel_stack(self, /) -> int |None:
        """
        `_KTHREAD.KernelStack`, the saved stack pointer of a thread that is
        not running.
        """
    @property
    def kernel_stack_resident(self, /) -> bool |None: ...
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` address.
        """
    @property
    def pending_irps(self, /) -> list[int] |None:
        """
        The IRPs on the thread's `IrpList`.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The ID of the process that owns the thread.
        """
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
    def stack_base(self, /) -> int |None: ...
    @property
    def stack_limit(self, /) -> int |None: ...
    @property
    def start_address(self, /) -> int |None: ...
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
    def teb(self, /) -> int |None: ...
    @property
    def tid(self, /) -> int |None:
        """
        The thread ID, or `None` if the thread has no ID (for example, an
        idle thread).
        """
    @property
    def trap_frame(self, /) -> int |None: ...
    @property
    def wait_irql(self, /) -> int |None: ...
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
    @property
    def win32_start_address(self, /) -> int |None: ...

@final
class ThreadStack(BaseRecord):
    """
    The state and walked stack of a thread (`!stacks`).
    """
    __match_args__: Final[tuple[Literal["thread"], Literal["top_symbol"], Literal["frames"], Literal["truncated"], Literal["error"]]]
    @property
    def active(self, /) -> int |None:
        """
        The processor that runs the thread, if the listing resolves it.
        `None` if no processor runs it, and while the target runs.
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
    def thread(self, /) -> ThreadInfo: ...
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
    __match_args__: Final[tuple[Literal["level"], Literal["filter"], Literal["scanned_threads"], Literal["displayed_threads"], Literal["interrupted"], Literal["threads"]]]
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
class Threads:
    """
    A collection of threads: `dbg.threads` (all threads) or `proc.threads`,
    keyed by TID or by a `ThreadInfo` record (`stop.thread`).
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: int |ThreadInfo, /) -> Thread:
        """
        The thread with a TID, or the thread a `ThreadInfo` record describes
        (`dbg.threads[stop.thread]`, which also finds an idle thread, which
        has no TID).
        """
    def __iter__(self, /) -> Iterator[Thread]: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def at(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> Thread |None:
        """
        The thread at an ETHREAD or KTHREAD address, or `None`.
        """
    def get(self, /, key: int |ThreadInfo) -> Thread |None:
        """
        The thread with a TID, or the thread a `ThreadInfo` record describes
        (`dbg.threads[stop.thread]`, which also finds an idle thread, which
        has no TID).
        """

@final
class TimerBucketEnd(BaseRecord):
    """
    A timer-table bucket whose list walk did not end at its head.
    """
    __match_args__: Final[tuple[Literal["processor"], Literal["bucket"], Literal["termination"]]]
    @property
    def bucket(self, /) -> int: ...
    @property
    def processor(self, /) -> int: ...
    @property
    def termination(self, /) -> ListTermination: ...

@final
class TimerTable(BaseRecord):
    """
    The timer tables of all processors (`!timer`).
    """
    __match_args__: Final[tuple[Literal["interrupt_time"], Literal["entries"], Literal["terminations"], Literal["total"], Literal["truncated"], Literal["errors"]]]
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
    __match_args__: Final[tuple[Literal["processor"], Literal["bucket"], Literal["timer"]]]
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
    __match_args__: Final[tuple[Literal["process"], Literal["token"], Literal["token_id"], Literal["authentication_id"], Literal["token_type"], Literal["impersonation_level"], Literal["flags"], Literal["user"], Literal["groups"], Literal["privileges"]]]
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
    def process(self, /) -> ProcessInfo:
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
    __match_args__: Final[tuple[Literal["luid"], Literal["attributes"]]]
    @property
    def attributes(self, /) -> int: ...
    @property
    def luid(self, /) -> int: ...

@final
class TransitionExtension(BaseRecord):
    """
    The power transition extension of the boot status data.
    """
    __match_args__: Final[tuple[Literal["shutdown_device_type"], Literal["setup_in_progress"], Literal["oobe_in_progress"], Literal["sleep_checkpoint_source"], Literal["sleep_checkpoint"], Literal["connected_standby_entry_reason_category"], Literal["connected_standby_exit_reason_category"], Literal["connected_standby_entry_scenario_instance_id"]]]
    @property
    def connected_standby_entry_reason_category(self, /) -> int: ...
    @property
    def connected_standby_entry_scenario_instance_id(self, /) -> int: ...
    @property
    def connected_standby_exit_reason_category(self, /) -> int: ...
    @property
    def oobe_in_progress(self, /) -> bool: ...
    @property
    def setup_in_progress(self, /) -> bool: ...
    @property
    def shutdown_device_type(self, /) -> int: ...
    @property
    def sleep_checkpoint(self, /) -> int: ...
    @property
    def sleep_checkpoint_source(self, /) -> int: ...

@final
class TriageCrashInfo(BaseRecord):
    """
    The process and thread that crashed, as a triage dump recorded them: it
    snapshots their `EPROCESS` and `ETHREAD` as raw bytes rather than as
    mapped memory. A field is `None` if the dump does not record it.
    """
    __match_args__: Final[tuple[Literal["process_name"], Literal["process_id"], Literal["parent_process_id"], Literal["exit_status"], Literal["create_time"], Literal["thread_id"], Literal["thread_exit_status"]]]
    @property
    def create_time(self, /) -> int |None:
        """
        When the process was created (FILETIME).
        """
    @property
    def create_time_utc(self, /) -> str |None:
        """
        When the process was created (ISO 8601 UTC). `None` if ntoseye cannot
        convert the recorded time.
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
class TriagePrcbInfo(BaseRecord):
    """
    The main `_KPRCB` data of the crashed processor, as a triage dump
    recorded it.
    """
    __match_args__: Final[tuple[Literal["current_thread"], Literal["processor_number"], Literal["mhz"], Literal["cpu_type"], Literal["vendor_string"]]]
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
    bugcheck or exception, the backtrace, the modules, the dump records, and
    the findings.
    """
    __match_args__: Final[tuple[Literal["status"], Literal["bugcheck"], Literal["exception"], Literal["system_info"], Literal["modules"], Literal["unloaded_drivers"], Literal["crash_context"], Literal["prcb"], Literal["broken_driver"], Literal["triage_overflowed"], Literal["failure_signature"], Literal["culprit"], Literal["verifier"], Literal["whea"], Literal["blackboxes"], Literal["kmdf_log"], Literal["power"], Literal["user"], Literal["warnings"]]]
    @property
    def backtrace(self, /) -> list[StackFrame] |None:
        """
        The stack of the current thread. `None` while the target runs or if
        the unwind failed (see `warnings`).
        """
    @property
    def blackboxes(self, /) -> list[BlackboxFinding]: ...
    @property
    def broken_driver(self, /) -> str |None:
        """
        The driver that the dump records as broken.
        """
    @property
    def bugcheck(self, /) -> BugcheckAnalysis |None:
        """
        The bugcheck, if the target is in a bugcheck.
        """
    @property
    def crash_context(self, /) -> TriageCrashInfo |None:
        """
        The process and thread that crashed, as a triage dump recorded them.
        """
    @property
    def culprit(self, /) -> CulpritAttribution |None:
        """
        What the evidence identifies as the cause: a module, or on a
        user-mode minidump, JIT-compiled code. `None` if the evidence
        identifies neither a non-kernel (or, on a user dump, non-system)
        module nor generated code.
        """
    @property
    def exception(self, /) -> DmpException |None:
        """
        The exception that a dump recorded.
        """
    @property
    def failure_signature(self, /) -> FailureSignature |None: ...
    @property
    def kmdf_log(self, /) -> KmdfLogFinding |None:
        """
        The KMDF driver whose In-Flight Recorder log the dump holds.
        """
    @property
    def modules(self, /) -> list[ModuleInfo]:
        """
        The loaded modules.
        """
    @property
    def power(self, /) -> PowerFailureFinding |None:
        """
        What a DRIVER_POWER_STATE_FAILURE names as stuck.
        """
    @property
    def prcb(self, /) -> TriagePrcbInfo |None:
        """
        The processor that crashed, as a triage dump recorded it.
        """
    @property
    def status(self, /) -> RunStatus:
        """
        The target's run status.
        """
    @property
    def system_info(self, /) -> DmpSystemInfo |None:
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
    def unloaded_drivers(self, /) -> list[UnloadedDriver]:
        """
        The drivers the system unloaded recently, as the crash dump records
        them.
        """
    @property
    def user(self, /) -> UserDumpTriage |None:
        """
        What a user-mode minidump adds: the process, the exception decoded,
        and the frame the failure is blamed on. `None` for a kernel target.
        """
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
    def info(self, /) -> TrustletInfo:
        """
        The `TrustletInfo` record of this handle: its properties as one value.
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
        The record (`info`) as a plain `dict`.
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
class TrustletInfo(BaseRecord):
    """
    An isolated user-mode process (trustlet) in VTL1, such as `LsaIso.exe`,
    as `!trustlets` lists it.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["pid"], Literal["name"], Literal["dtb"], Literal["trustlet_id"]]]
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
    def trustlet_id(self, /) -> int:
        """
        The trustlet ID from its creation attributes (1 for `LsaIso.exe`).
        """

@final
class Type:
    """
    A named PDB struct or union layout, or an enum definition.
    """
    def __repr__(self, /) -> str: ...
    def at(self, /, addr: int |str |Process |Thread |Module |Driver |Device |Heap) -> Struct:
        """
        Bind this layout to an address as a reflective struct cursor.
        """
    @property
    def fields(self, /) -> dict[str, FieldInfo]:
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
    def walk(self, /, head: int |str |Process |Thread |Module |Driver |Device |Heap, link_field: str) -> list[Struct]:
        """
        Walk an intrusive list whose head is at `head`, where `link_field` is
        the field that holds the links.
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
    __match_args__: Final[tuple[Literal["threads"]]]
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
    def threads(self, /) -> list[ThreadInfo]: ...
    @property
    def truncated(self, /) -> int:
        """
        The number of frames past the walk limit, which were not compared.
        """

class UniqStackScope(BaseRecord):
    """
    Which threads `!uniqstack` groups: `all`, or one `process`.
    """
    @property
    def kind(self, /) -> Literal["all", "process"]:
        """
        The variant: `all`, `process`.
        """
    @final
    class AllThreads(UniqStackScope):
        __match_args__: Final[tuple[()]]
        @property
        def kind(self, /) -> Literal["all"]:
            """
            `all`.
            """
    @final
    class Process(UniqStackScope):
        __match_args__: Final[tuple[Literal["pid"], Literal["name"]]]
        @property
        def kind(self, /) -> Literal["process"]:
            """
            `process`.
            """
        @property
        def name(self, /) -> str:
            """
            The image name of the process.
            """
        @property
        def pid(self, /) -> int:
            """
            The process ID.
            """

@final
class UniqStacks(BaseRecord):
    """
    Threads grouped by identical call stacks (`!uniqstack`).
    """
    __match_args__: Final[tuple[Literal["scope"], Literal["scanned_threads"], Literal["interrupted"], Literal["groups"], Literal["unwalked"]]]
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
        The threads whose stacks were walked and grouped: fewer than
        `scanned_threads` less `unwalked` when the walk was interrupted.
        """

@final
class UnloadedDriver(BaseRecord):
    """
    A driver that the system unloaded recently, as the crash dump records it.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["start_address"], Literal["end_address"]]]
    @property
    def end_address(self, /) -> int: ...
    @property
    def name(self, /) -> str: ...
    @property
    def start_address(self, /) -> int: ...

@final
class UnloadedModule(BaseRecord):
    """
    A module the process had unloaded (`UnloadedModuleListStream`).
    """
    __match_args__: Final[tuple[Literal["base"], Literal["size"], Literal["checksum"], Literal["time_date_stamp"], Literal["name"]]]
    @property
    def base(self, /) -> int: ...
    @property
    def checksum(self, /) -> int: ...
    @property
    def name(self, /) -> str: ...
    @property
    def size(self, /) -> int: ...
    @property
    def time_date_stamp(self, /) -> int: ...

@final
class UnwalkedThread(BaseRecord):
    """
    A thread whose stack walk failed, so ntoseye could not search or group
    it.
    """
    __match_args__: Final[tuple[Literal["thread"], Literal["error"]]]
    @property
    def error(self, /) -> str:
        """
        The reason the walk failed.
        """
    @property
    def thread(self, /) -> ThreadInfo: ...

@final
class UnwindHandler(BaseRecord):
    """
    The exception or termination handler of an unwind info.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["symbol"], Literal["data"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def data(self, /) -> int:
        """
        The start address of the language-specific data of the handler.
        """
    @property
    def symbol(self, /) -> str: ...

class UserAddressReport(BaseRecord):
    """
    `!address` on a user-mode minidump: what its memory-info list records,
    or, for a dump without one, the memory ranges it captured.
    """
    @property
    def kind(self, /) -> Literal["region", "map", "captured_range", "captured_ranges"]:
        """
        The variant: `region`, `map`, `captured_range`, `captured_ranges`.
        """
    @final
    class CapturedRange(UserAddressReport):
        """
        A dump without a memory-info list: the captured range that holds
        `address`, if one does.
        """
        __match_args__: Final[tuple[Literal["address"], Literal["range"]]]
        @property
        def address(self, /) -> int: ...
        @property
        def kind(self, /) -> Literal["captured_range"]:
            """
            `captured_range`.
            """
        @property
        def range(self, /) -> CapturedRange |None: ...
    @final
    class CapturedRanges(UserAddressReport):
        """
        A dump without a memory-info list: every range it captured.
        """
        __match_args__: Final[tuple[Literal["ranges"]]]
        @property
        def kind(self, /) -> Literal["captured_ranges"]:
            """
            `captured_ranges`.
            """
        @property
        def ranges(self, /) -> list[CapturedRange]: ...
    @final
    class Map(UserAddressReport):
        """
        Every region of the memory-info list, with their summary.
        """
        __match_args__: Final[tuple[Literal["regions"], Literal["summary"]]]
        @property
        def kind(self, /) -> Literal["map"]:
            """
            `map`.
            """
        @property
        def regions(self, /) -> list[UserRegion]: ...
        @property
        def summary(self, /) -> AddressSummary: ...
    @final
    class Region(UserAddressReport):
        """
        The memory-info list's region that holds `address` (`None` when no
        region does), and whether the dump captured the byte at `address`.
        """
        __match_args__: Final[tuple[Literal["address"], Literal["region"], Literal["address_captured"]]]
        @property
        def address(self, /) -> int: ...
        @property
        def address_captured(self, /) -> bool: ...
        @property
        def kind(self, /) -> Literal["region"]:
            """
            `region`.
            """
        @property
        def region(self, /) -> UserRegion |None: ...

@final
class UserDump:
    """
    A user-mode minidump (`dbg.user_dump`): the captured process, its
    threads, the exception the dump was written for, and the handle,
    memory-region, and unloaded-module records the dump holds. The system
    it ran on and when it was written are `dbg.inspect.version()` and
    `dbg.inspect.time()`.
    """
    def __repr__(self, /) -> str: ...
    def address_report(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> UserAddressReport:
        """
        What a user-mode minidump's memory-info list records (`!address`): with
        `address`, the region that holds it and whether the dump captured it;
        without, every region with the dump's summary. A dump without a
        memory-info list reports the memory ranges it captured instead.
        """
    @property
    def current_thread(self, /) -> UserThread |None:
        """
        The thread selected for inspection, which a debugger opens on the
        exception's thread when the dump records an exception.
        """
    @property
    def exception(self, /) -> UserExceptionDetail |None:
        """
        The exception the dump was written for, or `None` when it records
        none.
        """
    def exception_context(self, /) -> Frame:
        """
        The registers at the exception (`.ecxr`), from the CONTEXT the dump
        stores beside the exception record, as a read-only `Frame`. Raises
        `NtoseyeError` when the dump records no exception or its context is
        unusable.
        """
    @property
    def exception_thread(self, /) -> UserThread |None:
        """
        The thread that raised the dump's exception, or `None` when the dump
        records no exception (or its thread is not in the thread list).
        """
    @property
    def handles(self, /) -> list[UserHandle] |None:
        """
        The handles the process held, as the dump records them, or `None`
        when the dump has no handle data.
        """
    @property
    def notes(self, /) -> list[str]:
        """
        What ntoseye dropped or cut short while reading the dump, and why.
        """
    @property
    def process(self, /) -> UserProcess:
        """
        The captured process.
        """
    def region(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap) -> UserRegion |None:
        """
        The region holding `address`, or `None` when no region holds it or
        the dump has no memory-info list.
        """
    @property
    def regions(self, /) -> list[UserRegion] |None:
        """
        The regions of the process's address space, by base, each with what
        uses it (`!address`), or `None` when the dump has no memory-info list.
        A region's bytes read only where the dump captured them.
        """
    @property
    def threads(self, /) -> UserThreads:
        """
        The captured threads, by thread id: `threads[tid]`, iteration in the
        dump's order.
        """
    @property
    def unloaded_modules(self, /) -> list[UnloadedModule]:
        """
        The modules the process had unloaded.
        """

@final
class UserDumpTime(BaseRecord):
    """
    When a user-mode minidump was written (its header), and how long its
    process had run (`MiscInfoStream`), where it records them.
    """
    __match_args__: Final[tuple[Literal["written"], Literal["written_iso"], Literal["written_local"], Literal["time_zone"], Literal["process_created"], Literal["process_created_iso"], Literal["process_uptime_seconds"], Literal["process_uptime"], Literal["user_time_seconds"], Literal["kernel_time_seconds"]]]
    @property
    def kernel_time_seconds(self, /) -> int |None:
        """
        Kernel-mode time the process had run, in seconds.
        """
    @property
    def process_created(self, /) -> int |None:
        """
        When the process started, in seconds since 1970 (UTC).
        """
    @property
    def process_created_iso(self, /) -> str |None:
        """
        `process_created` as ISO 8601 UTC.
        """
    @property
    def process_uptime(self, /) -> str |None:
        """
        `process_uptime_seconds` as formatted text.
        """
    @property
    def process_uptime_seconds(self, /) -> int |None:
        """
        From the process's start to the dump, in seconds.
        """
    @property
    def time_zone(self, /) -> str |None:
        """
        The name of that zone's period in effect.
        """
    @property
    def user_time_seconds(self, /) -> int |None:
        """
        User-mode time the process had run, in seconds.
        """
    @property
    def written(self, /) -> int:
        """
        When the dump was written, in seconds since 1970 (UTC).
        """
    @property
    def written_iso(self, /) -> str |None:
        """
        `written` as ISO 8601 UTC.
        """
    @property
    def written_local(self, /) -> str |None:
        """
        `written` in the system's time zone.
        """

@final
class UserDumpTriage(BaseRecord):
    """
    What `!analyze` reports for a user-mode minidump beyond the fields it
    shares with a kernel report (the stack, the modules, the signature and
    the culprit): the process, the exception decoded, and the frame the
    failure is blamed on.
    """
    __match_args__: Final[tuple[Literal["process"], Literal["exception"], Literal["stack_thread"], Literal["exception_registers"]]]
    @property
    def exception(self, /) -> UserExceptionFinding |None:
        """
        The exception the dump was written for; `None` when it records none.
        """
    @property
    def exception_registers(self, /) -> list[RegisterValue]:
        """
        The general-purpose registers of the exception's context, in display
        order. Empty without an exception, or when its context is unusable.
        """
    @property
    def process(self, /) -> UserProcessSummary: ...
    @property
    def stack_thread(self, /) -> UserStackThread |None:
        """
        The thread whose stack the report's `backtrace` is, and the context
        the walk started from. `None` if no thread is selected.
        """

@final
class UserException(BaseRecord):
    """
    The exception a user-mode minidump was written for (`ExceptionStream`).
    """
    __match_args__: Final[tuple[Literal["thread_id"], Literal["code"], Literal["flags"], Literal["record"], Literal["address"], Literal["parameters"]]]
    @property
    def address(self, /) -> int:
        """
        Where the exception was raised.
        """
    @property
    def code(self, /) -> int:
        """
        The exception code (an NTSTATUS, or an application's own code).
        """
    @property
    def code_name(self, /) -> str |None:
        """
        The NTSTATUS name of `code`, when it is one ntoseye knows.
        """
    @property
    def context_error(self, /) -> str |None:
        """
        Why the exception's CONTEXT is unusable, `None` when it is.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def parameters(self, /) -> list[int]: ...
    @property
    def record(self, /) -> int:
        """
        The address of a chained `EXCEPTION_RECORD`, 0 for none.
        """
    @property
    def thread_id(self, /) -> int:
        """
        The thread that raised it.
        """

@final
class UserExceptionDetail(BaseRecord):
    """
    The exception a user-mode minidump was written for, with its address
    named in the dump's modules.
    """
    __match_args__: Final[tuple[Literal["info"], Literal["symbol"]]]
    @property
    def info(self, /) -> UserException: ...
    @property
    def symbol(self, /) -> str |None:
        """
        `info.address` as `module!function+offset`, when it resolves.
        """

@final
class UserExceptionFinding(BaseRecord):
    """
    The exception a user-mode minidump was written for, decoded.
    """
    __match_args__: Final[tuple[Literal["code"], Literal["kind"], Literal["name"], Literal["flags"], Literal["flag_names"], Literal["record"], Literal["address"], Literal["symbol"], Literal["address_owner"], Literal["parameters"], Literal["summary"], Literal["thread_id"], Literal["thread"], Literal["thread_name"], Literal["faulting_frame"], Literal["blamed_frame"], Literal["module_caller"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def address_owner(self, /) -> CodeOwner:
        """
        What holds the exception address: the faulting module.
        """
    @property
    def blamed_frame(self, /) -> UserFrame |None:
        """
        The first frame, from the faulting one outward, outside the system
        modules: the code the failure is blamed on. `None` when every frame
        is in a system module or there is no stack.
        """
    @property
    def code(self, /) -> int: ...
    @property
    def faulting_frame(self, /) -> int |None:
        """
        The index in the report's `backtrace` of the frame at the exception
        address; `None` when no frame is there.
        """
    @property
    def flag_names(self, /) -> list[str]:
        """
        The `EXCEPTION_*` flags set, with any unknown bits in hex.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def kind(self, /) -> Literal["ntstatus", "cpp_exception", "clr_exception", "well_known", "application_defined", "unknown"]: ...
    @property
    def module_caller(self, /) -> UserFrame |None:
        """
        When the blamed frame is in no module, the first frame further out
        that a module holds: the module code that called into it.
        """
    @property
    def name(self, /) -> str:
        """
        The code's name, or what kind of code it is when it has none.
        """
    @property
    def parameters(self, /) -> list[ExceptionParameter]: ...
    @property
    def record(self, /) -> int:
        """
        The address of a chained exception record, 0 for none.
        """
    @property
    def summary(self, /) -> str |None:
        """
        What the parameters say, in one line (`write to 0x10`).
        """
    @property
    def symbol(self, /) -> str: ...
    @property
    def thread(self, /) -> str:
        """
        The thread's id as `~` lists it.
        """
    @property
    def thread_id(self, /) -> int: ...
    @property
    def thread_name(self, /) -> str |None: ...

@final
class UserFrame(BaseRecord):
    """
    A frame of the report's stack, as the analysis uses it.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["ip"], Literal["symbol"], Literal["source"], Literal["owner"]]]
    @property
    def index(self, /) -> int:
        """
        The frame's index in the report's `backtrace`.
        """
    @property
    def ip(self, /) -> int: ...
    @property
    def owner(self, /) -> CodeOwner: ...
    @property
    def source(self, /) -> Literal["current", "seed", "unwind", "prolog", "scan"]: ...
    @property
    def symbol(self, /) -> str: ...

@final
class UserHandle(BaseRecord):
    """
    A handle the process held (`MINIDUMP_HANDLE_DESCRIPTOR` or
    `MINIDUMP_HANDLE_DESCRIPTOR_2`), as the dump records it. The dump names
    no object address.
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["type_name"], Literal["object_name"], Literal["attributes"], Literal["granted_access"], Literal["handle_count"], Literal["pointer_count"]]]
    @property
    def attribute_names(self, /) -> list[str]:
        """
        `attributes` as `OBJ_*` names.
        """
    @property
    def attributes(self, /) -> int:
        """
        `OBJ_*` attribute flags.
        """
    @property
    def granted_access(self, /) -> int: ...
    @property
    def handle(self, /) -> int: ...
    @property
    def handle_count(self, /) -> int: ...
    @property
    def object_name(self, /) -> str |None: ...
    @property
    def pointer_count(self, /) -> int: ...
    @property
    def type_name(self, /) -> str |None: ...

@final
class UserProcess:
    """
    The process a user-mode minidump captured (`dbg.user_dump.process`). It
    is the only one, so it has no EPROCESS or page-table root; `memory`,
    `modules`, and `threads` are the dump's.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def decode_peb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Peb:
        """
        Decode the process environment block and process parameters of the
        current process.
        
        If you do not give an address, the command uses EPROCESS.Peb of the
        current process: the one that .process selected, else the owner of the
        current thread. On a user-mode minidump it uses the PEB that the selected
        thread's TEB names, and the layouts of the dump's ntdll. It decodes the
        process parameters with their PDB layouts. To list the loader modules,
        use !dlls.
        """
    @property
    def info(self, /) -> UserProcessInfo:
        """
        The `UserProcessInfo` record of this handle: its properties as one value.
        """
    def loader_modules(self, /, *, containing: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> LoaderModules:
        """
        List the modules in the loader lists of the current process.
        
        The current process is the one that .process selected, else the owner of
        the current thread; on a user-mode minidump, its one process, as far as
        the dump captured the loader's lists (lm lists the dump's own module
        list). With -c <address>, the command shows only the module that
        contains that address. The module walk has a limit, and also stops if it
        finds a cycle in a list.
        """
    @property
    def memory(self, /) -> Memory:
        """
        The process's memory: every captured range, by virtual address.
        """
    @property
    def modules(self, /) -> Modules:
        """
        The modules the dump lists.
        """
    @property
    def name(self, /) -> str |None:
        """
        The executable's file name, from the first module the dump lists.
        """
    @property
    def peb(self, /) -> Struct |None:
        """
        The `ntdll!_PEB` cursor, found through the selected thread's TEB, or
        `None` when the dump holds neither.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The process id, when the dump records it.
        """
    @property
    def threads(self, /) -> UserThreads:
        """
        The captured threads.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class UserProcessInfo(BaseRecord):
    """
    The process a user-mode minidump captured (`dbg.user_dump.process`).
    """
    __match_args__: Final[tuple[Literal["pid"], Literal["name"]]]
    @property
    def name(self, /) -> str |None:
        """
        The executable's file name, from the first module the dump lists.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The process id, when the dump records it.
        """

@final
class UserProcessSummary(BaseRecord):
    """
    The captured process, as the dump's streams record it.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["pid"], Literal["major_version"], Literal["minor_version"], Literal["build_number"], Literal["build_string"], Literal["dump_time"], Literal["create_time"], Literal["threads"], Literal["modules"], Literal["unloaded_modules"], Literal["handles"]]]
    @property
    def arch(self, /) -> str:
        """
        `AMD64` or `ARM64`.
        """
    @property
    def build_number(self, /) -> int: ...
    @property
    def build_string(self, /) -> str |None:
        """
        `MINIDUMP_MISC_INFO_4.BuildString`.
        """
    @property
    def create_time(self, /) -> int |None:
        """
        When the process was created, in seconds since 1970 (UTC).
        """
    @property
    def create_time_utc(self, /) -> str |None:
        """
        When the process was created (ISO 8601 UTC).
        """
    @property
    def dump_time(self, /) -> int:
        """
        When the dump was written, in seconds since 1970 (UTC).
        """
    @property
    def dump_time_utc(self, /) -> str |None:
        """
        When the dump was written (ISO 8601 UTC).
        """
    @property
    def handles(self, /) -> int |None:
        """
        `None` when the dump has no handle stream.
        """
    @property
    def kernel_time_secs(self, /) -> int |None:
        """
        Kernel-mode time the process had run, in seconds.
        """
    @property
    def major_version(self, /) -> int: ...
    @property
    def minor_version(self, /) -> int: ...
    @property
    def modules(self, /) -> int: ...
    @property
    def name(self, /) -> str |None:
        """
        The executable's file name, from the first module the dump lists.
        """
    @property
    def pid(self, /) -> int |None: ...
    @property
    def threads(self, /) -> int: ...
    @property
    def unloaded_modules(self, /) -> int: ...
    @property
    def user_time_secs(self, /) -> int |None:
        """
        User-mode time the process had run, in seconds.
        """

@final
class UserRegion(BaseRecord):
    """
    One region of a user-mode minidump's memory-info list (`!address`),
    with what the dump shows uses it and how much of it the dump holds.
    """
    __match_args__: Final[tuple[Literal["info"], Literal["usage"], Literal["detail"], Literal["captured"]]]
    @property
    def captured(self, /) -> int:
        """
        Bytes of the region the dump captured.
        """
    @property
    def detail(self, /) -> str |None:
        """
        The module, thread, or heap the usage names.
        """
    @property
    def end(self, /) -> int:
        """
        The end of the region (exclusive).
        """
    @property
    def info(self, /) -> MemoryRegion:
        """
        The region, as `VirtualQueryEx` reported it.
        """
    @property
    def usage(self, /) -> Literal["free", "image", "stack", "teb", "peb", "heap", "unknown"]: ...

@final
class UserStackThread(BaseRecord):
    """
    The thread a user dump report's stack belongs to.
    """
    __match_args__: Final[tuple[Literal["tid"], Literal["name"], Literal["source"]]]
    @property
    def name(self, /) -> str |None: ...
    @property
    def source(self, /) -> Literal["exception_context", "thread_context"]: ...
    @property
    def tid(self, /) -> int: ...

@final
class UserThread:
    """
    One thread a user-mode minidump captured, identified by its thread id.
    Its registers are the context the dump recorded for it; nothing about it
    can be changed.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def backtrace(self, /, limit: int = 64) -> list[Frame]:
        """
        Recover the thread's stack from its recorded registers.
        """
    @property
    def context_error(self, /) -> str |None:
        """
        Why the thread's recorded context is unusable, or `None` when it is
        usable.
        """
    def decode_teb(self, /, address: int |str |Process |Thread |Module |Driver |Device |Heap |None = None) -> Teb:
        """
        Decode a thread environment block.
        
        If you do not give an address, the command uses the teb pseudo-register
        of the current thread. On a user-mode minidump it uses the TEB of the
        selected thread (~<n>s), and the layouts of the dump's ntdll.
        """
    @property
    def exception(self, /) -> bool:
        """
        Whether this thread raised the exception the dump was written for.
        """
    @property
    def index(self, /) -> int:
        """
        The thread's position in the dump's thread list, which `~N` names.
        """
    @property
    def info(self, /) -> UserThreadInfo:
        """
        The `UserThreadInfo` record of this handle: its properties as one value.
        """
    def last_error(self, /) -> LastError:
        """
        Show the last Win32 error value and the last NT status value of the
        current thread.
        """
    @property
    def name(self, /) -> str |None:
        """
        The thread's description (`SetThreadDescription`), when the dump
        records one.
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def priority_class(self, /) -> int: ...
    @property
    def registers(self, /) -> Registers:
        """
        The registers the dump recorded for the thread, read-only. Reading
        one raises `NtoseyeError` when the thread's context is unusable.
        """
    @property
    def stack(self, /) -> CapturedStack |None:
        """
        The captured stack, `None` when the dump holds none of it.
        """
    @property
    def suspend_count(self, /) -> int: ...
    @property
    def teb(self, /) -> Struct |None:
        """
        The `ntdll!_TEB` cursor, or `None` when the dump records no TEB.
        """
    @property
    def tid(self, /) -> int:
        """
        The thread id.
        """
    @property
    def times(self, /) -> UserThreadTimes |None:
        """
        What the dump's thread-info stream records of the thread, when it
        has one.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The record (`info`) as a plain `dict`.
        """

@final
class UserThreadInfo(BaseRecord):
    """
    A thread of the captured process (`MINIDUMP_THREAD`), with what the
    thread-info and thread-name streams add, matched by thread id.
    """
    __match_args__: Final[tuple[Literal["tid"], Literal["suspend_count"], Literal["priority_class"], Literal["priority"], Literal["teb"], Literal["stack"], Literal["name"], Literal["times"]]]
    @property
    def context_error(self, /) -> str |None:
        """
        Why the thread's recorded context is unusable, or `None` when it is
        usable.
        """
    @property
    def name(self, /) -> str |None:
        """
        The thread's description (`SetThreadDescription`), when the dump
        records one.
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def priority_class(self, /) -> int: ...
    @property
    def stack(self, /) -> CapturedStack |None:
        """
        The captured stack, `None` when the dump holds none of it.
        """
    @property
    def suspend_count(self, /) -> int: ...
    @property
    def teb(self, /) -> int:
        """
        The `_TEB` address, 0 when the dump records none.
        """
    @property
    def tid(self, /) -> int:
        """
        The thread id.
        """
    @property
    def times(self, /) -> UserThreadTimes |None:
        """
        What the dump's thread-info stream records of the thread, when it
        has one.
        """

@final
class UserThreadTimes(BaseRecord):
    """
    What the dump's thread-info stream (`ThreadInfoListStream`) records of
    a thread: what the kernel knew of it.
    """
    __match_args__: Final[tuple[Literal["exit_status"], Literal["create_time"], Literal["exit_time"], Literal["kernel_time"], Literal["user_time"], Literal["start_address"], Literal["affinity"]]]
    @property
    def affinity(self, /) -> int:
        """
        The thread's processor affinity mask.
        """
    @property
    def create_time(self, /) -> int:
        """
        When the thread started, as a FILETIME.
        """
    @property
    def exit_status(self, /) -> int:
        """
        The thread's exit status.
        """
    @property
    def exit_time(self, /) -> int:
        """
        When the thread exited, as a FILETIME (0 while it runs).
        """
    @property
    def kernel_time(self, /) -> int:
        """
        Kernel-mode time the thread had run, in 100 ns units.
        """
    @property
    def start_address(self, /) -> int:
        """
        The thread's start address.
        """
    @property
    def user_time(self, /) -> int:
        """
        User-mode time the thread had run, in 100 ns units.
        """

@final
class UserThreads:
    """
    The threads of a user-mode minidump (`dbg.user_dump.threads`), by
    thread id, in the dump's order.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, key: int |UserThreadInfo, /) -> UserThread:
        """
        The thread with a TID.
        """
    def __iter__(self, /) -> Iterator[UserThread]: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, key: int |UserThreadInfo) -> UserThread |None:
        """
        The thread with a TID.
        """

@final
class VcpuInfo(BaseRecord):
    """
    A vCPU (backend execution context) and the guest code that it runs.
    """
    __match_args__: Final[tuple[Literal["rip"], Literal["context"], Literal["symbol"], Literal["saved_vtl"], Literal["serving"], Literal["error"]]]
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
    def number(self, /) -> int |None:
        """
        The zero-based processor number, as `dbg.cpus` numbers it; `None`
        for a backend thread that is no processor.
        """
    @property
    def rip(self, /) -> int |None:
        """
        None if ntoseye cannot read the register context.
        """
    @property
    def saved_vtl(self, /) -> list[SavedVtl]:
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
    __match_args__: Final[tuple[Literal["level"], Literal["option_flags"], Literal["verify_mode"], Literal["level_options"], Literal["statistics"], Literal["drivers"], Literal["drivers_truncated"], Literal["configured_but_unloaded"], Literal["suspect_list_termination"]]]
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
    def suspect_list_termination(self, /) -> ListTermination:
        """
        How the suspect-list walk ended.
        """
    @property
    def verify_mode(self, /) -> Diagnostic[int]: ...

@final
class VerifierAddress(BaseRecord):
    """
    An address in a verifier bugcheck, and its role.
    """
    __match_args__: Final[tuple[Literal["role"], Literal["address"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def role(self, /) -> str: ...

@final
class VerifierArgument(BaseRecord):
    """
    A verifier bugcheck parameter and what it means for the subcode.
    """
    __match_args__: Final[tuple[Literal["value"], Literal["description"]]]
    @property
    def description(self, /) -> str: ...
    @property
    def value(self, /) -> int: ...

@final
class VerifierDriver(BaseRecord):
    """
    The image, signing level, and counters of one verified driver
    (`!verifier <module>`).
    """
    __match_args__: Final[tuple[Literal["module"], Literal["image_base"], Literal["image_size"], Literal["driver_object"], Literal["se_signing_level"], Literal["raise_irqls"], Literal["acquire_spin_locks"], Literal["synchronize_executions"], Literal["allocations_with_no_tag"], Literal["allocations_failed"], Literal["allocations_failed_deliberately"], Literal["current_paged_pool_allocations"], Literal["paged_bytes"], Literal["peak_paged_pool_allocations"], Literal["peak_paged_bytes"], Literal["current_nonpaged_pool_allocations"], Literal["nonpaged_bytes"], Literal["peak_nonpaged_pool_allocations"], Literal["peak_nonpaged_bytes"], Literal["locked_bytes"], Literal["peak_locked_bytes"], Literal["mapped_locked_bytes"], Literal["peak_mapped_locked_bytes"], Literal["mapped_io_space_bytes"], Literal["peak_mapped_io_space_bytes"], Literal["pages_for_mdl_bytes"], Literal["peak_pages_for_mdl_bytes"], Literal["contiguous_memory_bytes"], Literal["peak_contiguous_memory_bytes"], Literal["suspect"]]]
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
    __match_args__: Final[tuple[Literal["entry"], Literal["state"], Literal["nonpaged_bytes"], Literal["paged_bytes"], Literal["module"]]]
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
    __match_args__: Final[tuple[Literal["bugcheck_code"], Literal["bugcheck_name"], Literal["subcode"], Literal["known_subcode"], Literal["subcode_description"], Literal["arguments"], Literal["associated_driver"], Literal["addresses"]]]
    @property
    def addresses(self, /) -> list[VerifierAddress]:
        """
        The addresses in the parameters, with their roles.
        """
    @property
    def arguments(self, /) -> list[VerifierArgument]:
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
class VerifierStatistics(BaseRecord):
    """
    The aggregate counters of Driver Verifier. ntoseye reads each counter
    separately, and each read can fail.
    """
    __match_args__: Final[tuple[Literal["raise_irqls"], Literal["acquire_spin_locks"], Literal["synchronize_executions"], Literal["trims"], Literal["allocations_attempted"], Literal["allocations_succeeded"], Literal["allocations_succeeded_special_pool"], Literal["allocations_with_no_tag"], Literal["allocations_failed"], Literal["current_paged_pool_allocations"], Literal["paged_bytes"], Literal["peak_paged_pool_allocations"], Literal["peak_paged_bytes"], Literal["current_nonpaged_pool_allocations"], Literal["nonpaged_bytes"], Literal["peak_nonpaged_pool_allocations"], Literal["peak_nonpaged_bytes"], Literal["loads"], Literal["unloads"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["full_name"], Literal["base_name"], Literal["loads"], Literal["unloads"]]]
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
class VirtQueue(BaseRecord):
    """
    One queue: the driver's bookkeeping and, for a split ring, the ring.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["name"], Literal["role"], Literal["address"], Literal["size"], Literal["driver"], Literal["ring"], Literal["packed"], Literal["packed_ring"], Literal["event_idx"], Literal["error"]]]
    @property
    def address(self, /) -> int:
        """
        The `virtqueue_split` or `virtqueue_packed`.
        """
    @property
    def driver(self, /) -> DriverQueueState |None:
        """
        What the driver keeps of a split queue.
        """
    @property
    def error(self, /) -> str |None:
        """
        Why the queue or its ring could not be read.
        """
    @property
    def event_idx(self, /) -> bool:
        """
        The device and driver use event indexes (see [`VirtioDriver`]).
        """
    @property
    def index(self, /) -> int:
        """
        Its index in the device's queue table.
        """
    @property
    def interrupt_due(self, /) -> bool:
        """
        Whether an interrupt was due for the returned buffers (split).
        """
    @property
    def interrupts(self, /) -> Signal |None:
        """
        When the driver wants interrupts.
        """
    @property
    def name(self, /) -> str |None:
        """
        Its name where the virtio specification fixes it, such as `rx 0`
        or `request 2`, when the device's type is known ([`name_queues`]).
        """
    @property
    def notifications(self, /) -> Signal |None:
        """
        When the device wants notifications.
        """
    @property
    def packed(self, /) -> PackedQueueState |None:
        """
        The driver's bookkeeping of a packed queue.
        """
    @property
    def packed_ring(self, /) -> PackedRing |None:
        """
        A packed queue's ring, read against the driver's bookkeeping.
        """
    @property
    def progress(self, /) -> QueueProgress |None:
        """
        Counters that only grow, to compare two looks with.
        """
    @property
    def ring(self, /) -> SplitRing |None:
        """
        A split queue's ring.
        """
    @property
    def role(self, /) -> Literal["device_fills", "requests"] |None:
        """
        `device_fills` for a queue whose buffers wait until the device has
        something (receive, events), `requests` for one whose buffers
        carry requests.
        """
    @property
    def size(self, /) -> int: ...
    @property
    def state(self, /) -> str:
        """
        What the queue's counts mean together, as `!virtio` says it.
        """

@final
class VirtioBuffer(BaseRecord):
    """
    One buffer: its descriptors and the request it carries.
    """
    __match_args__: Final[tuple[Literal["position"], Literal["head"], Literal["written"], Literal["descriptors"], Literal["request"], Literal["broken"]]]
    @property
    def broken(self, /) -> str |None:
        """
        Why walking the chain stopped early.
        """
    @property
    def descriptors(self, /) -> list[VirtioDescriptor]: ...
    @property
    def head(self, /) -> int:
        """
        The head descriptor's index (split) or the buffer ID (packed).
        """
    @property
    def position(self, /) -> int:
        """
        The avail entry (split, with the device), the used element
        (returned), or the ring position (packed).
        """
    @property
    def request(self, /) -> str |None:
        """
        The request and, once the device returned it, its answer, decoded
        from the virtio specification's layouts.
        """
    @property
    def written(self, /) -> int |None:
        """
        The bytes the device wrote, for a returned buffer.
        """

@final
class VirtioDescriptor(BaseRecord):
    """
    One descriptor of a buffer.
    """
    __match_args__: Final[tuple[Literal["index"], Literal["id"], Literal["address"], Literal["length"], Literal["flags"], Literal["indirect"], Literal["indirect_error"]]]
    @property
    def address(self, /) -> int:
        """
        The buffer's guest-physical address.
        """
    @property
    def device_writes(self, /) -> bool:
        """
        Whether the device writes the buffer.
        """
    @property
    def flags(self, /) -> int: ...
    @property
    def id(self, /) -> int |None:
        """
        The buffer ID it carries (packed).
        """
    @property
    def index(self, /) -> int:
        """
        Its index in the table (split) or its ring position (packed).
        """
    @property
    def indirect(self, /) -> IndirectTable |None:
        """
        For an indirect descriptor: what its table holds, or why it could
        not be read (`indirect_error`).
        """
    @property
    def indirect_error(self, /) -> str |None: ...
    @property
    def length(self, /) -> int: ...

@final
class VirtioDriver(BaseRecord):
    """
    A device as its virtio-win driver sees it: its `virtio_device` and the
    queues it set up.
    """
    __match_args__: Final[tuple[Literal["module"], Literal["device"], Literal["packed"], Literal["event_idx"], Literal["msix"], Literal["queues"]]]
    @property
    def device(self, /) -> int:
        """
        The `virtio_device`.
        """
    @property
    def event_idx(self, /) -> bool:
        """
        The device and driver use event indexes to suppress signals
        (`VIRTIO_RING_F_EVENT_IDX`, virtio-win's `event_suppression_enabled`).
        """
    @property
    def module(self, /) -> str:
        """
        The driver module whose PDB types its structures.
        """
    @property
    def msix(self, /) -> bool:
        """
        Interrupts come by MSI-X, one vector per queue or shared.
        """
    @property
    def packed(self, /) -> bool: ...
    @property
    def queues(self, /) -> list[VirtQueue]: ...

@final
class VirtioFunction(BaseRecord):
    """
    A virtio PCI function and what its driver shows of it.
    """
    __match_args__: Final[tuple[Literal["bus"], Literal["device"], Literal["function"], Literal["device_id"], Literal["virtio_id"], Literal["transitional"], Literal["pdo"], Literal["service"], Literal["driver"], Literal["driver_missing"]]]
    @property
    def bus(self, /) -> int: ...
    @property
    def device(self, /) -> int: ...
    @property
    def device_id(self, /) -> int: ...
    @property
    def driver(self, /) -> VirtioDriver |None:
        """
        What its virtio-win driver shows of it, with the driver's private
        PDB. None when `driver_missing` says why not.
        """
    @property
    def driver_missing(self, /) -> str |None:
        """
        Why there is no driver state.
        """
    @property
    def function(self, /) -> int: ...
    @property
    def kind(self, /) -> Literal["net", "block", "console", "entropy", "balloon", "scsi", "nine_p", "gpu", "input", "vsock", "crypto", "iommu", "mem", "sound", "fs", "pmem", "unknown"]:
        """
        The specification's name of the type, such as `net` or `block`.
        """
    @property
    def location(self, /) -> str:
        """
        `bb:dd.f`.
        """
    @property
    def pdo(self, /) -> int: ...
    @property
    def service(self, /) -> str |None:
        """
        The service that drives it, from its device node.
        """
    @property
    def transitional(self, /) -> bool:
        """
        Whether the device also offers the legacy interface.
        """
    @property
    def virtio_id(self, /) -> int:
        """
        The virtio device type: 1 net, 2 block, 3 console, 8 SCSI, ...
        """

@final
class VirtioRing(BaseRecord):
    """
    A virtqueue's ring and the buffers outstanding in it (`!vring`).
    """
    __match_args__: Final[tuple[Literal["queue"], Literal["raw_ring"], Literal["request_kind"], Literal["with_device"], Literal["returned"]]]
    @property
    def queue(self, /) -> VirtQueue |None:
        """
        The driver's queue, or None for a ring read from its addresses
        (`raw_ring`).
        """
    @property
    def raw_ring(self, /) -> SplitRing |None:
        """
        A split ring read from its size and addresses, which has no driver
        queue (`!vring /r`).
        """
    @property
    def request_kind(self, /) -> Literal["blk", "scsi", "scsi_control", "scsi_event", "net", "net_control", "gpu", "vsock"] |None:
        """
        What its buffers hold, for decoding: `blk`, `scsi`, `net`, ...
        """
    @property
    def returned(self, /) -> list[VirtioBuffer]:
        """
        Buffers the device returned that the driver has not taken back
        (split rings), at most 64.
        """
    @property
    def with_device(self, /) -> list[VirtioBuffer]:
        """
        Buffers the device holds, at most 64.
        """

@final
class VirtualProcessor:
    """
    A virtual processor of a Windows hypervisor partition.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
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
    def info(self, /) -> HvVirtualProcessor:
        """
        The `HvVirtualProcessor` record of this handle: its properties as one value.
        """
    @property
    def processors(self, /) -> list[HvProcessor]:
        """
        The processors whose current VP this is (the one that runs it, or
        ran it last).
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
        The record (`info`) as a plain `dict`.
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
    __match_args__: Final[tuple[Literal["name"], Literal["value"], Literal["unit"]]]
    @property
    def name(self, /) -> str: ...
    @property
    def unit(self, /) -> Literal["pages", "bytes"] |None:
        """
        The unit of `value`, or `None` for a plain count.
        """
    @property
    def value(self, /) -> Diagnostic[int]: ...

@final
class VmDetail(BaseRecord):
    """
    Virtual-memory statistics (`!vm`). Each counter carries its own source
    and read failure, so one that cannot be read leaves the others.
    """
    __match_args__: Final[tuple[Literal["system"], Literal["pool"], Literal["pte"], Literal["page_files"], Literal["include_processes"]]]
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
    def pool(self, /) -> VmPoolDetail: ...
    @property
    def pte(self, /) -> VmPteDetail: ...
    @property
    def system(self, /) -> SystemMemorySummary:
        """
        The system memory counters and, when requested, per-process usage.
        """

@final
class VmPoolDetail(BaseRecord):
    """
    Pool counters and the pool fields of `MiState` (`!vm`).
    """
    __match_args__: Final[tuple[Literal["nonpaged_pool_bytes"], Literal["nonpaged_pool_maximum"], Literal["paged_pool_pages"], Literal["fields"]]]
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
class VmPteDetail(BaseRecord):
    """
    System PTE counters (`!vm`).
    """
    __match_args__: Final[tuple[Literal["counters"]]]
    @property
    def counters(self, /) -> list[VmCounter]: ...

@final
class VpRegisters(BaseRecord):
    """
    The registers of one VTL of a Windows hypervisor VP (`!hvr`, see
    [`Session::vp_registers`]).
    """
    __match_args__: Final[tuple[Literal["source"], Literal["missing"]]]
    @property
    def missing(self, /) -> str |None:
        """
        Why the general-purpose registers are missing, when they are.
        """
    @property
    def registers(self, /) -> dict[str, int]:
        """
        RIP, RSP, flags, control and segment registers, and the
        general-purpose ones when they are known, in
        [`crate::target::VP_STATE_REGISTERS`] order.
        """
    @property
    def source(self, /) -> str:
        """
        Where they are from: a vCPU that runs the VP now, the exit a vCPU
        in the hypervisor handles for it, or its last exit.
        """

@final
class VpbDetail(BaseRecord):
    """
    A volume parameter block (`!vpb`).
    """
    __match_args__: Final[tuple[Literal["address"], Literal["flags"], Literal["flag_names"], Literal["device_object"], Literal["device_name"], Literal["real_device"], Literal["real_device_name"], Literal["serial_number"], Literal["reference_count"], Literal["volume_label"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["size"], Literal["previous_size"], Literal["busy"], Literal["granule"], Literal["unused_bytes"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def busy(self, /) -> bool: ...
    @property
    def granule(self, /) -> int:
        """
        The header size in bytes (see [`SegmentHeap::granule`]).
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
    __match_args__: Final[tuple[Literal["address"], Literal["signature_ok"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def chunk_count(self, /) -> int:
        """
        The number of chunks that the walk found.
        """
    @property
    def signature_ok(self, /) -> bool:
        """
        Whether the signature of the subsegment matches the expected value.
        """

@final
class VtopDetail(BaseRecord):
    """
    A virtual address translated through the page tables of a DTB
    (`!vtop`), with every level read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["dtb"], Literal["levels"], Literal["physical"], Literal["large"], Literal["transition"], Literal["section"]]]
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
    def levels(self, /) -> list[PteLevel]:
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
        file view that is not touched yet. It cannot be written either.
        """
    @property
    def transition(self, /) -> bool:
        """
        Whether the leaf is a transition PTE. If true, `physical` is a frame
        that the guest still holds, but nothing maps it here and it cannot be
        written.
        """

@final
class WdfCallback(BaseRecord):
    """
    An event callback the driver set.
    """
    __match_args__: Final[tuple[Literal["name"], Literal["address"], Literal["symbol"]]]
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
    __match_args__: Final[tuple[Literal["globals"], Literal["name"], Literal["driver"], Literal["wdf_driver"], Literal["driver_object"], Literal["driver_object_name"], Literal["registry_path"], Literal["version"], Literal["image_base"], Literal["image_size"], Literal["log_header"], Literal["verifier_on"], Literal["problems"]]]
    @property
    def driver(self, /) -> int |None:
        """
        `Driver`, the `FxDriver`. `None` before the driver calls
        `WdfDriverCreate`.
        """
    @property
    def driver_object(self, /) -> int: ...
    @property
    def driver_object_name(self, /) -> str |None:
        """
        The `DRIVER_OBJECT`'s `DriverName` (`kdnic` in the `Driver`
        directory): what names a client whose `Public.DriverName` is empty.
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
        `WdfLogHeader`, the `_WDF_IFR_HEADER` of the IFR log. `None` if the
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
        What in the globals failed validation (a name that is not printable,
        a `Driver` that is not this driver's `FxDriver`, ...); the fields it
        concerns are `None`.
        """
    @property
    def registry_path(self, /) -> str |None:
        """
        The `FxDriver`'s `m_RegistryPath`.
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
        `None` when `WdfBindInfo` is null.
        """
    @property
    def wdf_driver(self, /) -> int |None:
        """
        `Public.Driver`, the WDFDRIVER handle.
        """

@final
class WdfContext(BaseRecord):
    """
    One `FxContextHeader` of an object.
    """
    __match_args__: Final[tuple[Literal["header"], Literal["context"], Literal["type_info"], Literal["name"], Literal["size"]]]
    @property
    def context(self, /) -> int:
        """
        The context itself (`FxContextHeader.Context`).
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
        `ContextSize`, bytes.
        """
    @property
    def type_info(self, /) -> int |None:
        """
        `ContextTypeInfo`, the `_WDF_OBJECT_CONTEXT_TYPE_INFO`. `None` for a
        header without a context type.
        """

@final
class WdfDeviceDetail(BaseRecord):
    """
    A WDFDEVICE with its device objects, state machines, queues, and I/O
    targets (`!wdfkd.wdfdevice`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["driver"], Literal["globals"], Literal["kind"], Literal["device_object"], Literal["attached_device"], Literal["physical_device"], Literal["device_name"], Literal["parent"], Literal["pnp_state"], Literal["power_state"], Literal["power_policy_state"], Literal["pkg_pnp"], Literal["device_power_state"], Literal["system_power_state"], Literal["pkg_io"], Literal["default_queue"], Literal["queues"], Literal["queues_stopped"], Literal["default_child_list"], Literal["static_child_list"], Literal["default_io_target"], Literal["self_io_target"], Literal["io_targets"], Literal["io_targets_stopped"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxDevice`.
        """
    @property
    def attached_device(self, /) -> int:
        """
        The device object this one is attached to (`m_AttachedDevice`).
        """
    @property
    def default_child_list(self, /) -> int |None:
        """
        An FDO's default child list (`m_DefaultDeviceList`, a WDFCHILDLIST).
        """
    @property
    def default_io_target(self, /) -> int |None:
        """
        An FDO's default I/O target (`FxPkgFdo.m_DefaultTarget`, a
        WDFIOTARGET), the next device object down its stack.
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
    def device_power_state(self, /) -> WdfEnumValue |None:
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
    def io_targets(self, /) -> list[WdfIoTargetSummary]:
        """
        The device's I/O targets (`m_IoTargetsList`).
        """
    @property
    def io_targets_stopped(self, /) -> str |None:
        """
        Why the walk of the I/O target list stopped before the list head.
        `None` if the walk completed.
        """
    @property
    def kind(self, /) -> Literal["fdo", "filter", "pdo", "control"]:
        """
        `FDO`, `filter`, `PDO`, or `control`.
        """
    @property
    def parent(self, /) -> WdfObjectRef |None:
        """
        A PDO's parent WDFDEVICE (`m_ParentDevice`).
        """
    @property
    def physical_device(self, /) -> int:
        """
        The device stack's PDO (`m_PhysicalDevice`).
        """
    @property
    def pkg_io(self, /) -> int:
        """
        The `FxPkgIo`.
        """
    @property
    def pkg_pnp(self, /) -> int:
        """
        `m_PkgPnp`, the `FxPkgPnp`. Null for a control device.
        """
    @property
    def pnp_state(self, /) -> WdfEnumValue:
        """
        `_WDF_DEVICE_PNP_STATE`.
        """
    @property
    def power_policy_state(self, /) -> WdfEnumValue:
        """
        `_WDF_DEVICE_POWER_POLICY_STATE`.
        """
    @property
    def power_state(self, /) -> WdfEnumValue:
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
    def self_io_target(self, /) -> int |None:
        """
        An FDO's self I/O target (`FxPkgFdo.m_SelfTarget`, a WDFIOTARGET),
        the top of its own stack.
        """
    @property
    def static_child_list(self, /) -> int |None:
        """
        An FDO's static child list (`m_StaticDeviceList`, a WDFCHILDLIST).
        """
    @property
    def system_power_state(self, /) -> WdfEnumValue |None:
        """
        `_SYSTEM_POWER_STATE`.
        """

@final
class WdfDriverDevice(BaseRecord):
    """
    One of a driver's `DEVICE_OBJECT`s and the WDFDEVICE behind it.
    """
    __match_args__: Final[tuple[Literal["device_object"], Literal["device"], Literal["handle"], Literal["kind"], Literal["pnp_state"], Literal["unlinked"]]]
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
    def kind(self, /) -> Literal["fdo", "filter", "pdo", "control"] |None:
        """
        `FDO`, `filter`, `PDO`, or `control`.
        """
    @property
    def pnp_state(self, /) -> WdfEnumValue |None:
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
    __match_args__: Final[tuple[Literal["client"], Literal["devices"], Literal["devices_stopped"]]]
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
class WdfDumpDriver(BaseRecord):
    """
    A KMDF client driver as Wdf01000 recorded it in a crash dump
    (`!wdfkd.wdfcrashdump loader`).
    """
    __match_args__: Final[tuple[Literal["name"], Literal["globals"], Literal["major"], Literal["minor"], Literal["build"]]]
    @property
    def build(self, /) -> int:
        """
        The build number of the KMDF version that it bound to.
        """
    @property
    def globals(self, /) -> int:
        """
        The driver's `_FX_DRIVER_GLOBALS` at the crash.
        """
    @property
    def major(self, /) -> int:
        """
        The major KMDF version that it bound to.
        """
    @property
    def minor(self, /) -> int:
        """
        The minor KMDF version that it bound to.
        """
    @property
    def name(self, /) -> str |None:
        """
        `None` for an entry without a printable name.
        """

@final
class WdfEnumValue(BaseRecord):
    """
    A PDB enum value and its name.
    """
    __match_args__: Final[tuple[Literal["value"], Literal["name"]]]
    @property
    def name(self, /) -> str |None:
        """
        `None` when the enum has no name for `value`.
        """
    @property
    def value(self, /) -> int: ...

@final
class WdfIoParameters(BaseRecord):
    """
    The buffer lengths in a stack location's `Parameters` for its major
    function: a read's or write's `Length`, a device control's buffer
    lengths and control code. Each is `None` when the major function has no
    such field.
    """
    __match_args__: Final[tuple[Literal["length"], Literal["input_length"], Literal["output_length"], Literal["io_control_code"]]]
    @property
    def input_length(self, /) -> int |None:
        """
        A device control's `InputBufferLength`.
        """
    @property
    def io_control_code(self, /) -> int |None:
        """
        A device control's `IoControlCode`.
        """
    @property
    def length(self, /) -> int |None:
        """
        A read's or write's `Length`.
        """
    @property
    def output_length(self, /) -> int |None:
        """
        A device control's `OutputBufferLength`.
        """

@final
class WdfIoTargetDetail(BaseRecord):
    """
    A WDFIOTARGET with the device object that it sends to and the requests
    sent to it (`!wdfkd.wdfiotarget`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["driver"], Literal["globals"], Literal["type_name"], Literal["kind"], Literal["is_default"], Literal["state"], Literal["open_state"], Literal["device"], Literal["in_stack"], Literal["in_stack_device"], Literal["target_device"], Literal["target_driver"], Literal["target_pdo"], Literal["file_object"], Literal["io_count"], Literal["stack_size"], Literal["sent"], Literal["sent_stopped"], Literal["ignored"], Literal["ignored_stopped"], Literal["pended"], Literal["pended_stopped"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxIoTarget`.
        """
    @property
    def device(self, /) -> WdfObjectRef |None:
        """
        The WDFDEVICE that it belongs to (`m_DeviceBase`).
        """
    @property
    def driver(self, /) -> str |None:
        """
        The owning driver's name, when it has one.
        """
    @property
    def file_object(self, /) -> int:
        """
        `m_TargetFileObject`.
        """
    @property
    def globals(self, /) -> int:
        """
        The owning driver's `_FX_DRIVER_GLOBALS`.
        """
    @property
    def handle(self, /) -> int: ...
    @property
    def ignored(self, /) -> list[WdfTargetRequest]:
        """
        Requests sent while the target was not started, with
        `WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE` (`m_IgnoredIoListHead`).
        """
    @property
    def ignored_stopped(self, /) -> str |None:
        """
        Why the walk of `ignored` stopped early; `None` if it completed.
        """
    @property
    def in_stack(self, /) -> bool:
        """
        `m_InStack`: whether the target is in the device's own stack.
        """
    @property
    def in_stack_device(self, /) -> int:
        """
        `m_InStackDevice`: the device's own device object.
        """
    @property
    def io_count(self, /) -> int:
        """
        `m_IoCount`: one for the target and one for each request in flight.
        """
    @property
    def is_default(self, /) -> bool:
        """
        Whether it is its device's default I/O target.
        """
    @property
    def kind(self, /) -> Literal["local", "remote", "self", "usb_device", "usb_pipe"]:
        """
        `local` (a target in the device's own stack), `remote` (one the
        driver opened), `self`, `USB device`, or `USB pipe`.
        """
    @property
    def open_state(self, /) -> WdfEnumValue |None:
        """
        A remote target's `m_OpenState` (`FxIoTargetRemoteOpenState`).
        """
    @property
    def pended(self, /) -> list[WdfTargetRequest]:
        """
        Requests that the target holds until it starts (`m_PendedQueue`).
        """
    @property
    def pended_stopped(self, /) -> str |None:
        """
        Why the walk of `pended` stopped early; `None` if it completed.
        """
    @property
    def sent(self, /) -> list[WdfTargetRequest]:
        """
        Requests sent and not completed (`m_SentIoListHead`).
        """
    @property
    def sent_stopped(self, /) -> str |None:
        """
        Why the walk of `sent` stopped early; `None` if it completed.
        """
    @property
    def stack_size(self, /) -> int:
        """
        `m_TargetStackSize`.
        """
    @property
    def state(self, /) -> WdfEnumValue:
        """
        `m_State` (`_WDF_IO_TARGET_STATE`).
        """
    @property
    def target_device(self, /) -> int:
        """
        `m_TargetDevice`, the device object that it sends requests to.
        """
    @property
    def target_driver(self, /) -> str |None:
        """
        The name of `target_device`'s driver.
        """
    @property
    def target_pdo(self, /) -> int:
        """
        `m_TargetPdo`.
        """
    @property
    def type_name(self, /) -> str:
        """
        Its `FX_OBJECT_TYPES` name.
        """

@final
class WdfIoTargetSummary(BaseRecord):
    """
    One of a device's I/O targets.
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["type_name"], Literal["kind"], Literal["state"], Literal["target_device"], Literal["is_default"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxIoTarget`.
        """
    @property
    def handle(self, /) -> int:
        """
        The WDFIOTARGET handle.
        """
    @property
    def is_default(self, /) -> bool:
        """
        Whether it is the device's default I/O target.
        """
    @property
    def kind(self, /) -> Literal["local", "remote", "self", "usb_device", "usb_pipe"]:
        """
        See [`WdfIoTargetDetail::kind`]: `local`, `remote`, `self`,
        `USB device`, or `USB pipe`.
        """
    @property
    def state(self, /) -> WdfEnumValue:
        """
        `m_State` (`_WDF_IO_TARGET_STATE`).
        """
    @property
    def target_device(self, /) -> int:
        """
        `m_TargetDevice`, the device object that it sends requests to.
        """
    @property
    def type_name(self, /) -> str:
        """
        Its `FX_OBJECT_TYPES` name.
        """

@final
class WdfIrpLocation(BaseRecord):
    """
    The stack location that an IRP's `CurrentLocation` names.
    """
    __match_args__: Final[tuple[Literal["number"], Literal["address"], Literal["major_function"], Literal["minor_function"], Literal["device_object"], Literal["driver"], Literal["file_object"], Literal["parameters"]]]
    @property
    def address(self, /) -> int:
        """
        The `_IO_STACK_LOCATION`.
        """
    @property
    def device_object(self, /) -> int: ...
    @property
    def driver(self, /) -> str |None:
        """
        The name of the device object's driver.
        """
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
    @property
    def number(self, /) -> int:
        """
        The location number, counted from 1 as `!irp` does.
        """
    @property
    def parameters(self, /) -> WdfIoParameters: ...

@final
class WdfLoader(BaseRecord):
    """
    The KMDF client drivers on `FxLibraryGlobals.FxDriverGlobalsList`
    (`!wdfkd.wdfldr`).
    """
    __match_args__: Final[tuple[Literal["library_globals"], Literal["clients"], Literal["stopped"]]]
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
class WdfLogDump(BaseRecord):
    """
    The In-Flight Recorder log of a client driver, oldest record first
    (`!wdfkd.wdflogdump`, `!wdfkd.wdfcrashdump`).
    """
    __match_args__: Final[tuple[Literal["driver"], Literal["globals"], Literal["header"], Literal["base"], Literal["size"], Literal["current"], Literal["previous"], Literal["sequence"], Literal["use_timestamps"], Literal["entries"], Literal["end"]]]
    @property
    def base(self, /) -> int:
        """
        The record area (`Base`).
        """
    @property
    def current(self, /) -> int:
        """
        `Offset.Current`: where KMDF writes the next record.
        """
    @property
    def driver(self, /) -> str: ...
    @property
    def end(self, /) -> IfrEnd:
        """
        Why the walk ended.
        """
    @property
    def entries(self, /) -> list[WdfLogEntry]:
        """
        Oldest first.
        """
    @property
    def globals(self, /) -> int:
        """
        The `_FX_DRIVER_GLOBALS`; 0 in a crash dump that does not list the
        driver.
        """
    @property
    def header(self, /) -> int:
        """
        The `_WDF_IFR_HEADER`.
        """
    @property
    def previous(self, /) -> int:
        """
        `Offset.Previous`: the newest record's offset.
        """
    @property
    def sequence(self, /) -> int:
        """
        The header's `Sequence`, the newest record's sequence number.
        """
    @property
    def size(self, /) -> int:
        """
        The size of the record area, in bytes.
        """
    @property
    def use_timestamps(self, /) -> bool:
        """
        `UseTimeStamp`: whether the records are 'L2', with a timestamp.
        """

@final
class WdfLogEntry(BaseRecord):
    """
    An In-Flight Recorder record and its message.
    """
    __match_args__: Final[tuple[Literal["record"], Literal["text"]]]
    @property
    def flags(self, /) -> str |None:
        """
        The TMF message's `FLAGS=`.
        """
    @property
    def function(self, /) -> str |None:
        """
        The TMF message's `FUNC=`.
        """
    @property
    def level(self, /) -> str |None:
        """
        The TMF message's `LEVEL=`.
        """
    @property
    def provider(self, /) -> str |None:
        """
        The TMF message's provider, when a loaded PDB declares it.
        """
    @property
    def record(self, /) -> IfrRecord: ...
    @property
    def text(self, /) -> Diagnostic[str]:
        """
        The message formatted with its arguments, or why it is not.
        """

@final
class WdfObject(BaseRecord):
    """
    A WDF handle and the object it names (`!wdfkd.wdfhandle`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["offset"], Literal["type_value"], Literal["type_name"], Literal["object_size"], Literal["refcount"], Literal["state"], Literal["flags"], Literal["flag_names"], Literal["globals"], Literal["driver"], Literal["parent"], Literal["contexts"], Literal["contexts_stopped"]]]
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
        The owning driver's `DriverName`, when it has one.
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
    def state(self, /) -> WdfEnumValue:
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
class WdfObjectDetail(BaseRecord):
    """
    A KMDF object with its children (`!wdfkd.wdfobject`).
    """
    __match_args__: Final[tuple[Literal["object"], Literal["children"], Literal["children_stopped"]]]
    @property
    def children(self, /) -> list[WdfObjectRef]:
        """
        The objects on `m_ChildListHead`, each of which names this object as
        its `m_ParentObject`.
        """
    @property
    def children_stopped(self, /) -> str |None:
        """
        Why the walk of the child list stopped before the list head. `None`
        if the walk completed.
        """
    @property
    def object(self, /) -> WdfObject:
        """
        The object, as `!wdfkd.wdfhandle` shows it.
        """

@final
class WdfObjectRef(BaseRecord):
    """
    The address, handle, and type of a KMDF object, as far as they read.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["handle"], Literal["type_name"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def handle(self, /) -> int |None:
        """
        `None` for an object without a handle (`m_ObjectSize` 0) or that does
        not read.
        """
    @property
    def type_name(self, /) -> str |None:
        """
        The `FX_OBJECT_TYPES` name of its `m_Type`.
        """

@final
class WdfQueueDetail(BaseRecord):
    """
    A WDFQUEUE with its configuration, state, and requests
    (`!wdfkd.wdfqueue`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["driver"], Literal["device"], Literal["dispatch_type"], Literal["state"], Literal["state_names"], Literal["power_state"], Literal["power_managed"], Literal["allow_zero_length_requests"], Literal["deleted"], Literal["execution_level"], Literal["synchronization_scope"], Literal["max_parallel_requests"], Literal["pending_count"], Literal["driver_cancelable_count"], Literal["driver_owned_count"], Literal["two_phase_completions"], Literal["callbacks"], Literal["pending"], Literal["pending_stopped"], Literal["driver_cancelable"], Literal["driver_cancelable_stopped"], Literal["driver_owned"], Literal["driver_owned_stopped"]]]
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
    def dispatch_type(self, /) -> WdfEnumValue:
        """
        `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        """
    @property
    def driver(self, /) -> str |None:
        """
        The owning driver's name, when it has one.
        """
    @property
    def driver_cancelable(self, /) -> list[WdfRequestRef]:
        """
        Requests the driver marked cancelable (`m_DriverCancelable`).
        """
    @property
    def driver_cancelable_count(self, /) -> int:
        """
        Requests the driver marked cancelable.
        """
    @property
    def driver_cancelable_stopped(self, /) -> str |None:
        """
        Why the walk of `driver_cancelable` stopped early; `None` if it
        completed.
        """
    @property
    def driver_owned(self, /) -> list[WdfRequestRef]:
        """
        Requests presented to the driver (`m_DriverOwned`).
        """
    @property
    def driver_owned_count(self, /) -> int:
        """
        Requests the driver owns.
        """
    @property
    def driver_owned_stopped(self, /) -> str |None:
        """
        Why the walk of `driver_owned` stopped early; `None` if it completed.
        """
    @property
    def execution_level(self, /) -> WdfEnumValue:
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
    def pending(self, /) -> list[WdfRequestRef]:
        """
        Requests waiting in the queue (`m_Queue`).
        """
    @property
    def pending_count(self, /) -> int:
        """
        Requests waiting in the queue.
        """
    @property
    def pending_stopped(self, /) -> str |None:
        """
        Why the walk of `pending` stopped early; `None` if it completed.
        """
    @property
    def power_managed(self, /) -> bool: ...
    @property
    def power_state(self, /) -> WdfEnumValue:
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
    def synchronization_scope(self, /) -> WdfEnumValue:
        """
        `_WDF_SYNCHRONIZATION_SCOPE`.
        """
    @property
    def two_phase_completions(self, /) -> int: ...

@final
class WdfQueueSummary(BaseRecord):
    """
    A queue of a device.
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["dispatch_type"], Literal["power_managed"], Literal["pending"], Literal["driver_owned"], Literal["is_default"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxIoQueue`.
        """
    @property
    def dispatch_type(self, /) -> WdfEnumValue:
        """
        `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        """
    @property
    def driver_owned(self, /) -> int:
        """
        Requests the driver owns (`m_DriverIoCount`).
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
        Requests waiting in the queue (`m_Queue.m_RequestCount`).
        """
    @property
    def power_managed(self, /) -> bool: ...

@final
class WdfRequestDetail(BaseRecord):
    """
    A WDFREQUEST with its IRP, its queue, and the I/O target it was sent
    to (`!wdfkd.wdfrequest`).
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["driver"], Literal["globals"], Literal["refcount"], Literal["object_state"], Literal["parent"], Literal["irp"], Literal["irp_detail"], Literal["irp_problem"], Literal["irp_allocation"], Literal["irp_reference_count"], Literal["completed"], Literal["canceled"], Literal["presented"], Literal["target_flags"], Literal["target_flag_names"], Literal["verifier_flags"], Literal["verifier_flag_names"], Literal["completion_state"], Literal["queue"], Literal["irp_queue"], Literal["irp_queue_role"], Literal["cancel_routine"], Literal["target"], Literal["completion_routine"], Literal["completion_context"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxRequest`.
        """
    @property
    def cancel_routine(self, /) -> WdfCallback |None:
        """
        The driver's `EvtRequestCancel` (`m_CancelRoutine`).
        """
    @property
    def canceled(self, /) -> bool: ...
    @property
    def completed(self, /) -> bool: ...
    @property
    def completion_context(self, /) -> int:
        """
        The completion routine's context (`m_TargetCompletionContext`).
        """
    @property
    def completion_routine(self, /) -> WdfCallback |None:
        """
        The completion routine set for its send (`m_CompletionRoutine`).
        """
    @property
    def completion_state(self, /) -> WdfEnumValue:
        """
        `m_CompletionState` (`FxRequestCompletionState`).
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
    def irp(self, /) -> int:
        """
        The IRP (`m_Irp.m_Irp`). Null for a request without an IRP.
        """
    @property
    def irp_allocation(self, /) -> WdfEnumValue:
        """
        `m_IrpAllocation` (`FxRequestAllocationSource`): whether the IRP
        came from the I/O manager (`REQUEST_ALLOCATED_FROM_IO`) or the
        framework or the driver allocated it.
        """
    @property
    def irp_detail(self, /) -> WdfRequestIrp |None:
        """
        The IRP, decoded. `None` if `irp` is null or not a live IRP.
        """
    @property
    def irp_problem(self, /) -> str |None:
        """
        Why `irp` is not a live IRP.
        """
    @property
    def irp_queue(self, /) -> int:
        """
        `m_IrpQueue`: the cancel-safe queue (`FxIrpQueue`) that holds its
        IRP. Null if none does, and the request cannot be canceled.
        """
    @property
    def irp_queue_role(self, /) -> Literal["pending", "driver_cancelable", "target_pended"] |None:
        """
        Which queue `irp_queue` is: `pending` (its queue's waiting
        requests), `driver_cancelable` (the driver marked it cancelable), or
        `target_pended` (its I/O target holds it until the target starts).
        `None` if `irp_queue` is null or none of these.
        """
    @property
    def irp_reference_count(self, /) -> int:
        """
        `m_IrpReferenceCount`.
        """
    @property
    def object_state(self, /) -> WdfEnumValue:
        """
        `m_ObjectState` (`FxObjectState`).
        """
    @property
    def parent(self, /) -> WdfObjectRef |None: ...
    @property
    def presented(self, /) -> bool:
        """
        `m_Presented`: whether its queue has presented it to the driver.
        """
    @property
    def queue(self, /) -> WdfObjectRef |None:
        """
        The queue that it came from or is in (`m_IoQueue`).
        """
    @property
    def refcount(self, /) -> int: ...
    @property
    def target(self, /) -> WdfObjectRef |None:
        """
        The I/O target that it was sent to (`m_Target`).
        """
    @property
    def target_flag_names(self, /) -> list[str]:
        """
        The `FxRequestTargetFlags` set in `target_flags`.
        """
    @property
    def target_flags(self, /) -> int:
        """
        `m_TargetFlags`.
        """
    @property
    def verifier_flag_names(self, /) -> list[str]:
        """
        The `FxRequestVerifierFlags` set in `verifier_flags`.
        """
    @property
    def verifier_flags(self, /) -> int:
        """
        `m_VerifierFlags`, which KMDF keeps only with the verifier on.
        """

@final
class WdfRequestIrp(BaseRecord):
    """
    The IRP that a request carries.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["stack_count"], Literal["current_location"], Literal["system_buffer"], Literal["user_buffer"], Literal["mdl_address"], Literal["current"]]]
    @property
    def address(self, /) -> int: ...
    @property
    def current(self, /) -> WdfIrpLocation |None:
        """
        `None` when `CurrentLocation` names no stack location, because the
        IRP has left every driver of the stack.
        """
    @property
    def current_location(self, /) -> int: ...
    @property
    def mdl_address(self, /) -> int: ...
    @property
    def stack_count(self, /) -> int: ...
    @property
    def system_buffer(self, /) -> int:
        """
        `AssociatedIrp.SystemBuffer`.
        """
    @property
    def user_buffer(self, /) -> int: ...

@final
class WdfRequestRef(BaseRecord):
    """
    A request on one of a queue's lists.
    """
    __match_args__: Final[tuple[Literal["handle"], Literal["address"], Literal["irp"]]]
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
class WdfTargetRequest(BaseRecord):
    """
    A request on one of an I/O target's lists.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["handle"], Literal["irp"]]]
    @property
    def address(self, /) -> int:
        """
        The `FxRequest`.
        """
    @property
    def handle(self, /) -> int |None:
        """
        The WDFREQUEST handle. `None` for the framework's own request that
        has no handle, such as the one a synchronous send builds on the
        sender's stack.
        """
    @property
    def irp(self, /) -> int: ...

@final
class WdfVersion(BaseRecord):
    """
    The KMDF version a client bound to (`_WDF_BIND_INFO.Version`).
    """
    __match_args__: Final[tuple[Literal["major"], Literal["minor"], Literal["build"]]]
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
    __match_args__: Final[tuple[Literal["record_address"], Literal["state"]]]
    @property
    def record_address(self, /) -> int |None:
        """
        The address of the record. `None` if the bugcheck does not give one.
        """
    @property
    def state(self, /) -> WheaRecordState: ...

@final
class WheaRecord(BaseRecord):
    """
    A decoded WHEA error record.
    """
    __match_args__: Final[tuple[Literal["revision"], Literal["severity"], Literal["length"], Literal["sections"]]]
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
    def severity(self, /) -> int:
        """
        The record's error severity (`WHEA_ERROR_SEVERITY`).
        """

class WheaRecordState(BaseRecord):
    """
    A WHEA error record, `decoded`, or `unavailable` with the `reason`.
    """
    @property
    def kind(self, /) -> Literal["decoded", "unavailable"]:
        """
        The variant: `decoded`, `unavailable`.
        """
    @final
    class Decoded(WheaRecordState):
        __match_args__: Final[tuple[Literal["decoded"]]]
        @property
        def decoded(self, /) -> WheaRecord: ...
        @property
        def kind(self, /) -> Literal["decoded"]:
            """
            `decoded`.
            """
    @final
    class Unavailable(WheaRecordState):
        __match_args__: Final[tuple[Literal["reason"]]]
        @property
        def kind(self, /) -> Literal["unavailable"]:
            """
            `unavailable`.
            """
        @property
        def reason(self, /) -> str: ...

@final
class WheaSection(BaseRecord):
    """
    One section of a WHEA error record.
    """
    __match_args__: Final[tuple[Literal["offset"], Literal["length"], Literal["severity"], Literal["section_type"], Literal["kind"]]]
    @property
    def kind(self, /) -> Literal["processor_generic", "memory", "pci_express", "x64_processor", "unknown"]: ...
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
class WinlogonBlackbox(BaseRecord):
    """
    What winlogon was doing.
    """
    __match_args__: Final[tuple[Literal["thread_name"], Literal["is_operation_pending"]]]
    @property
    def is_operation_pending(self, /) -> int: ...
    @property
    def thread_name(self, /) -> str: ...

@final
class WorkItem(BaseRecord):
    """
    A pending `_WORK_QUEUE_ITEM`.
    """
    __match_args__: Final[tuple[Literal["address"], Literal["routine"], Literal["routine_symbol"], Literal["parameter"], Literal["io_work_item"]]]
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
    __match_args__: Final[tuple[Literal["address"], Literal["partition"], Literal["node"], Literal["queue_index"], Literal["queue_index_name"], Literal["items_processed"], Literal["items_processed_last_pass"], Literal["thread_count"], Literal["min_threads"], Literal["max_threads"], Literal["concurrency"], Literal["pending"], Literal["priorities"], Literal["threads"], Literal["threads_termination"]]]
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
    def threads_termination(self, /) -> ListTermination:
        """
        How the worker-thread list walk ended.
        """

@final
class WorkQueuePriority(BaseRecord):
    """
    One of the 32 priority lists of a work queue.
    """
    __match_args__: Final[tuple[Literal["priority"], Literal["queue_types"], Literal["current_count"], Literal["items"], Literal["termination"]]]
    @property
    def current_count(self, /) -> int:
        """
        `CurrentCount[priority]`, the number of threads that run an item of
        this priority.
        """
    @property
    def items(self, /) -> list[WorkItem]:
        """
        The pending work items (key `items`).
        """
    @property
    def priority(self, /) -> int: ...
    @property
    def queue_types(self, /) -> list[str]:
        """
        The `WORK_QUEUE_TYPE`s that `ExQueueWorkItem` maps to this priority.
        """
    @property
    def termination(self, /) -> ListTermination:
        """
        How the list walk ended.
        """

@final
class WorkQueues(BaseRecord):
    """
    All executive worker queues (`!exqueue`).
    """
    __match_args__: Final[tuple[Literal["flags"], Literal["priority_filter"], Literal["queues"], Literal["errors"]]]
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
    __match_args__: Final[tuple[Literal["kthread"], Literal["thread"], Literal["stack"]]]
    @property
    def kthread(self, /) -> int: ...
    @property
    def stack(self, /) -> Diagnostic[list[StackFrame]] |None:
        """
        The stack of the thread; `None` if stacks were not requested or the
        thread did not decode.
        """
    @property
    def thread(self, /) -> Diagnostic[ThreadInfo]: ...

@final
class ZombieKinds(BaseRecord):
    """
    Which kinds `!zombies` looks for (WinDbg's flags: 1 processes, 2 threads).
    """
    __match_args__: Final[tuple[Literal["processes"], Literal["threads"]]]
    @property
    def processes(self, /) -> bool: ...
    @property
    def threads(self, /) -> bool: ...

@final
class ZombieProcess(BaseRecord):
    """
    An exited process whose object still has references.
    """
    __match_args__: Final[tuple[Literal["eprocess"], Literal["pid"], Literal["image"], Literal["exit_time"], Literal["exit_status"], Literal["handle_count"], Literal["pointer_count"]]]
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
    __match_args__: Final[tuple[Literal["ethread"], Literal["pid"], Literal["tid"], Literal["process"], Literal["image"], Literal["exit_status"], Literal["handle_count"], Literal["pointer_count"]]]
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
        The owning `_EPROCESS` (`Tcb.Process`).
        """
    @property
    def tid(self, /) -> int: ...

@final
class Zombies(BaseRecord):
    """
    The exited processes and terminated threads that still have references
    (`!zombies`), which ntoseye finds with a scan of nonpaged pool.
    """
    __match_args__: Final[tuple[Literal["kinds"], Literal["region_start"], Literal["region_end"], Literal["scanned_pages"], Literal["processes"], Literal["threads"], Literal["live_processes"], Literal["live_threads"], Literal["interrupted"], Literal["truncated"]]]
    @property
    def interrupted(self, /) -> bool:
        """
        True if the scan was interrupted before it finished.
        """
    @property
    def kinds(self, /) -> ZombieKinds:
        """
        The kinds the scan looked for; the list of a kind it did not look for
        is empty.
        """
    @property
    def live_processes(self, /) -> int:
        """
        The number of live processes that the scan found, to put the zombies
        in proportion.
        """
    @property
    def live_threads(self, /) -> int:
        """
        The number of live threads that the scan found.
        """
    @property
    def processes(self, /) -> list[ZombieProcess]: ...
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
    def threads(self, /) -> list[ZombieThread]: ...
    @property
    def truncated(self, /) -> bool:
        """
        True if a result list reached its limit ([`MAX_ZOMBIES`]).
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
    kd/kdnet/gdb, or the dump file path for dmp: a kernel crash dump, or a
    Windows user-mode minidump, whose process and threads `Debugger.user_dump`
    holds. Without `connect`, the function uses the default of the backend,
    but dmp has no default and needs a path. kdnet needs `key`.
    `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
    
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
