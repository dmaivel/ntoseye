use crate::repl::*;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::Expr;
use crate::types::PhysAddr;

use super::memory::{MAX_DISPLAY_BYTES, parse_write_values, read_page_chunks};

repl_command! {
    cmd_phys_db;
    names: ["!db"],
    usage: "!db <address> [L<count>|length|end]",
    summary: "Display guest-physical memory as bytes.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dw;
    names: ["!dw"],
    usage: "!dw <address> [L<count>|length|end]",
    summary: "Display guest-physical memory as words.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dd;
    names: ["!dd"],
    usage: "!dd <address> [L<count>|length|end]",
    summary: "Display guest-physical memory as doublewords.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dq;
    names: ["!dq"],
    usage: "!dq <address> [L<count>|length|end]",
    summary: "Display guest-physical memory as quadwords.",
    completion: Expression,
}

repl_command! {
    cmd_phys_eb;
    names: ["!eb"],
    usage: "!eb <address> <value...>",
    summary: "Write one or more bytes to guest-physical memory.",
    completion: Expression,
}

repl_command! {
    cmd_phys_ed;
    names: ["!ed"],
    usage: "!ed <address> <value...>",
    summary: "Write one or more doublewords to guest-physical memory.",
    completion: Expression,
}

repl_command! {
    cmd_phys_eq;
    names: ["!eq"],
    usage: "!eq <address> <value...>",
    summary: "Write one or more quadwords to guest-physical memory.",
    completion: Expression,
}

impl ReplState<'_> {
    fn read_physical_best_effort(&self, range: &AddressRange) -> (Vec<u8>, Vec<bool>) {
        read_page_chunks(range.start, range.len(), |address, buf| {
            self.ctx.target.phys.read_bytes(address.0, buf)
        })
    }

    fn display_physical_command(
        &self,
        invocation: &CommandInvocation<'_>,
        default_count: u64,
        item_size: u64,
        mode: MemoryDisplayMode,
    ) -> Result<()> {
        let range = match AddressRange::parse(
            invocation,
            &self.ctx.target,
            self.radix,
            default_count,
            item_size,
        ) {
            Ok(range) => range,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return Ok(());
        }
        let (data, valid) = self.read_physical_best_effort(&range);
        display_memory_with_validity(range.start, &data, Some(&valid), &mode);
        Ok(())
    }

    fn write_physical_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        noun: &str,
        encode: impl Fn(u64) -> Vec<u8>,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help(command));
            return Ok(());
        }
        let address =
            match Expr::eval_with_radix(invocation.arg(0).unwrap(), &self.ctx.target, self.radix) {
                Ok(address) => address.0,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            };
        let values = match parse_write_values(self, invocation) {
            Ok(values) => values,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend(encode(value));
        }
        match self
            .ctx
            .target
            .phys
            .write_bytes(address as PhysAddr, &bytes)
        {
            Ok(()) => outln!("wrote {} bytes to physical {:#x}\n", bytes.len(), address),
            Err(e) => error!("failed to write physical {}: {}", noun, e),
        }
        Ok(())
    }

    fn cmd_phys_db(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 128, 1, MemoryDisplayMode::bytes())
    }

    fn cmd_phys_dw(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 32, 2, MemoryDisplayMode::words())
    }

    fn cmd_phys_dd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 16, 4, MemoryDisplayMode::dwords())
    }

    fn cmd_phys_dq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 8, 8, MemoryDisplayMode::qwords())
    }

    fn cmd_phys_eb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!eb", "byte", |value| vec![value as u8])
    }

    fn cmd_phys_ed(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!ed", "dword", |value| {
            (value as u32).to_le_bytes().to_vec()
        })
    }

    fn cmd_phys_eq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!eq", "qword", |value| {
            value.to_le_bytes().to_vec()
        })
    }
}
