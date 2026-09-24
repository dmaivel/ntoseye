//! Maps physical pages in Windows kernel crash dumps to file offsets.
//!
//! Adapted from `kdmp-parser` 0.8.1 (MIT). See `THIRD-PARTY.md` for attribution.

use std::collections::BTreeMap;

use zerocopy::FromBytes;

use crate::dmp::structs::{
    BmpHeader64, DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP, DumpType,
    FullRdmpHeader64, Header64, KernelRdmpHeader64, PfnRange, PhysmemDesc, PhysmemRun,
};
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;

/// Maps a guest-physical address to the file offset where the page lives.
pub type PhysmemMap = BTreeMap<u64, u64>;

const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

pub struct ParsedDump {
    pub headers: Header64,
    pub dump_type: DumpType,
    pub physmem: PhysmemMap,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidDump(message.into())
}

/// A bounds-checked forward cursor over the mapped dump.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn position(&self) -> u64 {
        self.pos as u64
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| invalid("dump cursor overflowed"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| invalid("dump is truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    fn read<T: FromBytes>(&mut self) -> Result<T> {
        let bytes = self.take(size_of::<T>())?;
        T::read_from_bytes(bytes).map_err(|_| invalid("dump is truncated"))
    }
}

/// Read a `T` out of a fixed in-header buffer.
fn read_from<T: FromBytes>(buffer: &[u8], offset: usize) -> Result<T> {
    let end = offset
        .checked_add(size_of::<T>())
        .ok_or_else(|| invalid("header buffer overflowed"))?;
    let bytes = buffer
        .get(offset..end)
        .ok_or_else(|| invalid("header buffer is too small"))?;
    T::read_from_bytes(bytes).map_err(|_| invalid("header buffer is too small"))
}

fn insert_page(physmem: &mut PhysmemMap, gpa: u64, file_offset: u64) -> Result<()> {
    if physmem.insert(gpa, file_offset).is_some() {
        return Err(invalid(format!("duplicate physical page at {gpa:#x}")));
    }
    Ok(())
}

fn advance_page(page_offset: u64) -> Result<u64> {
    page_offset
        .checked_add(PAGE_SIZE_U64)
        .ok_or_else(|| invalid("page file offset overflowed"))
}

fn remaining_page_data(data: &[u8], page_offset: u64) -> Result<u64> {
    let offset = usize::try_from(page_offset)
        .map_err(|_| invalid("page data offset exceeds the dump size"))?;
    let remaining = data
        .get(offset..)
        .ok_or_else(|| invalid("page data offset exceeds the dump size"))?;
    u64::try_from(remaining.len() / PAGE_SIZE)
        .map_err(|_| invalid("page data extent exceeds addressable pages"))
}

/// Parse the dump header and build its physical-memory map.
pub fn parse(data: &[u8]) -> Result<ParsedDump> {
    let mut cursor = Cursor::new(data);
    let headers = cursor.read::<Header64>()?;

    if headers.signature != DUMP_HEADER64_EXPECTED_SIGNATURE {
        return Err(invalid(format!(
            "bad dump signature {:#x}",
            headers.signature
        )));
    }

    if headers.valid_dump != DUMP_HEADER64_EXPECTED_VALID_DUMP {
        return Err(invalid(format!(
            "bad valid-dump marker {:#x}",
            headers.valid_dump
        )));
    }

    let dump_type = DumpType::try_from(headers.dump_type)?;
    let physmem = match dump_type {
        DumpType::Full => full_physmem(&headers, &mut cursor)?,
        DumpType::Bmp | DumpType::LiveKernelMemory => bmp_physmem(&mut cursor)?,
        DumpType::KernelMemory | DumpType::KernelAndUserMemory | DumpType::CompleteMemory => {
            kernel_physmem(dump_type, &mut cursor)?
        }
    };

    Ok(ParsedDump {
        headers,
        dump_type,
        physmem,
    })
}

/// Build the physical memory map for a [`DumpType::Full`] dump.
///
/// Each run describes consecutive PFNs. Page contents are packed after the
/// header in run order; gaps in physical memory consume no file space.
fn full_physmem(headers: &Header64, cursor: &mut Cursor<'_>) -> Result<PhysmemMap> {
    let mut page_offset = cursor.position();
    let runs_buffer = &headers.physical_memory_block_buffer;
    let physmem_desc = read_from::<PhysmemDesc>(runs_buffer, 0)?;
    if physmem_desc.number_of_pages > remaining_page_data(cursor.data, page_offset)? {
        return Err(invalid("declared physical page count exceeds dump data"));
    }

    let mut physmem = PhysmemMap::new();
    let mut page_count = 0u64;

    for run_idx in 0..physmem_desc.number_of_runs as usize {
        let offset = size_of::<PhysmemDesc>() + run_idx * size_of::<PhysmemRun>();
        let run = read_from::<PhysmemRun>(runs_buffer, offset).map_err(|_| {
            invalid(format!(
                "physical memory run {run_idx} does not fit in the dump header"
            ))
        })?;

        let next_page_count = page_count
            .checked_add(run.page_count)
            .ok_or_else(|| invalid("physical page count overflowed"))?;
        if next_page_count > physmem_desc.number_of_pages {
            return Err(invalid("physical memory runs exceed number_of_pages"));
        }
        if run.page_count > remaining_page_data(cursor.data, page_offset)? {
            return Err(invalid(format!(
                "physical memory run {run_idx} exceeds dump page data"
            )));
        }

        for page_idx in 0..run.page_count {
            let gpa = run
                .base_page
                .checked_add(page_idx)
                .and_then(|page| page.checked_mul(PAGE_SIZE_U64))
                .ok_or_else(|| {
                    invalid(format!(
                        "physical address overflow in run {run_idx} page {page_idx}"
                    ))
                })?;

            insert_page(&mut physmem, gpa, page_offset)?;
            page_offset = advance_page(page_offset)?;
        }
        page_count = next_page_count;
    }

    if page_count != physmem_desc.number_of_pages {
        return Err(invalid("physical memory runs do not match number_of_pages"));
    }

    Ok(physmem)
}

/// Build the physical memory map for a [`DumpType::Bmp`] dump.
fn bmp_physmem(cursor: &mut Cursor<'_>) -> Result<PhysmemMap> {
    let bmp_header = cursor.read::<BmpHeader64>()?;
    if !bmp_header.looks_good() {
        return Err(invalid("bmp header doesn't look right"));
    }

    let remaining_bits = (bmp_header.pages % 8) as u32;
    let bitmap_size = usize::try_from(bmp_header.pages.div_ceil(8))
        .map_err(|_| invalid("bitmap is too large to address"))?;
    // Validate the bitmap's extent before iterating over untrusted page counts.
    let bitmap = cursor.take(bitmap_size)?;

    let mut page_offset = bmp_header.first_page;
    let mut physmem = PhysmemMap::new();

    for (bitmap_idx, &byte) in bitmap.iter().enumerate() {
        // Ignore padding bits in the final byte.
        let byte = if bitmap_idx == bitmap_size - 1 && remaining_bits != 0 {
            byte & (1u8 << remaining_bits).wrapping_sub(1)
        } else {
            byte
        };

        if byte == 0 {
            continue;
        }

        for bit_idx in 0..8u32 {
            if (byte >> bit_idx) & 1 == 0 {
                continue;
            }

            let gpa = (bitmap_idx as u64)
                .checked_mul(8)
                .and_then(|base| base.checked_add(u64::from(bit_idx)))
                .and_then(|pfn| pfn.checked_mul(PAGE_SIZE_U64))
                .ok_or_else(|| invalid("physical address overflow in bitmap"))?;

            insert_page(&mut physmem, gpa, page_offset)?;
            page_offset = advance_page(page_offset)?;
        }
    }

    Ok(physmem)
}

/// Build the physical memory map for [`DumpType::KernelMemory`],
/// [`DumpType::KernelAndUserMemory`] and [`DumpType::CompleteMemory`] dumps.
fn kernel_physmem(dump_type: DumpType, cursor: &mut Cursor<'_>) -> Result<PhysmemMap> {
    let (mut page_offset, metadata_size, total_number_of_pages) = match dump_type {
        DumpType::KernelMemory | DumpType::KernelAndUserMemory => {
            let kernel_hdr = cursor.read::<KernelRdmpHeader64>()?;
            if !kernel_hdr.hdr.looks_good() {
                return Err(invalid("RdmpHeader64 doesn't look right"));
            }

            (
                kernel_hdr.hdr.first_page_offset,
                kernel_hdr.hdr.metadata_size,
                0,
            )
        }
        DumpType::CompleteMemory => {
            let full_hdr = cursor.read::<FullRdmpHeader64>()?;
            if !full_hdr.hdr.looks_good() {
                return Err(invalid("FullRdmpHeader64 doesn't look right"));
            }

            (
                full_hdr.hdr.first_page_offset,
                full_hdr.hdr.metadata_size,
                full_hdr.total_number_of_pages,
            )
        }
        _ => unreachable!("kernel_physmem called with {dump_type:?}"),
    };

    if page_offset == 0 || metadata_size == 0 {
        return Err(invalid("no first page or metadata size"));
    }

    let pfn_range_size = size_of::<PfnRange>() as u64;
    if !metadata_size.is_multiple_of(pfn_range_size) {
        return Err(invalid("metadata size is not a multiple of the PFN range"));
    }

    let number_pfns = metadata_size / pfn_range_size;
    let mut page_count = 0u64;
    let mut physmem = PhysmemMap::new();

    for _ in 0..number_pfns {
        if dump_type == DumpType::CompleteMemory {
            // `CompleteMemory` dumps are bound by `total_number_of_pages`,
            // *not* by `metadata_size`.
            if page_count == total_number_of_pages {
                break;
            }

            if page_count > total_number_of_pages {
                return Err(invalid("page count exceeds total_number_of_pages"));
            }
        }

        let pfn_range = cursor.read::<PfnRange>()?;
        if pfn_range.page_file_number == 0 {
            break;
        }

        let next_page_count = page_count
            .checked_add(pfn_range.number_of_pages)
            .ok_or_else(|| invalid("page count overflowed"))?;
        if dump_type == DumpType::CompleteMemory && next_page_count > total_number_of_pages {
            return Err(invalid("page count exceeds total_number_of_pages"));
        }
        if pfn_range.number_of_pages > remaining_page_data(cursor.data, page_offset)? {
            return Err(invalid("PFN range exceeds dump page data"));
        }

        for page_idx in 0..pfn_range.number_of_pages {
            let gpa = pfn_range
                .page_file_number
                .checked_add(page_idx)
                .and_then(|pfn| pfn.checked_mul(PAGE_SIZE_U64))
                .ok_or_else(|| invalid("physical address overflow in PFN range"))?;

            insert_page(&mut physmem, gpa, page_offset)?;
            page_offset = advance_page(page_offset)?;
        }

        page_count = next_page_count;
    }

    Ok(physmem)
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use crate::dmp::structs::RdmpHeader64;

    use super::*;

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn full_dump(run_pages: u64, declared_pages: u64, file_pages: usize) -> Vec<u8> {
        let mut data = vec![0; size_of::<Header64>() + file_pages * PAGE_SIZE];
        put_u32(
            &mut data,
            offset_of!(Header64, signature),
            DUMP_HEADER64_EXPECTED_SIGNATURE,
        );
        put_u32(
            &mut data,
            offset_of!(Header64, valid_dump),
            DUMP_HEADER64_EXPECTED_VALID_DUMP,
        );
        put_u32(
            &mut data,
            offset_of!(Header64, dump_type),
            DumpType::Full as u32,
        );

        let descriptor = offset_of!(Header64, physical_memory_block_buffer);
        put_u32(
            &mut data,
            descriptor + offset_of!(PhysmemDesc, number_of_runs),
            1,
        );
        put_u64(
            &mut data,
            descriptor + offset_of!(PhysmemDesc, number_of_pages),
            declared_pages,
        );
        let run = descriptor + size_of::<PhysmemDesc>();
        put_u64(&mut data, run + offset_of!(PhysmemRun, base_page), 1);
        put_u64(
            &mut data,
            run + offset_of!(PhysmemRun, page_count),
            run_pages,
        );
        data
    }

    fn complete_dump(ranges: &[(u64, u64)], total_pages: u64, file_pages: usize) -> Vec<u8> {
        let metadata_size = (ranges.len() * size_of::<PfnRange>()) as u64;
        let page_offset = metadata_size + 0x2020;
        let file_size = (page_offset as usize)
            .max(size_of::<Header64>() + size_of::<FullRdmpHeader64>())
            + file_pages * PAGE_SIZE;
        let mut data = vec![0; file_size];
        put_u32(
            &mut data,
            offset_of!(Header64, signature),
            DUMP_HEADER64_EXPECTED_SIGNATURE,
        );
        put_u32(
            &mut data,
            offset_of!(Header64, valid_dump),
            DUMP_HEADER64_EXPECTED_VALID_DUMP,
        );
        put_u32(
            &mut data,
            offset_of!(Header64, dump_type),
            DumpType::CompleteMemory as u32,
        );

        let header = size_of::<Header64>();
        put_u32(&mut data, header, 0x40);
        put_u32(&mut data, header + 4, 0x50_4D_44_52);
        put_u32(&mut data, header + 8, 0x50_4D_55_44);
        put_u64(
            &mut data,
            header + offset_of!(RdmpHeader64, metadata_size),
            metadata_size,
        );
        put_u64(
            &mut data,
            header + offset_of!(RdmpHeader64, first_page_offset),
            page_offset,
        );
        put_u64(
            &mut data,
            header + offset_of!(FullRdmpHeader64, total_number_of_pages),
            total_pages,
        );

        let ranges_offset = header + size_of::<FullRdmpHeader64>();
        for (index, &(first_page, page_count)) in ranges.iter().enumerate() {
            let offset = ranges_offset + index * size_of::<PfnRange>();
            put_u64(&mut data, offset, first_page);
            put_u64(&mut data, offset + 8, page_count);
        }
        data
    }

    #[test]
    fn full_dump_rejects_page_runs_larger_than_file_data() {
        let data = full_dump(2, 2, 1);
        assert!(parse(&data).is_err());
    }

    #[test]
    fn complete_dump_rejects_a_range_exceeding_declared_pages() {
        let data = complete_dump(&[(1, 1), (2, 2)], 2, 3);
        assert!(parse(&data).is_err());
    }
}
