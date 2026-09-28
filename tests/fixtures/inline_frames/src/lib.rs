#![no_std]

use core::hint::black_box;
use core::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
fn scale(value: u32, factor: u32) -> u32 {
    let scaled = black_box(value.wrapping_mul(factor));
    COUNTER.fetch_add(scaled, Ordering::SeqCst);
    scaled
}

#[inline(always)]
fn accumulate(value: u32) -> u32 {
    let doubled = scale(value, 2);
    let tripled = scale(doubled, 3);
    black_box(doubled ^ tripled)
}

#[unsafe(no_mangle)]
pub extern "system" fn DriverEntry(driver: *mut u8, registry: *mut u8) -> u32 {
    let seed = black_box(driver as usize as u32);
    let total = accumulate(seed);
    total.wrapping_add(registry as usize as u32)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
