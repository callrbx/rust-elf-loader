#![no_main]

// jump to arbitrary address and being execution
pub unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
