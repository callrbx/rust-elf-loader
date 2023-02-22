use std::{env, error::Error, fs};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: info FILE");
    let input = fs::read(&input_path)?;

    let elf = match elfparse::File::parse_or_print_error(&input[..]) {
        Ok(bin) => bin,
        Err(e) => {
            eprintln!("input is not a supported ELF file!");
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    println!("Mapping {:?} in memory...", input_path);

    // we'll need to hold onto our "mmap::MemoryMap", because dropping them
    // unmaps them!
    let mut mappings = Vec::new();

    let base = 0x400000_usize;

    // we're only interested in "Load" segments
    for ph in elf
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == elfparse::SegmentType::LOAD)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = aligned_start as _;
        let paddr: *mut u8 = (aligned_start + padding) as _;
        println!("Addr: {:p}, Padding: {:08x}", addr, padding);

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data... {}", ph.data.len());
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(paddr, ph.data.len()) };
            dst.copy_from_slice(&ph.data[..]);
        }

        println!("Adjusting permissions...");
        // the `region` crate and our `elfparse` crate have two different
        // enums (and bit flags) for protection, so we need to map from
        // elfparse's to region's.
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                elfparse::SegmentFlag::Read => Protection::READ,
                elfparse::SegmentFlag::Write => Protection::WRITE,
                elfparse::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Jumping to entry point @ base + {:?}...", elf.entry_point);
    pause("jmp")?;
    unsafe {
        // note that we don't have to do pointer arithmetic here,
        // as the entry point is indeed mapped in memory at the right place.
        jmp((elf.entry_point.0 + base) as _);
    }

    Ok(())
}

// jump to arbitrary address and being execution
unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

// And this little helper function is new as well!
fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

fn align_lo(x: usize) -> usize {
    x & !0xFFF
}
