#![no_std]

mod parse;

extern crate alloc;

use alloc::fmt::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Range;
use core::{fmt, usize};
use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;
use nom::{
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::many_till,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
};

pub struct HexDump<'a>(&'a [u8]);

// "Add" and "Sub" are in `derive_more`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub usize);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0 as u64
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x as usize)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(le_u64, From::from)(i)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    NONE = 0x0,
    REL = 0x1,
    EXEC = 0x2,
    DYN = 0x3,
    CORE = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    NULL = 0x0,
    LOAD = 0x1,
    DYNAMIC = 0x2,
    INTERP = 0x3,
    NOTE = 0x4,
    SHLIB = 0x5,
    PHDR = 0x6,
    LOPROC = 0x7,
    HIPROC = 0x8,
    EHFRAME = 0x6474e550,
    GNUSTACK = 0x6474e551,
    GNURELRO = 0x6474e552,
    GNUPROPERTY = 0x6474e553,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[bitflags]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    Flags = 30,
    LoOs = 0x60000000,
    VerSym = 0x6ffffff0,
    VerNeeded = 0x6ffffffe,
    HiOs = 0x6fffffff,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
    GnuHash = 0x6ffffef5,
    Flags1 = 0x6ffffffb,
    RelACount = 0x6ffffff9,
}

impl_parse_for_enum!(DynamicTag, le_u64);
impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);
impl_parse_for_enum!(SegmentType, le_u32);
impl_parse_for_enumflags!(SegmentFlag, le_u32);

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
    pub contents: SegmentContents,
}

#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse_or_print_error(i: parse::Input) -> Result<Self, String> {
        match Self::parse(i) {
            Ok((_, file)) => Ok(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                let mut err_string = String::new();
                for (input, err) in err.errors {
                    err_string.push_str(&format(format_args!("{:?} at:", err)));
                    err_string.push_str(&format(format_args!("{:?}", HexDump(input))));
                }
                Err(err_string)
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }

    #[allow(unused_variables)]
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;

        // Verify Needed ELF Header Fields
        let (i, _) = tuple((
            // -------
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endianness", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            // -------
            context("Padding", take(8_usize)),
        ))(i)?;

        // parse elf type, machine id, entry point
        let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;

        // parse elf headers
        // this 32-bit integer should always be set to 1 in the current
        // version of ELF, see the diagram. We don't *have* to check it,
        // but it's so easy to, let's anyway!
        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;

        // // some values are stored as u16 to save storage, but they're actually
        // // file offsets, or counts, so we want them as `usize` in rust.
        // // ph = program header, sh = section header
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) =
            tuple((map(le_u16, |x| x as usize), map(le_u16, |x| x as usize)))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((
            map(le_u16, |x| x as usize),
            map(le_u16, |x| x as usize),
            map(le_u16, |x| x as usize),
        ))(i)?;

        // // `chunks()` divides a slice into chunks of equal size - perfect, as we know the entry size.
        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::new();

        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let res = Self {
            machine,
            r#type,
            entry_point,
            program_headers,
        };
        Ok((i, res))
    }
}

impl Type {
    pub fn from_u16(x: u16) -> Option<Self> {
        match x {
            0 => Some(Self::NONE),
            1 => Some(Self::REL),
            2 => Some(Self::EXEC),
            3 => Some(Self::DYN),
            4 => Some(Self::CORE),
            _ => None,
        }
    }
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

impl ProgramHeader {
    /**
     * File range where the segment is stored
     */
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /**
     * Memory range where the segment is mapped
     */
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        // this used to be directly in the `Self` struct literal, but
        // we're going to use it in the next block to parse dynamic entries from it.
        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::DYNAMIC => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _last)| SegmentContents::Dynamic(entries),
            )(slice)?,
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            data: full_input[offset.into()..][..filesz.into()].to_vec(),
            contents,
        };
        Ok((i, res))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            // the default Debug formatter for `enumflags2` is a bit
            // on the verbose side, let's print something like `RWX` instead
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type,
        )
    }
}

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Machine;
    use super::SegmentFlag;
    use core::convert::TryFrom;
    use enumflags2::BitFlags;

    #[test]
    fn try_enums() {
        assert_eq!(Machine::X86_64 as u16, 0x3E);
        assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0xFA), Err(0xFA));
    }
    #[test]
    fn type_to_u16() {
        assert_eq!(super::Type::DYN as u16, 0x3);
    }

    #[test]
    fn type_from_u16() {
        assert_eq!(super::Type::from_u16(0x3), Some(super::Type::DYN));
        assert_eq!(super::Type::from_u16(0xf00d), None);
    }

    #[test]
    fn try_bitflag() {
        // this is a value we could've read straight from an ELF file
        let flags_integer: u32 = 6;
        // this is how we parse it. in practice, it's less verbose,
        // because of type inference.
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        // this does not correspond to any flags
        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}
