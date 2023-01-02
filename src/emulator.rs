use crate::{
    emulator::FileType::{STDIN, STDOUT, STDERR},
    MAX_ALLOCATION_ADDR, FIRSTALLOCATION,
};
use rustc_hash::FxHashMap;
use unicorn_engine::{
    Unicorn,
    unicorn_const::{Permission, uc_error},
};

/// Different types of exit-conditions for the fuzzer
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExitType {
    /// Leave JIT to create snapshot at this address
    Snapshot,

    /// Leave JIT reporting success-case
    Success,

    /// Exit JIT as if exit() was called
    Exit,
}

/// Different types of files that the fuzzer supports
#[derive(Copy, Debug, Clone, Eq, PartialEq)]
pub enum FileType {
    /// STDIN (0)
    STDIN,

    /// STDOUT (1), basically ignored apart from debug-prints to console
    STDOUT,

    /// STDERR (2), basically ignored apart from debug-prints to console
    STDERR,

    /// The input we are fuzzing. It keeps its byte-backing in emulator.fuzz_input
    FUZZINPUT,

    /// A standard file that is not 0/1/2 or the input we are fuzzing
    OTHER,

    /// Invalid file
    INVALID,
}

/// Memoery mapped file implementation
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct File {
    /// Filetype of this file
    pub ftype:   FileType,

    /// The byte-backing used by this file. Not required by 0/1/2, or the fuzzinput
    pub backing: Option<Vec<u8>>,

    /// Cursor is used by the fuzz-input and potential other files that aren't 0/1/2
    pub cursor:  Option<usize>,
}

impl File {
    fn new(ftype: FileType) -> Self {
        let (backing, cursor) = match ftype {
            FileType::OTHER => (Some(Vec::new()), Some(0)),
            FileType::FUZZINPUT => (None, Some(0)),
            _ => (None, None),
        };
        File {
            ftype,
            backing,
            cursor,
        }
    }
}

/// Emulator that runs the actual code. Each thread gets its own emulator 
pub struct Emulator {
    /// List of file descriptors that the process can use for syscalls
    pub fd_list: Vec<File>,

    /// The fuzz input that is in use by the current case
    pub fuzz_input: Vec<u8>,

    /// Map of exit conditions that would cause the fuzzer to prematurely exit
    pub _exit_conds: FxHashMap<usize, ExitType>,

    /// JIT-backing-address at which the injected code for the snapshot is located
    pub _snapshot_addr: usize,

    /// Holds the current program break at which new memory is allocated whenever needed
    alloc_addr: usize,

    /// Allocations made during process run, used to find heap bugs
    heap_allocations: FxHashMap<usize, usize>,
}

impl Emulator {
    /// Create a new emulator that has access to the shared jit backing
    pub fn new() -> Self {
        Emulator {
            fd_list:         vec![File::new(STDIN), File::new(STDOUT), File::new(STDERR)],
            fuzz_input:      Vec::new(),
            _exit_conds:      FxHashMap::default(),
            _snapshot_addr:   0,
            alloc_addr:       FIRSTALLOCATION,
            heap_allocations: FxHashMap::default(),
        }
    }

    /// Allocate a new new memory region, memory is never repeated, each allocation returns fresh 
    /// memory, even if a prior allocation was free'd
    pub fn allocate(&mut self, uc: &mut Unicorn<'_, ()>, size: usize, perms: Permission) 
            -> Option<usize> {
        // Need to align all allocations to page size due to unicorn restrictions
        let aligned_size = (0xfff + size) & !0xfff;
        let base = self.alloc_addr;

        // Cannot allocate without running out of memory
        if base >= MAX_ALLOCATION_ADDR || base.checked_add(aligned_size)? >= MAX_ALLOCATION_ADDR {
            return None;
        }

        // Register this allocation
        self.heap_allocations.insert(base, aligned_size);

        // Set permissions on allocated memory region and increase the next allocation addr
        uc.mem_protect(base as u64, aligned_size, perms).ok()?;
        self.alloc_addr = self.alloc_addr.checked_add(aligned_size)?;

        // Mark as dirty

        Some(base)
    }

    /// Free a region of previously allocated memory
    pub fn free(&mut self, uc: &mut Unicorn<'_, ()>, addr: usize) 
            -> Result<(), uc_error> {

        if addr > MAX_ALLOCATION_ADDR {
            //return Err(Fault::InvalidFree(addr));
            panic!("Invalid Free @ 0x{:X}", addr);
        }

        let allocation_size = self.heap_allocations.get(&addr);
        if allocation_size.is_none() {
            panic!("Attempting to free memory that hasn't been allocted @ 0x{:X}", addr);
        }

        let aligned_size = (0xfff + allocation_size.unwrap()) & !0xfff;

        // Unset all permissions including metadata
        uc.mem_protect(addr as u64, aligned_size, Permission::NONE)?;
        Ok(())
    }

    /// Allocate a new file in the emulator
    pub fn alloc_file(&mut self, ftype: FileType) -> usize {
        let file = File::new(ftype);
        self.fd_list.push(file);
        self.fd_list.len() - 1
    }
}
