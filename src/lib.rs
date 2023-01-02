//! # ZFUZZ
//!
//! Follow up on SFUZZ built on unicorn emulation engine

#![feature(once_cell)]

pub mod syscalls;
pub mod emulator;
pub mod hooks;
pub mod config;

use elfparser::{self, ARCH64, ELFMAGIC, LITTLEENDIAN, TYPEEXEC, RISCV};
use unicorn_engine::{
    Unicorn,
    unicorn_const::{Permission, uc_error},
};

use std::process;

pub const DEBUG: bool = true;
const TARGET: &str = "./test_cases/hello";

/// The starting address for our memory allocator
pub const FIRSTALLOCATION: usize = 0x900000;

/// Amount of memory allocated for each emulator to handle stack & heap allocations
pub const VMMAP_ALLOCATION_SIZE: usize = 16 * 1024 * 1024;

/// Maximum allocation address
pub const MAX_ALLOCATION_ADDR: usize = FIRSTALLOCATION + VMMAP_ALLOCATION_SIZE;

/// Small wrapper to easily handle unrecoverable errors without panicking
pub fn error_exit(msg: &str) -> ! {
    println!("{}", msg);
    process::exit(1);
}

/// Small wrapper to easily handle debug prints
pub fn dbg_print(msg: &str) {
    if DEBUG {
        println!("[DEBUG]: {}", msg);
    }
}

/// Used to verify that the binary is suitable for this fuzzer. (64-bit, ELF, Little Endian...) 
fn verify_elf_hdr(elf_hdr: elfparser::Header) -> Result<(), String> {                           
    if elf_hdr.magic != ELFMAGIC {                                                              
        return Err("Magic value does not match ELF".to_string());                               
    }                                                                                           
    if elf_hdr.endian != LITTLEENDIAN {                                                         
        return Err("Endian is not Little Endian".to_string());                                  
    }                                                                                           
    if elf_hdr.o_type != TYPEEXEC {                                                             
        return Err("Elf is not an executeable".to_string());                                    
    }                                                                                           
    if elf_hdr.bitsize != ARCH64 {
        return Err("Architecture is not 64-bit".to_string());
    }
    if elf_hdr.machine != RISCV {                                                               
        return Err("Elf is not RISCV architecture".to_string());                                
    }                                                                                           
    Ok(())                                                                                      
}

/// Parse out segments from an elf file and load them into emulator memory space
pub fn load_elf_segments(emu: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    let target = std::fs::read(TARGET).expect("Failed to read target binary from disk");
    let elf = elfparser::ELF::parse_elf(&target);

    if let Err(error) = verify_elf_hdr(elf.header) {
        error_exit(&format!("Process exited with error: {}", error));
    }

    // Loop through all segments and allocate memory for each segment with segment-type=Load
    for phdr in elf.program_headers {
        if phdr.seg_type != elfparser::LOADSEGMENT {
            continue;
        }

        let mut data = target[phdr.offset..phdr.offset.checked_add(phdr.filesz).unwrap()].to_vec();

        // ELF files can contain padding that needs to be loaded into memory but does not exist
        // in the file on disk, we still need to fill it up in memory though
        data.extend_from_slice(&vec![0; phdr.memsz - phdr.filesz]);
        assert_eq!(data.len(), phdr.memsz, "Incorrect memory loading");

        // Unicorn requires 4kb alignment for address and size, so these masks are required
        let aligned_size = (phdr.align - 1 + phdr.memsz) & !(phdr.align - 1);
        let aligned_addr = (phdr.vaddr & !(phdr.align - 1)) as u64;
        assert!((aligned_size + aligned_addr as usize) >= (phdr.vaddr + phdr.memsz), 
                "Aligning to memory bounds required by Unicorn messed up the allocation");

        // Convert elf permission flags to format Unicorn expects
        let perms: Permission = {
            let mut init_perms: Permission = Permission::NONE;
            if phdr.flags & 1 != 0 { init_perms |= Permission::EXEC;  }
            if phdr.flags & 2 != 0 { init_perms |= Permission::WRITE; }
            if phdr.flags & 4 != 0 { init_perms |= Permission::READ;  }
            init_perms
        };

        // Map data stored on disk for this section into emulator memory
        emu.mem_map(aligned_addr, aligned_size, perms).unwrap();

        // Write data for this section into emulator memory
        emu.mem_write(phdr.vaddr as u64, &data)?;
    }

    emu.set_pc(elf.header.entry_addr as u64)?;

    Ok(())
}


