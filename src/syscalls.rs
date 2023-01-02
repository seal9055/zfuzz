use crate::{
    emulator::{Emulator, FileType::{self, STDOUT, STDERR, INVALID}},
    config::FUZZ_INPUT,
    DEBUG, dbg_print,
};

use unicorn_engine::{
    Unicorn,
    RegisterRISCV,
    unicorn_const::uc_error,
};

use std::cell::{RefMut, Ref};

// Helper Structs for syscalls {{{

#[repr(C)]
#[derive(Debug)]
struct Stat {
    st_dev:     u64,
    st_ino:     u64,
    st_mode:    u32,
    st_nlink:   u32,
    st_uid:     u32,
    st_gid:     u32,
    st_rdev:    u64,
    __pad1:     u64,

    st_size:    i64,
    st_blksize: i32,
    __pad2:     i32,

    st_blocks: i64,

    st_atime:     u64,
    st_atimensec: u64,
    st_mtime:     u64,
    st_mtimensec: u64,
    st_ctime:     u64,
    st_ctimensec: u64,

    __glibc_reserved: [i32; 2],
}

// }}}

pub fn exit(_emu: Ref<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Exit syscall hit");
    uc.emu_stop()?;
    Ok(())
}

pub fn fstat(emu: Ref<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Fstat syscall hit");
    let fd       = uc.reg_read(RegisterRISCV::A0)? as usize;
    let statbuf  = uc.reg_read(RegisterRISCV::A1)?;

    // Check if the FD is valid
    let file = emu.fd_list.get(fd);
    if file.is_none() {
        // FD was not valid, return out with an error
        uc.reg_write(RegisterRISCV::A0, !0)?;
        return Ok(());
    }

    // qemu output for the syscall + correct input lengths
    if file.unwrap().ftype == FileType::FUZZINPUT {
        let stat: Stat = Stat {
            st_dev:           0x803,
            st_ino:           0x81889,
            st_mode:          0x81a4,
            st_nlink:         0x1,
            st_uid:           0x3e8,
            st_gid:           0x3e8,
            st_rdev:          0x0,
            __pad1:           0,
            st_size:          emu.fuzz_input.len() as i64,
            st_blksize:       0x1000,
            __pad2:           0,
            st_blocks:        (emu.fuzz_input.len() as i64 + 511) / 512,
            st_atime:         0x5f0fe246,
            st_atimensec:     0,
            st_mtime:         0x5f0fe244,
            st_mtimensec:     0,
            st_ctime:         0x5f0fe244,
            st_ctimensec:     0,
            __glibc_reserved: [0, 0],
        };

        // Cast the stat structure to raw bytes
        let stat = unsafe {
            core::slice::from_raw_parts(
                &stat as *const Stat as *const u8,
                core::mem::size_of_val(&stat))
        };

        // Write in the stat data
        uc.mem_write(statbuf, stat)?;
        uc.reg_write(RegisterRISCV::A0, 0)?;
    } else if file.unwrap().ftype != FileType::OTHER {
        uc.reg_write(RegisterRISCV::A0, !0)?;
    } else {
        unreachable!();
    }

    Ok(())
}

pub fn open(mut emu: RefMut<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Open syscall hit");

    let filename  = uc.reg_read(RegisterRISCV::A0)?;
    let _flags    = uc.reg_read(RegisterRISCV::A1)?;
    let _mode     = uc.reg_read(RegisterRISCV::A2)?;

    let mut buf: Vec<u8> = Vec::new();
    let mut cur = 0;
    // Read filename until nullbyte
    loop {
        let c: u8 = uc.mem_read_as_vec(filename + cur, 1)?[0];
        buf.push(c);
        if c == 0 {
            break;
        }
        cur += 1;
    }

    let fd = if buf == FUZZ_INPUT.get().unwrap().as_bytes() {
        emu.alloc_file(FileType::FUZZINPUT)
    } else {
        emu.alloc_file(FileType::OTHER)
    } as u64;

    uc.reg_write(RegisterRISCV::A0, fd)?;
    Ok(())
}

pub fn read(mut emu: RefMut<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Read syscall hit");

    let fd    = uc.reg_read(RegisterRISCV::A0)? as usize;
    let buf   = uc.reg_read(RegisterRISCV::A1)?;
    let count = uc.reg_read(RegisterRISCV::A2)? as usize;

    // If the file does not exist or has already been closed, return an error
    let file = emu.fd_list.get(fd);
    if file.is_none() || file.unwrap().ftype == FileType::INVALID {
        uc.reg_write(RegisterRISCV::A0, !0)?;
        return Ok(());
    }

    // Special case, reading in the fuzzinput
    if emu.fd_list[fd].ftype == FileType::FUZZINPUT {
        let offset = emu.fd_list[fd].cursor.unwrap();
        let len = core::cmp::min(count, emu.fuzz_input.len()-offset);

        uc.mem_write(buf, &emu.fuzz_input[offset..offset+len])
            .expect("Error occured while trying to read in fuzz-input");

        uc.reg_write(RegisterRISCV::A0, len as u64)?;
        emu.fd_list[fd].cursor = Some(offset + len);
    } else {
        // Read in a different file
        uc.reg_write(RegisterRISCV::A0, count as u64)?;
    }

    Ok(())
}

pub fn write(emu: Ref<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Write syscall hit");

    let fd    = uc.reg_read(RegisterRISCV::A0)? as usize;
    let buf   = uc.reg_read(RegisterRISCV::A1)?;
    let count = uc.reg_read(RegisterRISCV::A2)? as usize;

    // If the file does not exist or has already been closed, return an error
    let file = emu.fd_list.get(fd);
    if file.is_none() || file.as_ref().unwrap().ftype == FileType::INVALID {
        uc.reg_write(RegisterRISCV::A0, !0)?;
        return Ok(());
    }

    // Set to true if you wish to see the actual stdout output of this syscall
    if DEBUG {
        let file = file.unwrap();
        if file.ftype == STDOUT || file.ftype == STDERR {
            let mut read_data = vec![0u8; count];
            uc.mem_read(buf, &mut read_data).unwrap();

            match std::str::from_utf8(&read_data) {
                Ok(v) => print!("{}", v),
                Err(_) => print!("{:?}", read_data),
            }
        } else {
            panic!("Write to unsupported file occured");
        }
    }

    uc.reg_write(RegisterRISCV::A0, count as u64)?;
    Ok(())
}

pub fn brk(uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Brk syscall hit");

    let base = uc.reg_read(RegisterRISCV::A0)?;
    if base == 0 {
        uc.reg_write(RegisterRISCV::A0, 0)?;
        return Ok(());
    }

    panic!("Not supporting brk, consider inserting a hook to a custom malloc implementation");
}

pub fn close(mut emu: RefMut<Emulator>, uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("Close syscall hit");

    let fd = uc.reg_read(RegisterRISCV::A0)? as usize;

    let file = emu.fd_list.get_mut(fd);

    if file.is_none() {
        uc.reg_write(RegisterRISCV::A0, !0)?;
        return Ok(());
    }

    let file = file.unwrap();
    file.ftype = INVALID;

    uc.reg_write(RegisterRISCV::A0, 0)?;
    Ok(())
}
