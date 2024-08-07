use crate::{
    execution_state::ExecEnv,
    syscalls, dbg_print, TargetShared,
    configurables::{COVMAP_SIZE, EMIT_COV, LIBC_VERSION, LibcOpt},
};

use unicorn_engine::{
    Unicorn, RegisterRISCV, RegisterX86, InsnSysX86,
    unicorn_const::{uc_error, Permission, HookType, MemType, IsDirty, Arch, Mode},
};

use std::rc::Rc;
use std::sync::Arc;
use std::cell::RefCell;
use std::io::prelude::*;
use std::fs::OpenOptions;

/// Hook that makes use of zfuzz's mmu to perform a memory safe malloc_r operation
/// TODO: Needs updates
pub fn insert_malloc_r_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, 
            malloc_addr: u64) -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("malloc_rhook hit");
        // I usually insert this hook at the location of `malloc_r` which takes size in arg1 vs
        // `malloc`'s arg0. Change this depending on what you are hooking
        let alloc_size_reg = uc.syscall_arg1_reg().unwrap();
        let return_reg     = uc.syscall_return_reg().unwrap();
        let _link_register  = uc.link_register().unwrap();
        let alloc_size: usize = uc.reg_read(alloc_size_reg).unwrap() as usize;

        let mut exec_env_mut = exec_env_clone.borrow_mut();
        match exec_env_mut.allocate(uc, alloc_size, Permission::READ | Permission::WRITE) {
            Ok(addr) => {
                uc.reg_write(return_reg, addr).unwrap();
                uc.simulate_return().unwrap();
            },
            Err(e) => exec_env_mut.error_exit(uc, e),
        }
    };

    uc.add_code_hook(malloc_addr, malloc_addr, callback)?;

    Ok(())
}

/// Hook that makes use of zfuzz's mmu to perform a memory safe malloc operation
pub fn insert_malloc_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, 
            malloc_addr: u64) -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("Malloc hook hit");

        let return_reg = uc.syscall_return_reg().unwrap();
        let mut alloc_size = uc.function_arg0_val().unwrap() as usize;

        // Align size differently depending on libc in use
        if LIBC_VERSION == LibcOpt::LibUc {
            // Simulating size alignment that uc-libc performs in the target in an attempt to 
            // accurately model heap allocations
            //
            // Add 0x8 for size field
            // Then add (0x8-1) to make sure we have at least (size + header_size) bytes
            // Finally mask to 8-byte align and allocate
            alloc_size = (alloc_size + 0x8 + (0x8 - 1)) & !(0x8-1);
        }

        let mut binding = exec_env_clone.borrow_mut();

        // Insert guard page prior to the allocation
        binding.allocate(uc, 0x1000, Permission::NONE).unwrap();

        match binding.allocate(uc, alloc_size, Permission::READ | Permission::WRITE) {
            Ok(addr) => {
                uc.reg_write(return_reg, addr).unwrap();
                uc.simulate_return().unwrap();
            },
            Err(err) => {
                binding.error_exit(uc, err);
            }
        };
    };

    uc.add_code_hook(malloc_addr, malloc_addr, callback)?;

    Ok(())
}

/// Hook that makes use of zfuzz's mmu to perform a memory safe free operation
pub fn insert_free_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, free_addr: u64) 
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("free hook hit");

        let mut binding = exec_env_clone.borrow_mut();
        let free_ptr = uc.function_arg0_val().unwrap();
        if let Err(e) = binding.free(uc, free_ptr) {
           binding.error_exit(uc, e);
        }

        uc.simulate_return().unwrap();
    };

    uc.add_code_hook(free_addr, free_addr, callback)?;
    Ok(())
}


/// Hook that makes use of zfuzz's mmu to perform a memory safe realloc operation
pub fn insert_realloc_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, 
            malloc_addr: u64) -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("Realloc hook hit");

        let return_reg = uc.syscall_return_reg().unwrap();
        let orig_ptr   = uc.function_arg0_val().unwrap() as usize;
        let mut alloc_size = uc.function_arg1_val().unwrap() as usize;

        // Align size differently depending on libc in use
        if LIBC_VERSION == LibcOpt::LibUc {
            // Simulating size alignment that uc-libc performs in the target in an attempt to 
            // accurately model heap allocations
            //
            // Add 0x8 for size field
            // Then add (0x8-1) to make sure we have at least (size + header_size) bytes
            // Finally mask to 8-byte align and allocate
            alloc_size = (alloc_size + 0x8 + (0x8 - 1)) & !(0x8-1);
        }

        let mut binding = exec_env_clone.borrow_mut();
        if let Err(e) = binding.free(uc, orig_ptr as u64) {
            binding.error_exit(uc, e);
        }

        // Insert guard page prior to the allocation
        binding.allocate(uc, 0x1000, Permission::NONE).unwrap();

        match binding.allocate(uc, alloc_size, Permission::READ | Permission::WRITE) {
            Ok(addr) => {
                uc.reg_write(return_reg, addr).unwrap();
                uc.simulate_return().unwrap();
            },
            Err(e) => binding.error_exit(uc, e),
        }
    };

    uc.add_code_hook(malloc_addr, malloc_addr, callback)?;

    Ok(())
}

/// Hook that makes use of zfuzz's mmu to perform a memory safe free operation
/// TODO: Needs updates
pub fn insert_free_r_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, free_addr: u64) 
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("free_r hook hit");

        // I usually insert this hook at the location of `free_r` which takes the free-ptr in arg1 
        // vs `free`'s arg0. Change this depending on what you are hooking
        let free_ptr_reg    = uc.syscall_arg1_reg().unwrap();
        let link_register   = uc.link_register().unwrap();
        let free_ptr: u64   = uc.reg_read(free_ptr_reg).unwrap();

        exec_env_clone.borrow_mut().free(uc, free_ptr).unwrap();
        uc.set_pc(uc.reg_read(link_register).unwrap()).unwrap();
    };

    uc.add_code_hook(free_addr, free_addr, callback)?;

    Ok(())
}

/// Inserts a hook that is in charge of bounds-checking memory-operations
/// This hook needs to be inserted before the dirty-bit-tracking hook so it doesn't potentially go 
/// out of bounds when processing invalid address.
pub fn insert_ld_st_boundcheck_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>)
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, mem_type: MemType, address: u64, 
        size: usize, _value: i64| -> bool {
            let real_size = uc.real_size(address) as u64;
            let end = address + size as u64;

            // Check if this memory-access is within a valid memory region
            for mem_region in uc.mem_regions().unwrap() {
                if address >= mem_region.begin && end <= (mem_region.end + 1) {
                    if address <= mem_region.begin + real_size {
                        return true;
                    }
                }
            }

            // If we haven't returned yet, this operation was not valid, so set appropriate error
            // flag
            exec_env_clone.borrow_mut().error_flag = match mem_type {
                MemType::READ           => uc_error::READ_UNMAPPED,
                MemType::WRITE          => uc_error::WRITE_UNMAPPED,
                MemType::FETCH          => uc_error::FETCH_UNMAPPED,
                MemType::READ_UNMAPPED  => uc_error::READ_UNMAPPED,
                MemType::WRITE_UNMAPPED => uc_error::WRITE_UNMAPPED,
                MemType::WRITE_PROT     => uc_error::WRITE_PROT,
                MemType::READ_PROT      => uc_error::READ_PROT,
                MemType::FETCH_PROT     => uc_error::FETCH_PROT,
                MemType::READ_AFTER     => uc_error::READ_UNMAPPED,
                _ => unreachable!(),
            };

            // Stop the emulation after the error is set
            uc.emu_stop().unwrap();

            true
    };

    uc.add_mem_hook(HookType::MEM_WRITE | HookType::MEM_READ, 0, std::u64::MAX, callback)?;
    Ok(())
}

/// Inserts hook that tracks dirtied memory on memory writes
pub fn insert_dirty_page_tracking_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>)
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _mem_type: MemType, address: u64, 
        _size: usize, _value: i64| -> bool {

            let mut local_emu = exec_env_clone.borrow_mut();

            let is_dirty = uc.test_and_set_dirty(address);
            match is_dirty {
                IsDirty::DIRTY => {},
                IsDirty::NDIRTY => {
                    local_emu.dirty.push(address as usize);
                },
                IsDirty::INVALID => {
                    // Invalid address that does not fit into any of the mappings.
                    // The `ld_st_boundcheck_hook` should have caught this error
                    unreachable!();
                },
            }
            true
    };

    uc.add_mem_hook(HookType::MEM_WRITE, 0, std::u64::MAX, callback)?;
    Ok(())
}

/// Inserts a hook to track edge coverage
pub fn insert_coverage_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>, 
        shared_data: &Arc<TargetShared>) -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let shared_data_clone = Arc::clone(shared_data);

    let mut f = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("cov.txt")
        .unwrap();

    let callback = move |_uc: &mut Unicorn<'_, ()>, address: u64, _size: u32| {
        let cur_location = (address >> 4) ^ (address << 8);
        let hash = (cur_location ^ exec_env_clone.borrow().prev_block) % COVMAP_SIZE;

        // This breaks rust thread-safety for the coverage map. The alternative would be to wrap 
        // this in locks, but we would like to avoid wrapping frequently accessed ds's like 
        // coverage-maps in locks since that would greatly impact performance.
        //
        // The result of races might be that an input might think that it found new coverage even 
        // though it did not. This is an acceptable result for massive performance gains.
        unsafe {
            // Coverage uses same hashing algorithm as afl
            // See: https://lcamtuf.coredump.cx/afl/technical_details.txt
            let cov_ptr = shared_data_clone.coverage_bytemap.as_ptr() as u64;
            let bytemap_entry: *mut u8 = (cov_ptr + hash) as *mut u8;
            if *bytemap_entry == 0 {
                if EMIT_COV {
                    f.write_all(format!("{:#X?}\n", address).as_bytes()).unwrap();
                }

                // Set the entry in the thread-shared bytemap to mark this edge as taken
                *bytemap_entry = 1;

                // Indicate that this case found new coverage
                exec_env_clone.borrow_mut().cov_count += 1;
            }
        }
        exec_env_clone.borrow_mut().prev_block = cur_location >> 1;
    };

    uc.add_block_hook(callback)?;
    Ok(())
}

/// Insert super expensive hook that traces every single executed pc into a `pc_trace.txt` file.
pub fn insert_pc_trace_hook(uc: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        let mut f = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open("pc_trace.txt")
            .unwrap();
        f.write_all(format!("pc = {:#0x?} ; eax = {:#0x?} ; esi = {:#0x?} ; edx = {:#0x?}\n", 
                                uc.get_pc().unwrap(), 
                                uc.reg_read(RegisterX86::EAX).unwrap(),
                                uc.reg_read(RegisterX86::ESI).unwrap(),
                                uc.reg_read(RegisterX86::EDX).unwrap(),
                            ).as_bytes()).unwrap();
    };

    uc.add_code_hook(0x0, 0xffffffffffffffff, callback).unwrap();
    Ok(())
}

/// Insert syscall hooks for a target that is compiled for linux' ABI.
pub fn insert_linux_syscall_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {

    match uc.get_arch() {
        Arch::RISCV => insert_linux_riscv_syscall_hook(exec_env, uc)?,
        Arch::X86   => {
            match uc.get_mode() {
                Mode::MODE_32 => insert_linux_x86_32_syscall_hook(exec_env, uc)?,
                Mode::MODE_64 => insert_linux_x86_64_syscall_hook(exec_env, uc)?,
                _ => unreachable!(),
            }
        }
        _ => panic!("Syscall-mappings for architecture: {:#?} do not exist", uc.get_arch()),
    };
    Ok(())
}

/// Maps RISCV64 syscall numbers
pub fn insert_linux_riscv_syscall_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, interrupt_num: u32| {
        match interrupt_num {
            8 => { /* Interrupt number 8 indicates a SYSCALL on RISCV*/
                let ret = match uc.reg_read(RegisterRISCV::A7).unwrap() {
                    50   => syscalls::openat(exec_env_clone.borrow_mut(), uc),
                    57   => syscalls::close(exec_env_clone.borrow_mut(), uc),
                    63   => syscalls::read(exec_env_clone.borrow_mut(), uc),
                    64   => syscalls::write(exec_env_clone.borrow(), uc),
                    79   => syscalls::fstatat(exec_env_clone.borrow_mut(), uc),
                    80   => syscalls::fstat(exec_env_clone.borrow_mut(), uc),
                    93   => syscalls::exit(exec_env_clone.borrow_mut(), uc),
                    94   => syscalls::exit_group(exec_env_clone.borrow_mut(), uc),
                    174  => syscalls::getuid(uc),
                    175  => syscalls::geteuid(uc),
                    214  => syscalls::brk(uc),
                    222  => syscalls::mmap(exec_env_clone.borrow_mut(), uc),
                    1024 => syscalls::open(exec_env_clone.borrow_mut(), uc),
                    1033 => syscalls::access(uc),
                    _    => {
                        panic!("Unimplemented syscall: {} at pc: 0x{:X}",
                               uc.reg_read(RegisterRISCV::A7).unwrap(),
                               uc.get_pc().unwrap()
                               ); 
                    }
                };
                // Check if an error occured during a syscall, and if so set the error flag in the 
                // emulator and stop the emulation
                if let Err(err) = ret {
                    exec_env_clone.borrow_mut().error_flag = err;

                    // Stop the emulation after the error is set
                    uc.emu_stop().unwrap();
                }

            },
            _ => panic!("Unsupported interrupt number: {} @ 0x{:X}", 
                        interrupt_num, uc.get_pc().unwrap()),
        }
    };
    uc.add_intr_hook(callback)?;
    Ok(())
}

/// Maps X86-64 syscall numbers
pub fn insert_linux_x86_64_syscall_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {

    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>| {
        let ret = match uc.reg_read(RegisterX86::RAX).unwrap() {
            0   => syscalls::read(exec_env_clone.borrow_mut(), uc),
            1   => syscalls::write(exec_env_clone.borrow(), uc),
            2   => syscalls::open(exec_env_clone.borrow_mut(), uc),
            3   => syscalls::close(exec_env_clone.borrow_mut(), uc),
            5   => syscalls::fstat(exec_env_clone.borrow_mut(), uc),
            9   => syscalls::mmap(exec_env_clone.borrow_mut(), uc),
            12  => syscalls::brk(uc),
            21  => syscalls::access(uc),
            60  => syscalls::exit(exec_env_clone.borrow_mut(), uc),
            102 => syscalls::getuid(uc),
            107 => syscalls::geteuid(uc),
            158 => syscalls::arch_prctl(uc),
            231 => syscalls::exit_group(exec_env_clone.borrow_mut(), uc),
            257 => syscalls::openat(exec_env_clone.borrow_mut(), uc),
            262 => syscalls::fstatat(exec_env_clone.borrow_mut(), uc),
            318 => syscalls::getrandom(exec_env_clone.borrow_mut(), uc),
            _   => {
                panic!("Unimplemented syscall: {} at pc: 0x{:X}",
                       uc.reg_read(RegisterX86::RAX).unwrap(),
                       uc.get_pc().unwrap()
                       ); 
            }
        };

        // Check if an error occured during a syscall, and if so set the error flag in the 
        // emulator and stop the emulation
        if let Err(err) = ret {
            exec_env_clone.borrow_mut().error_flag = err;

            // Stop the emulation after the error is set
            uc.emu_stop().unwrap();
        }
    };

    uc.add_insn_sys_hook(InsnSysX86::SYSCALL, 0, std::u64::MAX, callback)?;
    Ok(())
}

/// Maps X86-32 syscall numbers
pub fn insert_linux_x86_32_syscall_hook(exec_env: &Rc<RefCell<ExecEnv>>, uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {

    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, int_num: u32| {
        if int_num != 0x80 {
            panic!("INT_{int_num} called, only supporting INT_80");
        }

        let ret = match uc.reg_read(RegisterX86::EAX).unwrap() {
            1   => syscalls::exit(exec_env_clone.borrow_mut(), uc),
            3   => syscalls::read(exec_env_clone.borrow_mut(), uc),
            4   => syscalls::write(exec_env_clone.borrow(), uc),
            5   => syscalls::open(exec_env_clone.borrow_mut(), uc),
            6   => syscalls::close(exec_env_clone.borrow_mut(), uc),
            24  => syscalls::getuid(uc),
            43  => syscalls::times(uc),
            45  => syscalls::brk(uc),
            49  => syscalls::geteuid(uc),
            90  => syscalls::mmap(exec_env_clone.borrow_mut(), uc),
            108 => syscalls::fstat(exec_env_clone.borrow_mut(), uc),
            252 => syscalls::exit_group(exec_env_clone.borrow_mut(), uc),
            295 => syscalls::openat(exec_env_clone.borrow_mut(), uc),
            355 => syscalls::getrandom(exec_env_clone.borrow_mut(), uc),
            _   => {
                panic!("Unimplemented syscall: {} at pc: 0x{:X}",
                       uc.reg_read(RegisterX86::EAX).unwrap(),
                       uc.get_pc().unwrap()
                       ); 
            }
        };

        // Check if an error occured during a syscall, and if so set the error flag in the 
        // emulator and stop the emulation
        if let Err(err) = ret {
            exec_env_clone.borrow_mut().error_flag = err;

            // Stop the emulation after the error is set
            uc.emu_stop().unwrap();
        }
    };

    uc.add_intr_hook(callback)?;
    Ok(())
}
