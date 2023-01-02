use crate::{
    emulator::Emulator,
    syscalls, dbg_print
};
use unicorn_engine::{
    Unicorn, RegisterRISCV,
    unicorn_const::{uc_error, Permission},
};

use std::rc::Rc;
use std::cell::RefCell;

pub fn insert_syscall_hook(emu: &Rc<RefCell<Emulator>>, uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {
    let emu_clone = Rc::clone(emu);
    let callback = move |uc: &mut Unicorn<'_, ()>, interrupt_num: u32| {
        match interrupt_num {
            8 => { /* SYSCALL */
                match uc.reg_read(RegisterRISCV::A7).unwrap() {
                    57 => {
                        syscalls::close(emu_clone.borrow_mut(), uc).unwrap();
                    },
                    63 => {
                        syscalls::read(emu_clone.borrow_mut(), uc).unwrap();
                    },
                    64 => {
                        syscalls::write(emu_clone.borrow(), uc).unwrap();
                    },
                    80 => {
                        syscalls::fstat(emu_clone.borrow(), uc).unwrap();
                    },
                    93 => {
                        syscalls::exit(emu_clone.borrow(), uc).unwrap();
                    },
                    214 => {
                        syscalls::brk(uc).unwrap();
                    },
                    1024 => {
                        syscalls::open(emu_clone.borrow_mut(), uc).unwrap();
                    },
                    _ => {
                        panic!("Unimplemented syscall: {} at pc: 0x{:X}", 
                               uc.reg_read(RegisterRISCV::A7).unwrap(),
                               uc.pc_read().unwrap()
                               ); 
                    }
                }
            },
            _ => panic!("Unsupported interrupt number: {} @ 0x{:X}", 
                        interrupt_num, uc.pc_read().unwrap()),
        }
    };

    uc.add_intr_hook(callback)?;

    Ok(())
}

/// Hook that makes use of zfuzz's mmu to perform a memory safe malloc operation
pub fn insert_malloc_hook(emu: &Rc<RefCell<Emulator>>, uc: &mut Unicorn<'_, ()>, malloc_addr: u64) 
        -> Result<(), uc_error> {

    let emu_clone = Rc::clone(emu);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("Malloc hook hit");
        let alloc_size = uc.reg_read(RegisterRISCV::A1).unwrap() as usize;

        if let Some(addr) = emu_clone
            .borrow_mut()
            .allocate(uc, alloc_size, Permission::READ | Permission::WRITE) {
                uc.reg_write(RegisterRISCV::A0, addr as u64).unwrap();
                uc.set_pc(uc.reg_read(RegisterRISCV::RA).unwrap()).unwrap();
        } else {
            panic!("OOM: Allocation failed");
        }
    };

    uc.add_code_hook(malloc_addr, malloc_addr, callback)?;

    Ok(())
}

/// Hook that makes use of zfuzz's mmu to perform a memory safe free operation
pub fn insert_free_hook(emu: &Rc<RefCell<Emulator>>, uc: &mut Unicorn<'_, ()>, free_addr: u64) 
        -> Result<(), uc_error> {
    let emu_clone = Rc::clone(emu);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        dbg_print("Free hook hit");

        let ptr = uc.reg_read(RegisterRISCV::A1).unwrap();

        emu_clone.borrow_mut().free(uc, ptr as usize).unwrap();
        uc.set_pc(uc.reg_read(RegisterRISCV::RA).unwrap()).unwrap();
    };

    uc.add_code_hook(free_addr, free_addr, callback)?;

    Ok(())
}

pub fn insert_debug_hooks(_emu: &Rc<RefCell<Emulator>>, _uc: &mut Unicorn<'_, ()>) 
        -> Result<(), uc_error> {
    Ok(())
}
