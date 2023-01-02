use zfuzz::{
    emulator::Emulator,
    hooks::{insert_debug_hooks, insert_syscall_hook, insert_malloc_hook, insert_free_hook},
    config::{handle_cli, Cli},
    error_exit, load_elf_segments, VMMAP_ALLOCATION_SIZE, FIRSTALLOCATION, DEBUG, dbg_print,
};
use byteorder::{LittleEndian, WriteBytesExt};
use unicorn_engine::{
    Unicorn,
    RegisterRISCV,
    unicorn_const::{Permission, uc_error, Arch, Mode},
};
use clap::Parser;

use std::rc::Rc;
use std::cell::RefCell;

pub fn emulate(_emu: &Rc<RefCell<Emulator>>, uc: &mut Unicorn<'_, ()>) -> Result<(),uc_error> {
    let start_addr = uc.pc_read()?;
    uc.emu_start(start_addr, 0, 0, 0)?;
    Ok(())
}

fn main() -> Result<(), uc_error> {
    // Create emulator that will hold system context such as open files, dirty pages, etc
    let emu: Rc<RefCell<Emulator>> = Rc::new(RefCell::new(Emulator::new()));

    // Create unicorn cpu emulator
    let mut unicorn = unicorn_engine::Unicorn::new(Arch::RISCV, Mode::RISCV64)?;

    
    // Parse commandline-args and set config variables based on them
    let mut args = Cli::parse();
    handle_cli(&mut args);

    load_elf_segments(&mut unicorn).unwrap_or_else(|err| {
        let error_string = format!("{:#?}", err);
        error_exit(&format!("Unrecoverable error while loading elf segments: {}", error_string));
    });

    // Allocate memory map for emulator. This backing will be used to allocate the initial stack 
    // and handle later heap allocations during program execution
    unicorn.mem_map(FIRSTALLOCATION as u64, VMMAP_ALLOCATION_SIZE, Permission::NONE).unwrap();

    // Allocate stack and populate argc, argv & envp
    {
        let stack = emu.borrow_mut()
            .allocate(&mut unicorn, 1024 * 1024, Permission::READ | Permission::WRITE)
            .expect("Error allocating stack");
        unicorn.reg_write(RegisterRISCV::SP, (stack + (1024 * 1024)) as u64)?;

        let argv: Vec<usize> = Vec::new();

        // Macro to push 64-bit integers onto the stack
        macro_rules! push {
            ($expr:expr) => {
                let sp = unicorn.reg_read(RegisterRISCV::SP)? - 8;
                let mut wtr = vec![];
                wtr.write_u64::<LittleEndian>($expr as u64).unwrap();
                unicorn.mem_write(sp, &wtr)?;
                unicorn.reg_write(RegisterRISCV::SP, sp)?;
            }
        }

        // Setup argc, argv & envp
        push!(0u64);            // Auxp
        push!(0u64);            // Envp
        push!(0u64);            // Null-terminate Argv
        for arg in argv.iter().rev() {
            push!(*arg);
        }
        push!(argv.len());      // Argc
    }

    insert_syscall_hook(&emu, &mut unicorn)?;

    insert_malloc_hook(&emu, &mut unicorn, 0x11088)?;
    insert_free_hook(&emu, &mut unicorn, 0x12ab0)?;

    if DEBUG {
        insert_debug_hooks(&emu, &mut unicorn)?;
    }

    emulate(&emu, &mut unicorn)?;

    dbg_print("Reached end of main");

    Ok(())
}
