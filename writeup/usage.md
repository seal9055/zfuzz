This part is better done in a live demo, but I’ll just list the steps required to harness a target for the fuzzer here.

/src/targets/targets.rs 

This file is used to register your harness. Here you will specify the different target(s) you wish to run, how many threads should be allocated to each target, and your initialization function.

pub const TARGETS: [HarnessInit; NUM_TARGETS] = [
    HarnessInit {
        target_id: TargetId::TargetOne as usize,
        num_threads: 12,
        instr_timeout: 0,
        time_timeout: 0,
    },
    HarnessInit {
        target_id: TargetId::TargetThree as usize,
        num_threads: 6,
        instr_timeout: 0,
        time_timeout: 0,
    },
];

/src/lib.rs 

This file has code similar to below listing in it. This is responsible for importing modules into the fuzzer. If you eg. create a file called target_3.rs to hold your harness in the next step, add pub mod target_3 to the below listing.

pub mod targets {
    pub mod target_1;
    pub mod targets;
}

/src/targets/<insert_name>.rs 

This is where you define your actual harness. A couple of example harnesses are shown in the project. 

The main things that need to be done here are:

* Defining the architecture for the target and calling the Unicorn/state setup functions (these are also returned at the end of this function)
*  Defining how the input should be loaded into the emulator’s address space (eg. parsing an elf, loading a memory dump, or anything else that you prefer)
* Mapping in a memory-region that can be used by the target to perform dynamic allocations
* Adding hooks your target requires to run (eg. hooking interrupts to catch syscalls, or hooking code-regions that you know will cause a crash to redirect fuzz-cases a little, etc)
* Defining a way to load input into your target. This could be a hook at eg. a pc-location after a read syscall where you just get the value of (at least on x86) rsi at that point and write the fuzz-input into memory at that address. If you want the target to eg. read the input through a syscall instead, you can also just set the FUZZ_INPUT configurable. The emulated syscalls will look out for any read/open/fstat/mmap syscalls that operate on the specified file and automatically use these to insert the fuzz-case into the target.
* Optional: Define exit conditions. You could just let your target run until it exits after each fuzz-case, but it will often be more efficient to insert hooks after you are done fuzzing the interesting code to early-terminate the fuzz-cases

MISC

Not related to fuzzer, but I briefly worked on 3 other targets during the internship listed here

* FFmpeg
  * I Briefly looked at this when I was trying to decide on a target to fuzz but decided against it because of SIMD issues. Found some double-free bugs in the example-programs they list in their docs. Was curious if any real projects used the documentation as a reference and added these bugs into their codebases, but found no instances of it (Although 2 forks of popular projects did have this vulnerability: mgba & qTox).
* CVE-2022-4262 - V8 bug listed in Project-Ideas 
  * I spent about 2 days on this trying to poc the bug, but I was unfortunately not successful
  * I started by finding the immediate pre/post patch versions of the bug, and locally built asan+debug symbol builds of both of these
  * The bug is related to the code that is in charge of determining how many heap-variable should be allocated for a given block-scope. Issues apparently arise when eval calls running in non-strict-mode code define additional variables that aren’t properly passed on to the scope manager. The below code was added to fix the bug. I was able to trigger this added fix and was able to get  scope->num_heap_slots_ != Context::MIN_CONTEXT_EXTENDED_SLOTS; which would presumably cause some form of bug according to the fix, but I was not able to spot anything being corrupted or trigger an asan crash. 
  * The bug-report included no information apart from the actual patch, and no poc was provided which in addition to this being a bug in a very complicated part of the engine, made this bug hard to work with.
* Android
  * After failing to harness some projects I pulled off of Github for my fuzzer due to the SIMD issues I decided it may be better to attempt to run my fuzzer against a target it is actually intended for. I don’t have any embedded devices lying around that I have enough prior work on to quickly get a memory dump, but I did have an old android tablet I ordered from wish for $20 a while ago. 

  image.png

Sure enough, security was basically non-existent and I was pretty much able to get an immediate root-shell on the device by hooking up ADB. I had never previously worked with Android devices before, so I ended up spending a lot of time on something that didn’t end up working out.

After getting a toolchain setup I wrote this code to dump physical ram from /dev/mem and register-state from the device. The device did not have enough available memory to read/write the entire ram-mappings in one go, but I was able to get them out in several stages. I also dumped /proc/kallsyms and the individual kernel code/data sections so that I could load the kernel-image into Binary Ninja and get symbols (Wrote some short binja-scripts for this). This worked out nicely and allowed me to look at the implementations for some of their drivers. My goal was to use this to choose a driver to fuzz.

So far so good. At this point, the last required step was to parse out virtual memory mappings from the /dev/mem file. The best idea I had for this was to parse out the device’s page-tables from the pmem dump. Android page tables can be found using the ttbr0 register, this however is a privileged register that I can’t read from userspace even if I’m running under the root user. Since this is also a very off-brand/weird device I did not have much hope to get a kernel-dev environment setup for it. 

The hacky solution that I ended up coming up with was to pull an existing kernel module off of the device and patch it to do my bidding and dump the relevant registers. This worked and I was able to get the relevant registers.

image.png

image.png

This is where the issue comes in, and my unfamiliarity with android/arm comes to show. As it turns out, the register is changed on every single context switch, so this was completely useless.

I have some ideas on how I can still get this dump moving forward, but all of these involve more work than what I would have had time for during the last 2 days of the internship while working on this writeup.
