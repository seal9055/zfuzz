# Design Doc
* Gilbert Hoermann
* 03/01/2023 - 03/02/2023

### Overview

My winter internship at Trail of Bits was mainly focused on writing a coverage-guided graybox
fuzzer based on Qemu/Unicorn. After completing my initial work on the fuzzer I moved on to start
looking at some targets to test it against.

I decided to divide this writeup into 4 parts. In the following introduction, I want to talk
a bit more about my goals with the fuzzer, and then move on to describe some Qemu & Unicorn
internals since that is what I spent most of my first week on. In the second part, I dive deeper
into the internals of the fuzzer and some of the design choices I made to support my goals with
it. In the third part, I showcase how the fuzzer can be harnessed and used against different
targets. Due to time limitations, this portion is not nearly as involved as I would have liked,
but I still believe that it showcases some of the fuzzers strengths. In the final part, I leave
a brief conclusion in which I try to objectively evaluate the fuzzer in its current state and
describe some potential future work I would like to look into concerning this project.

##### Goals with the Fuzzer

The motivation for this project was mainly based on a previous fuzzer I wrote, Sfuzz
(https://github.com/seal9055/sfuzz). For Sfuzz, I wrote a snapshot fuzzer based on a custom RISCV 
binary lifter, IR and JIT. Everything being handrolled allowed me to fully control target 
instrumentation and codegen to be optimized for fuzzing. With this, I was able to design a fuzzer 
that massively outperformed almost all fuzzers I tested it against while providing coverage 
collection, byte-level permissions, CmpCov, and more. Everything being architected from scratch also 
came with some very major drawbacks, however. I only supported RISCV and expanding it to be usable 
against impactful targets would require massive development efforts on the lifting/IR/JIT side. This 
means that all the results I was able to achieve ended in a proof-of-concept fuzzer that worked 
amazingly against simple targets but failed against anything more complex.

When I recently came across Unicorn I had the idea of trying to implement many of Sfuzz’s ideas
on top of Unicorn's CPU-emulation framework. This would allow me to cut out a lot of Qemu’s
complexity and focus on the aspects that made Sfuzz stand out over other fuzzers without having
to worry about manually lifting and JIT compiling.

To summarize, my main goal for this fuzzer is to have a coverage-guided snapshot fuzzer operating
at high performance that can load arbitrary memory dumps and start fuzzing them from any given
memory state. This fuzzer will never be useful in fuzzing complex userspace programs from
their main function or Linux/Windows Kernel images. I do believe that the results showcase the
fuzzer’s potential especially when targeting phones/embedded devices where memory dumps can
be obtained and having access to source code is unrealistic.

##### Qemu

Qemu internals were the first topic I started looking into at the start of the internship, so I
will be starting my writeup on this as well. Even though I never interacted with it directly for the
fuzzer, getting a good understanding of Qemu helped me immensely in properly making use of Unicorn
which is basically an emulator based almost entirely on ripping out parts of Qemu’s codebase.

Qemu is an emulator that supports various types of target/host configurations. It supports
multiple popular architectures and provides full-system emulation, user-mode emulation, and
various virtualization technologies. Full-system emulation is used to emulate entire operating
systems. Qemu-user in comparison can be used to emulate individual binaries that may have been
taken off of some operating system. To achieve these goals, Qemu provides different device/hardware
models that the emulation targets can use to eg. emulate syscalls that aren’t available on
the OS Qemu & the target are running on. Qemu also exposes the KVM virtualization model that
allows the Linux kernel to act as a hypervisor. KVM is an official part of the mainline Linux
kernel. Its strongest feature is that it allows emulation targets to run directly on the host
without requiring explicit emulation/translations assuming that the host and target have the same
architecture. This allows guests to achieve almost native performance instead of incurring the
emulation overhead. This is accomplished by intercepting every impure operation a guest performs
(eg. accessing hardware registers or interrupts) and passing off handling of this to Qemu.

Let’s move on to talk about Qemu's memory model. A lot goes into this, especially when taking
various hardware physical memory models into account that Qemu can support. Here I will mainly focus
on the aspects that are directly relevant to the fuzzer. Guest physical ram is represented using
an acyclic graph of MemoryRegions that contains ram & mmio regions in addition to more specialized
regions to represent eg. memory buses. Additionally, AddressSpace objects are used to describe
a mapping of guest addresses to MemoryRegion objects. This results in memory operations in the
emulated code using AddressSpace to get a translation of an address to a MemoryRegion which then
contains the memory that the guest is trying to operate on. There are a lot of details we could
go into here such as the actual data being backed by RamBlock objects, or that Qemu can overlap
MemoryRegions and assign priority numbers to determine which one should be used when an address
is accessed that is in 2 regions, but I will conclude this section here. If you are curious,
a lot more details on the general Memory Architecture, reference to relevant code sections,
and some APIs that are exposed to interact with it are listed in the notes I took on this.

Finally let’s briefly cover TCG, Qemu’s general-purpose code generator. Qemu has multiple
different “accelerators” that it can use to run the guest code on some host. A lot of these
are platform/architecture-specific such as KVM for Linux, or WHP for Windows, and a lot of these
are generally preferable to TCG due to their improved performance capabilities. TCG is much more
general purpose and pretty much always works, and is the only accelerator Unicorn supports so I
will be focusing on this. Qemu uses TCG as part of its JIT compiler. It takes an intermediate
representation (IR) for some chunk of code as input and transforms that into assembly for
your host architecture. The JIT engine pretty much just starts loading the guest’s code, one
execution block at a time, and checks a translation cache if it has already compiled this block
of code. If it has, it just jumps to the code it compiled for this previously. If it has not,
it lifts the code block into its IR and passes it on to TCG which then generates and pushes the
assembly instructions into the JIT cache. At the IR compilation stage, TCG supports some simple
block-level optimizations but nothing that even comes close to the level of optimization LLVM
performs. Most instructions are generically transformed from IR to host instructions. Some
more specialized instructions that can’t be directly translated are emulated using Qemu's
helper-function-model. For these instructions, an entire helper function is compiled and TCG
inserts a call instruction to that helper function in the generated code. Memory accesses for
example are handled by calls to such helpers. I provide several examples of how both the IR and
final X86-host code look in the notes alongside some full code-traces that I generated using
some simple gdb scripting that Peter Goodman helped me set up.

Qemu by default includes some interesting functionality to snapshot state based on dirtied memory
that might have been interesting, but Unicorn did not adopt this feature so I did not look into
this further.

##### Unicorn

Unicorn is a CPU emulator based on top of Qemu. This means it supports basically the exact same
memory & compilation model as Qemu. Its main difference, which is also what pulled me towards it,
is that it pulled out all of Qemu's complex hardware emulation code and exposes the pure emulator
as a loadable library. This lets us invoke it like this to just run any code we give it.

```
let unicorn = Unicorn::init();
let code = load_code_from_disk();


unicorn.mem_write(load_addr, code);
unicorn.emulate(load_addr);
```

It also provides some simple hooking APIs that we can use to eg. intercept syscalls or memory
operations which makes it really nice to set up & instrument targets for fuzzing. The API it
exposes to users is mostly located here (I made some small modifications to the engine for my
fuzzer so I forked the repo. I will explain these later). For a more in-depth layout of Unicorn,
refer to my notes.

## Fuzzer-Design

In this part of the writeup, I will describe how I designed the fuzzer to achieve my goals and
explain some of the decisions that went into this.

### Memory Management

##### Fuzz-case Resets

Since this project uses Unicorn as the backend, most of the memory management work is offloaded
onto the engine. That being said there are still some additions that make the engine much more
amenable to fuzzing.

First and most importantly, let’s talk about resetting a fuzz-case to start up the next
fuzz-case. Since we are doing emulated fuzzing, we need to take care of resetting up memory
correctly at the start of every fuzz-case on our own. There are some existing fuzzing projects
based on Unicorn, most notably AFL-Unicorn, but these have some negative performance properties
due to being built on top of AFL’s forkserver. This sets up fuzz-cases with a fork()  syscall
using copy-on-write to only copy changed regions of memory.

Unfortunately forks performance properties mean that it will never scale well across cores, and even
for single cases the overhead is significantly higher than the case resetting implemented for Zfuzz.

Zfuzz’s memory resetting is based on dirty-bit tracking. Each page (in this case 4096 bytes)
has a dirty-bit in a giant bitmap assigned to it. Whenever a write to a page occurs, we check
this bitmap to see if it has already been dirtied previously. If not, we set the bit, and append
the address of this page to a vector. During the case-reset, we then just need to traverse the
vector once, and just reset the pages pointed to by this bitmap and the corresponding bitmap
entries. For a lot of fuzzing situations only about 5-25 pages are dirtied, so resetting only
these pages instead of the entire address space is a massive improvement.

Doing this on stock Unicorn would be difficult, so to accomplish this I added an additional
field to Qemu’s MemoryRegion struct to maintain the dirty-bitmap and implemented 2 additional
Unicorn APIs that can test/set this bit for a given address, and one to reset the bitmap at the
end of the fuzz-case.

Other contexts that need to be reset such as CPU-state or fd-listings are simply copied over
into the new state.

##### Virtualized Input Feeding

Many traditional fuzzers feed their inputs to a target through the filesystem. In this fuzzer
nothing ever touches disk apart from saved crashes. Inputs can either be passed through a
userspace-emulated filesystem or by inserting a hook at some location in the target that is in
charge of loading the test-case in some way.

##### Byte-level permission Checks

This is only really feasible for heap allocations since we don't have much bounds-information when
it comes to closed-source binaries and their stack allocations (at least not without doing some
pretty heavy static analysis to eg. determine what memory region is an array and where that would
end resulting in possible overflows). The heap implementation for this however keeps track of the
allocation sizes (assuming the allocators are hooked), and when a memory read/write is done on a
heap region the previous allocation sizes are compared with the write-addresses. If this goes even a
single byte oob the fuzzer will catch it.

### Hooks

These hooks allow us to instrument the target by collecting runtime data, a property that greatly
improves the fuzzer.

* Allocator hooks - These will be a little target-dependent and will require some manual effort
to set up, but allocator hooks are available to catch all instances of UAF/double-free bugs.
* Dirty page tracking hook - This hooks all memory store operations and does the previously
mentioned dirty-bit checking
* Coverage tracking - This hook is called at the start of every block and collects edge-level
coverage information. This information is later used to guide the fuzzer through a target.
* Syscall hooks - While this fuzzer is much more geared towards memory dumps from embedded
devices that don’t rely on system calls, I did implement ~10 syscalls in userspace to assist
in fuzzing. These include file io syscalls (useful to feed input to the fuzzer), and other useful
syscalls such as mmap.

### Shared State / Scaling

Minimizing overhead that comes with running multiple threads was one of my main goals with
this. This fuzzer should be scalable to hundreds of cores and support differentially fuzzing
different targets against each other without ruining performance.

To achieve this there are 2 types of shared state structs in this fuzzer, TargetShared, and
AllShared. The fuzzer supports running multiple different targets at once, this could be used
to eg. fuzz 2 different Json parsers against one another and to compare their outputs to find
non-corruption bugs. With this model, TargetShared state is shared between only the threads that
harness an individual target. AllShared is state that is shared between all threads of all targets.

AllShared by default only includes the corpus under a RwLock. This lock only has to be taken
when one of the targets finds new coverage/wants to add a new input to the corpus, which
with long-running fuzzing campaigns should be extremely rare, thus eliminating most of this
overhead. If one wanted to add differential fuzzing to this fuzzer, a map could be added to
this struct to compare the outputs of different targets. This is not added by default since
it is rather expensive, but there really isn’t a good way to do this cheaply because every
single input→output combination from target-A needs to be compared with the same input→output
combination for target-B. A hashmap that includes a hash of the input and maps to a hash of the
output is not too expensive, but sharing that between threads quickly slows down things by a lot.

TargetShared contains a map to dedup crashes and some coverage-tracking metadata. The crash-map is
behind a RwLock as well and is not of much concern since it is only written to when a new unique
crash is found. For the coverage-map however, I opted to use it in an “unsafe” manner. This
map is accessed hundreds of times during every single fuzz-case so throwing this behind some
form of lock would be terrible for performance. I decided to just give every thread a raw pointer
to this coverage hashmap. Race conditions here will lead to some edges generating coverage more
than once if 2 threads find it at basically the same time, but I don’t think this matters at
all compared to the performance losses a lock/atomic ds would incur.

The final state that needs to be synced between threads is Statistics. I decided not to have
them shared between threads. In my model, the main thread runs in an infinite loop and collects
statistics from the fuzz-threads over a Multi-producer, single-consumer FIFO queue (module
available in Rust’s std: mspc). New entries are entered into the queue every X cases where X
is a configurable that should be set depending on the speed of the target (usually somewhere
between 500-10,000). In my testing, the performance was about the same as with shared state,
but I prefer the code structure I get with this.

### Mutators/Generators

The fuzzer currently supports 2 different fuzz-case generators. One based on mutating inputs and
one that generates new cases from a user-provided grammar. These are designed in a pluggable fashion
though, so mutators can easily be exchanged with different models/target-dependent custom mutators.

The input mutator is about as generic as they come. I pretty much copy-pasted the mutator from
the one I wrote for Sfuzz, so for more information, here is a short description. It is seeded
with a tested/extremely fast prng (Xoroshiro64Star) and performs the following strategies:

* Byte Replacements
* Bitflips
* Magic Numbers
* Simple Arithmetic
* Block Removals
* Block Duplication
* Input Resizes
* Dictionary
* Havoc

The generational mutator is a little more interesting. The one I am currently using unfortunately
only supports generating cases based on a grammar without mutations, but that is something I
intend to change in the future. It is currently using fzero with some slight modifications. This
is a generator written by Brandon Falk based on the Writing Fast Fuzzers paper. During build-time
it takes a grammar file and generates a module similar to the below code snippets. This code is
written specifically for the provided grammar and just generates the fuzz-case by having each
non-terminal call a randomly linked terminal/non-terminal based on the grammar. This is able
to greatly outperform traditional concepts since every step just calls random functions without
having to work with the actual grammar representation anymore. To use this generator, users can
define a grammar-file in the projects Makefile, which will then generate the rust-module and
link it into Zfuzz.

```rs
fn fragment_40(&mut self, depth: usize) {
    if depth >= 16 { return; }
    match self.rand() % 3 {
        0 => self.fragment_49(depth + 1),
        1 => self.fragment_51(depth + 1),
        2 => self.fragment_53(depth + 1),
        _ => unreachable!(),
    }
}
```

I never worked much with grammar-generators in the past so this was quite interesting to me and
I decided to do a short survey of existing mutators and their capabilities. I went through the
papers of the generators listed below and installed all of them to locally evaluate them. Since
they all take different grammar representations, and I had no interest in manually setting up
4 different grammars for complex targets, I evaluated them based on this super simple grammar
I set up for all their expected input-formats.

Fzero was by far the fastest due to its grammar-compilation model and just overall
simplicity. Dharma was by far the slowest, but given that it’s written in python without any
focus on performance, this makes sense (which makes it unfortunate that this is probably the
most popularly used grammar-generator out there). Resmack did not stand out to me in a notable
way. I think it's more of a hobby project, but the author had detailed blogposts on it and it was
very easy to get set up for profiling so I gave it a go. It does not seem like it is currently
able to perform grammar-based mutations but it seems like it's currently a work-in-progress so
this project may eventually become more interesting. Grammatron stood out to me the most. The
project preprocesses the provided grammar into a finite state automaton that de-layers nested
non-terminals to address sampling biases that come with grammars in default CFG form. It also
maintains a tree-based representation of the grammar that unlike the other mutators listed here,
allows it to smartly mutate inputs for coverage-guided fuzzing rather than just generating new
cases. It is also surprisingly well written and achieves a quite impressive performance. I also
briefly looked at Nautilus, but I couldn’t easily get it to build and from the evaluations
made in the Grammatron paper, it seems like it basically supersedes Nautilus anyways.

Grammatron was unfortunately a little bit harder to set up, so including it in Zfuzz would
have been a bigger effort than I currently had time for. In the future I would like to either
integrate Grammatron entirely or write my own variation of it, combining Fzero’s compilation
model with Grammatron’s capabilities.

* Fzero-generational:             371.5906 MiB/s, 6,448,320.6128 iters/s
* Grammatron-mutational:      59.7226 MiB/s,   721,470.7124 iters/s
* Grammatron-generational:   50.8891 MiB/s,   802,460.4788 iters/s
* Resmack-generational:         21.3895 MiB/s,   521,365.4300 iters/s
* Dharma-generational:            0.4342 MiB/s,      6250.6510 iters/s
* Nautilus-generational:    5.075 MiB/s,  154,000 iters/s (Performed on worse hardware, gonna
have to properly repeat eventually)

### Misc

Here I would like to just quickly mention some additional things I worked on for the fuzzer.

* Simple elf loader that can parse/load static elf binaries into the fuzzer
* Gdb-script that can dump entire memory/register/file state from a running process
* Dump-loader that can load these dumps into the fuzzer
* A couple of benchmarks listed here that showcase some advantages/issues with the fuzzer

## Conclusion

Overall I am quite happy with the results of this project and believe that it is a very solid
foundation to build extremely capable fuzzers on top off. There are still a lot of things that
could be improved upon, both performance-wise, and fuzzing-logic wise to generate smarter inputs,
but all of these can be done with some time investment.

The fuzzer will never be as generic as AFL or Libfuzzer, and harder targets will always require
manual effort to harness, but I believe that this fuzzer is in a spot where it can deal with hard
targets that are otherwise hard to harness such as embedded devices, phones, or targets that
can only be run on top of Qemu’s emulation. It overcame Sfuzz’s main disadvantage of only
supporting RISCV/being more of a poc, and is actually usable while providing greatly improved
performance over most other emulation-based fuzzers.

### Moving Forward

* Add better Unicorn-hooking capabilities to directly modify IR similar to how many dbi frameworks
operate. Current hooks have a massive performance overhead which will be the main bottleneck
for any larger target
* CmpCov (I believe this should only be added after fixing the previous Unicorn-hooking 
performance issues since they will otherwise slow the target down too much)
* Grammar generator that supports mutations to enable coverage-guided grammar fuzzing

## Usage
This part is better done in a live demo, but I’ll just list the steps required to harness a
target for the fuzzer here.

- `/src/targets/targets.rs`

This file is used to register your harness. Here you will specify the different target(s) you
wish to run, how many threads should be allocated to each target, and your initialization function.

```rs
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
```

- `/src/lib.rs`

This file has code similar to below listing in it. This is responsible for importing modules into
the fuzzer. If you eg. create a file called target_3.rs to hold your harness in the next step,
add `pub mod target_3;` to the below listing.

```rs
pub mod targets {
    pub mod target_1;
    pub mod target_2;
    pub mod targets;
}
```

- `/src/targets/<insert_name>.rs`

This is where you define your actual harness. A couple of example harnesses are provided in the
project.

The main things that need to be done here are:

* Defining the architecture for the target and calling the Unicorn/state setup functions (these
are also returned at the end of this function)
*  Defining how the input should be loaded into the emulator’s address space (eg. parsing an
elf, loading a memory dump, or anything else that you prefer)
* Mapping in a memory-region that can be used by the target to perform dynamic allocations
* Adding hooks your target requires to run (eg. hooking interrupts to catch syscalls, or hooking
code-regions that you know will cause a crash to redirect fuzz-cases a little, etc)
* Defining a way to load input into your target. This could be a hook at eg. a pc-location after
a read syscall where you just get the value of (at least on x86) rsi at that point and write the
fuzz-input into memory at that address. If you want the target to eg. read the input through
a syscall instead, you can also just set the FUZZ_INPUT configurable. The emulated syscalls
will look out for any read/open/fstat/mmap syscalls that operate on the specified file and
automatically use these to insert the fuzz-case into the target.
* Optional: Define exit conditions. You could just let your target run until it exits after each
fuzz-case, but it will often be more efficient to insert hooks after you are done fuzzing the
interesting code to early-terminate the fuzz-cases
