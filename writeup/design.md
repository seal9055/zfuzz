In this part of the writeup, I will describe how I designed the fuzzer to achieve my goals and explain some of the decisions that went into this.

Memory Management

Fuzz-case Resets

Since this project uses Unicorn as the backend, most of the memory management work is offloaded onto the engine. That being said there are still some additions that make the engine much more amenable to fuzzing.

First and most importantly, let’s talk about resetting a fuzz-case to start up the next fuzz-case. Since we are doing emulated fuzzing, we need to take care of resetting up memory correctly at the start of every fuzz-case on our own. There are some existing fuzzing projects based on Unicorn, most notably AFL-Unicorn, but these have some negative performance properties due to being built on top of AFL’s forkserver. This sets up fuzz-cases with a fork()  syscall using copy-on-write to only copy changed regions of memory.

Unfortunately forks performance properties mean that it will never scale well across cores, and even for single cases the overhead is significantly higher than the case resetting implemented for Zfuzz. 

Zfuzz’s memory resetting is based on dirty-bit tracking. Each page (in this case 4096 bytes) has a dirty-bit in a giant bitmap assigned to it. Whenever a write to a page occurs, we check this bitmap to see if it has already been dirtied previously. If not, we set the bit, and append the address of this page to a vector. During the case-reset, we then just need to traverse the vector once, and just reset the pages pointed to by this bitmap and the corresponding bitmap entries. For a lot of fuzzing situations only about 5-25 pages are dirtied, so resetting only these pages instead of the entire address space is a massive improvement.

Doing this on stock Unicorn would be difficult, so to accomplish this I added an additional field to Qemu’s MemoryRegion struct to maintain the dirty-bitmap and implemented 2 additional Unicorn APIs that can test/set this bit for a given address, and one to reset the bitmap at the end of the fuzz-case. 

Other contexts that need to be reset such as CPU-state or fd-listings are simply copied over into the new state.

Virtualized Input Feeding

Many traditional fuzzers feed their inputs to a target through the filesystem. In this fuzzer nothing ever touches disk apart from saved crashes. Inputs can either be passed through a userspace-emulated filesystem or by inserting a hook at some location in the target that is in charge of loading the test-case in some way.

Byte-level permission Checks

TODO - I worked on an implementation for this a little bit, but my implementation was poor so I will need to redo that at some point. Basic idea is to keep a permission byte for every single byte of memory the target uses. This means we can catch minimal heap bugs that might eg. only go 1-byte oob.

Hooks

These hooks allow us to instrument the target by collecting runtime data, a property that greatly improves the fuzzer. 

* Allocator hooks - These will be a little target-dependent and will require some manual effort to set up, but allocator hooks are available to catch all instances of UAF/double-free bugs.
* Dirty page tracking hook - This hooks all memory store operations and does the previously mentioned dirty-bit checking
* Coverage tracking - This hook is called at the start of every block and collects edge-level coverage information. This information is later used to guide the fuzzer through a target.
* Syscall hooks - While this fuzzer is much more geared towards memory dumps from embedded devices that don’t rely on system calls, I did implement ~10 syscalls in userspace to assist in fuzzing. These include file io syscalls (useful to feed input to the fuzzer), and other useful syscalls such as mmap.

Shared State / Scaling

Minimizing overhead that comes with running multiple threads was one of my main goals with this. This fuzzer should be scalable to hundreds of cores and support differentially fuzzing different targets against each other without ruining performance.

To achieve this there are 2 types of shared state structs in this fuzzer, TargetShared, and AllShared. The fuzzer supports running multiple different targets at once, this could be used to eg. fuzz 2 different Json parsers against one another and to compare their outputs to find non-corruption bugs. With this model, TargetShared state is shared between only the threads that harness an individual target. AllShared is state that is shared between all threads of all targets. 

AllShared by default only includes the corpus under a RwLock. This lock only has to be taken when one of the targets finds new coverage/wants to add a new input to the corpus, which with long-running fuzzing campaigns should be extremely rare, thus eliminating most of this overhead. If one wanted to add differential fuzzing to this fuzzer, a map could be added to this struct to compare the outputs of different targets. This is not added by default since it is rather expensive, but there really isn’t a good way to do this cheaply because every single input→output combination from target-A needs to be compared with the same input→output combination for target-B. A hashmap that includes a hash of the input and maps to a hash of the output is not too expensive, but sharing that between threads quickly slows down things by a lot.

TargetShared contains a map to dedup crashes and some coverage-tracking metadata. The crash-map is behind a RwLock as well and is not of much concern since it is only written to when a new unique crash is found. For the coverage-map however, I opted to use it in an “unsafe” manner. This map is accessed hundreds of times during every single fuzz-case so throwing this behind some form of lock would be terrible for performance. I decided to just give every thread a raw pointer to this coverage hashmap. Race conditions here will lead to some edges generating coverage more than once if 2 threads find it at basically the same time, but I don’t think this matters at all compared to the performance losses a lock/atomic ds would incur.

The final state that needs to be synced between threads is Statistics. I decided not to have them shared between threads. In my model, the main thread runs in an infinite loop and collects statistics from the fuzz-threads over a Multi-producer, single-consumer FIFO queue (module available in Rust’s std: mspc). New entries are entered into the queue every X cases where X is a configurable that should be set depending on the speed of the target (usually somewhere between 500-10,000). In my testing, the performance was about the same as with shared state, but I prefer the code structure I get with this.

Mutators/Generators

The fuzzer currently supports 2 different fuzz-case generators. One based on mutating inputs and one that generates new cases from a user-provided grammar. These are designed in a pluggable fashion though, so mutators can easily be exchanged with different models/target-dependent custom mutators.

The input mutator is about as generic as they come. I pretty much copy-pasted the mutator from the one I wrote for Sfuzz, so for more information, here is a short description. It is seeded with a tested/extremely fast prng (Xoroshiro64Star) and performs the following strategies:

* Byte Replacements
* Bitflips
* Magic Numbers
* Simple Arithmetic
* Block Removals
* Block Duplication
* Input Resizes
* Dictionary
* Havoc

The generational mutator is a little more interesting. The one I am currently using unfortunately only supports generating cases based on a grammar without mutations, but that is something I intend to change in the future. It is currently using fzero with some slight modifications. This is a generator written by Brandon Falk based on the Writing Fast Fuzzers paper. During build-time it takes a grammar file and generates a module similar to the below code snippets. This code is written specifically for the provided grammar and just generates the fuzz-case by having each non-terminal call a randomly linked terminal/non-terminal based on the grammar. This is able to greatly outperform traditional concepts since every step just calls random functions without having to work with the actual grammar representation anymore. To use this generator, users can define a grammar-file in the projects Makefile, which will then generate the rust-module and link it into Zfuzz. 

fn fragment_40(&mut self, depth: usize) {
    if depth >= 16 { return; }     
    match self.rand() % 3 {         
        0 => self.fragment_49(depth + 1),
        1 => self.fragment_51(depth + 1),
        2 => self.fragment_53(depth + 1),
        _ => unreachable!(),
    }
}

image.png

I never worked much with grammar-generators in the past so this was quite interesting to me and I decided to do a short survey of existing mutators and their capabilities. I went through the papers of the generators listed below and installed all of them to locally evaluate them. Since they all take different grammar representations, and I had no interest in manually setting up 4 different grammars for complex targets, I evaluated them based on this super simple grammar I set up for all their expected input-formats.

Fzero was by far the fastest due to its grammar-compilation model and just overall simplicity. Dharma was by far the slowest, but given that it’s written in python without any focus on performance, this makes sense (which makes it unfortunate that this is probably the most popularly used grammar-generator out there). Resmack did not stand out to me in a notable way. I think it's more of a hobby project, but the author had detailed blogposts on it and it was very easy to get set up for profiling so I gave it a go. It does not seem like it is currently able to perform grammar-based mutations but it seems like it's currently a work-in-progress so this project may eventually become more interesting. Grammatron stood out to me the most. The project preprocesses the provided grammar into a finite state automaton that de-layers nested non-terminals to address sampling biases that come with grammars in default CFG form. It also maintains a tree-based representation of the grammar that unlike the other mutators listed here, allows it to smartly mutate inputs for coverage-guided fuzzing rather than just generating new cases. It is also surprisingly well written and achieves a quite impressive performance. I also briefly looked at Nautilus, but I couldn’t easily get it to build and from the evaluations made in the Grammatron paper, it seems like it basically supersedes Nautilus anyways.

Grammatron was unfortunately a little bit harder to set up, so including it in Zfuzz would have been a bigger effort than I currently had time for. In the future I would like to either integrate Grammatron entirely or write my own variation of it, combining Fzero’s compilation model with Grammatron’s capabilities.

* Fzero-generational:             371.5906 MiB/s, 6,448,320.6128 iters/s 
* Grammatron-mutational:      59.7226 MiB/s,   721,470.7124 iters/s 
* Grammatron-generational:   50.8891 MiB/s,   802,460.4788 iters/s 
* Resmack-generational:         21.3895 MiB/s,   521,365.4300 iters/s 
* Dharma-generational:            0.4342 MiB/s,      6250.6510 iters/s 

* Nautilus-generational:    5.075 MiB/s,  154,000 iters/s (Performed on worse hardware, gonna have to properly repeat eventually)

Misc

Here I would like to just quickly mention some additional things I worked on for the fuzzer.

* Simple elf loader that can parse/load static elf binaries into the fuzzer
* Gdb-script that can dump entire memory/register/file state from a running process
* Dump-loader that can load these dumps into the fuzzer
* A couple of benchmarks listed here that showcase some advantages/issues with the fuzzer


