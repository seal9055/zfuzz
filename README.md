# zfuzz
Emulation based snapshot fuzzer. Can load arbitrary memory dumps and start fuzzing. Provides a
mutational and a generationl grammar based mutator.

#### Build
```sh
# This will take a while the first time. Afterwards you can set the `QUICK_REBUILD` flag which
# should speed up build considerably
# (code should work on all OS's, makefile is currently laid out specifically for linux though)
make
```

#### Testing against provided test\_cases
The repo currently contains 2 test-cases that the fuzzer is harnessed for. `simple_test` &
`simple_test_x86`. Both are based on the source code `/test_cases/simple_test.c`. 

- `simple_test_riscv64` is a riscv64 statically linked binary. The harness for it is located at
`src/target_1.rs`. This binary is loaded from disk using a simple static elf-loader. Allocators are
hooked, and the fuzzer starts running it.

- `simple_test_x86` is a 64-bit statically compiled binary (Although in this case it could also be
dynamic. I just chose to compile it static cause it seems to run faster in my fuzzer). The harness
for this test-case is located at `src/target_2.rs`. In this case a memory-dump is loaded from disk
and then executed. To test this case you will need to generate this dump using the following
commands. They will run the target in the debugger until right after the `read` syscall and then
use the snapshot.py gdb-script I wrote to dump the entire memory/register/file-state.
```sh
gdb ./test_cases/simple_test_x86
b *main+52      
run ./in/input.txt
source ./tools/snapshot.py 
fulldump
```

To run either of the targets, follow the steps outlined above, and then go to 
`src/targets/target.rs`. Here you can add targets to the `TARGETS` array using their TargetId 
number. Every target registered this way will be run by the fuzzer. Both targets can even be
run at the same time by registering multiple harnesses in `targets.rs`. This feature can be used to 
setup differential fuzzing between 2 targets taking the same testcases (eg. 2 json parsers). 

#### Run
```sh
mkdir in out && head -c 100 /dev/urandom > in/input.txt
./target/release/zfuzz -i in -o out
```

#### Usage Advice

###### Debugging
During snapshot fuzzing there will always be issues during harness setup. My favorite way of
debugging these is generally using print-debugging. For this the fuzzer supports a pc-trace hook
that can be enabled using `insert_pc_trace_hook`. This hook emits a full runtime trace to a
`pc_trace.txt` file (make sure you are running single threaded for this). You can also print out any
other registers/memory regions here if you believe they might help you with debugging your issue. I
often find this hook helpful in combination with a trace from the real target (eg. using a simple
gdb script like `tools/trace_full_regs.sh`) to see where the fuzzer diverges from the real target
hinting at some potential issue in the harness. This hook is very slow so avoid using it during real
fuzzing.

###### Coverage analysis
In `src/configurables.rs` you can set the `EMIT_COV` flag to have the fuzzer emit a `cov.txt` file.
Unlike the address-trace hook, this one does not significantly alter the fuzzers performance and can
be run multithreaded. It also gives you a (less detailed) pc-trace and is intended to be used while
running a campaign. This trace can then be loaded into a decompiler (eg. using the
`tools/binja_highlight_cov.py` script) to get a better idea of how the fuzzer is behaving/getting
through your target.

###### Grammar mutators
The fuzzer supports grammar based mutations (although this mode disables coverage since it is fully
generational by default making coverage-guided fuzzing impossible. To enable this, just setup a
grammar json file (similar to those in `/grammars`), change the makefile to enable grammar fuzzing
(and specify your grammar file), and set the mutator to `MutType::Gen` in `configurables.rs`. This
will have the fzero grammar engine use your grammar file to generate rust code implementing your
grammar as the generator.

###### Custom mutators
Custom mutators can very easily be added by just replacing the `src/mutator.rs` file. Your custom
mutator only needs to support a .mutate() method and you should be good to go. In the past I've used
this to eg. pass in an AST and do AST-based mutations for targets that would benefit from this.
