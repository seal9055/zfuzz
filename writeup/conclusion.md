Overall I am quite happy with the results of this project and believe that it is a very solid foundation to build extremely capable fuzzers on top off. There are still a lot of things that could be improved upon, both performance-wise, and fuzzing-logic wise to generate smarter inputs, but all of these can be done with some time investment. 

The fuzzer will never be as generic as AFL or Libfuzzer, and harder targets will always require manual effort to harness, but I believe that this fuzzer is in a spot where it can deal with hard targets that are otherwise hard to harness such as embedded devices, phones, or targets that can only be run on top of Qemu’s emulation. It overcame Sfuzz’s main disadvantage of only supporting RISCV/being more of a poc, and is actually usable while providing greatly improved performance over most other emulation-based fuzzers.

Moving Forward

* Add better Unicorn-hooking capabilities to directly modify IR similar to how many dbi frameworks operate. Current hooks have a massive performance overhead which will be the main bottleneck for any larger target
* Byte-level permission mode & CmpCov (I believe these should both only be added after fixing the previous Unicorn-hooking performance issues since they will otherwise slow the target down too much)
* Grammar generator that supports mutations to enable coverage-guided grammar fuzzing
* Power-Schedule/dynamic-value-calculation for fuzz-cases to prioritize better inputs
* This is less specific for this project, but Unicorn does not seem to support modern x86 SIMD instructions which pretty much every target has nowadays (especially when linked against modern-system Libc). I don’t see an easy fix for this, but this basically makes the fuzzer useless against most closed-source x86 targets. I believe Qemu has pretty good support for this so it’s unfortunate that Unicorn does not. Maybe this will be added in the future?
