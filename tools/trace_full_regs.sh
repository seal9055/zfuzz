#!/bin/zsh

'''
Script used to trace the register state of a program running under qemu and format it so that I can
just run `diff` on the traces generated by qemu and my fuzzer to find differences in execution
'''

# Requires target program and the pc to stop tracing at
if [ "$#" -ne 2 ]; then
    echo "Usage: ./trace_full_regs.sh <target> <last_pc>"
    exit
fi

# gdb-script that runs `info reg` on every instruction until $last_pc
echo "set pagination off" >> script
echo "set logging file gdb.output" >> script
echo "set logging on" >> script
echo "" >> script
echo "target remote :1234" >> script
echo "" >> script
echo "while(\$pc != $2)" >> script
echo "    info reg" >> script
echo "    si" >> script
echo "end" >> script
echo "" >> script
echo "set logging off" >> script
echo "quit" >> script

# Run qemu with gdb
qemu-riscv64 -g 1234 ./$1 &
gdb-multiarch ./$1 --command=script

# Format output
cat gdb.output | grep -v 'in' | tr -s ' ' | cut -d ' ' -f1,2 | cut -d$'\t' -f1 > trace
sed -i '/pc/ s/$/\n/' trace

rm gdb.output
rm script