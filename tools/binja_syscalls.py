"""
Start iterating down function-callee's recursively from `here` in decompiler, and find all 
syscalls used. I don't think this currently fully works

Run from snipper editor
"""

syscalls = []
functions = []

def get_syscalls_in_function(func):
	global syscalls
	global functions
	for callee in func.callees:
		functions.append(callee)
	for block in func.llil_basic_blocks:
		for instr in block:
			if instr.operation == LowLevelILOperation.LLIL_SYSCALL:
				syscall_num = instr.operands[0].value
				syscalls.append(syscall_num)

def main(bv):
	global syscalls
	global functions
	cur_func = bv.get_functions_containing(here)[0]
	functions.append(cur_func)
	for function in functions:
		get_syscalls_in_function(function)
	for syscall in syscalls:
		print(syscall)
	print("Done")

main(bv)

external_symbols = bv.get_symbols_of_type(SymbolType.ExternalSymbol)
for s in external_symbols:
    print(s)

print(len(functions))
