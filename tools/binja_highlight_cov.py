"""
Iterate through file containing 1 address per line, and if the address exists within codebase,
highlight the block green to indicate that the fuzzer hit it

Executed via snippet editor
"""

def x(n):
    try:
        return int(n, 16)
    except:
        return 0

def main():
    f = open("C:\\Users\\Gilbert\\Downloads\\cov.txt", "r")
    data = f.read()
    as_arr = data.split('\n')
    addresses = list(map(x, as_arr))
    for func in bv.functions:
        for block in func.basic_blocks:
            for instr in block.disassembly_text:
                if instr.address in addresses:
                    if instr.address in addresses:
                        print(f"Highlighting: {hex(instr.address)}")
                        block.set_user_highlight(HighlightStandardColor.GreenHighlightColor)

print("Starting")
main()
print("DONE")
