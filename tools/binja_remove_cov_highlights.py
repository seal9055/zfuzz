"""
Script to go through all basic blocks and remove all instances of highlighted code blocks.

Executed via snipped editor.
"""

def main():
    for func in bv.functions:
        for block in func.basic_blocks:
            block.set_user_highlight(HighlightStandardColor.NoHighlightColor)

print("Starting")
main()
print("DONE")
