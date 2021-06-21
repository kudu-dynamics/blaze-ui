from typing import overload

from binaryninja import Function
from binaryninja.basicblock import BasicBlock
from binaryninja.lineardisassembly import LinearDisassemblyLine, LinearViewCursor


class LinearViewLine(LinearDisassemblyLine):
    cursor: LinearViewCursor
    lineIndex: int

class LinearViewCursorPosition:
    function: Function
    block: BasicBlock
    address: int
    instrIndex: int
    cursor: LinearViewCursor
    lineIndex: int
    tokenIndex: int
    characterIndex: int
    cursorX: int
    cursorY: int

    @overload
    def __init__(self): ...
    @overload
    def __init__(self, pos: 'LinearViewCursorPosition', /): ...
    @overload
    def __init__(self, line: LinearViewLine, /): ...

    def __lt__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __le__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __gt__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __ge__(self, other: 'LinearViewCursorPosition', /) -> bool: ...

    def AsLine(self) -> 'LinearViewCursorPosition': ...