from binaryninja import BinaryView
from binaryninja.filemetadata import FileMetadata

from ._filecontext import FileMetadata
from ._viewframe import ViewFrame


class FileContext:
    def __init__(
        self,
        file: FileMetadata,
        rawData: BinaryView,
        filename: str = '',
        isValidSaveName: bool = False,
        createViews: bool = True,
        /
    ): ...

    def getFilename(self) -> str: ...
    def getCurrentViewFrame(self) -> ViewFrame: ...

    def GetCurrentView(self) -> str: ...
    def GetCurrentOffset(self) -> int: ...
    def Navigate(self, view: str, offset: int, /) -> bool: ...
    def updateAnalysis(self): ...

    @staticmethod
    def newFile() -> FileContext: ...
    @staticmethod
    def openFilename(path: str, /) -> FileContext: ...
