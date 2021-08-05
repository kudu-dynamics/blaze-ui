#!/usr/bin/env python3

import enum
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, Union, cast

from binaryninja.enums import InstructionTextTokenContext, InstructionTextTokenType
from binaryninja.function import DisassemblyTextLine, InstructionTextToken

Address = int
ByteOffset = int
Word64 = int
UUID = str
BranchId = UUID
CfgId = UUID
ClientId = UUID
BinaryHash = str
HostBinaryPath = str

# What Aeson encodes the unit value `()` as
Unit = Literal[[]]

BINARYNINJAUI_CUSTOM_EVENT = 0xfff6


class Symbol(TypedDict):
    _symbolName: str
    _symbolRawName: str


FuncParamInfo = Any


class Function(TypedDict):
    symbol: Optional[Symbol]
    name: str
    address: Address
    params: List[FuncParamInfo]


CtxIndex = int


class Ctx(TypedDict):
    func: Function
    ctxIndex: CtxIndex


PilExpr = object

class ConstFuncPtrOp(TypedDict):
    address: Address
    symbol: Optional[Symbol]

class ExternPtrOp(TypedDict):
    address: Address
    offset: ByteOffset
    symbol: Optional[Symbol]
    
class CallDest(TypedDict):
    tag: Literal['CallAddr', 'CallFunc', 'CallExpr', 'CallExprs', 'CallExtern']
    contents: Union[ConstFuncPtrOp, Function, PilExpr, List[PilExpr], ExternPtrOp]


TokenType = Literal['TextToken', 'InstructionToken', 'OperandSeparatorToken', 'RegisterToken',
                    'IntegerToken', 'PossibleAddressToken', 'BeginMemoryOperandToken',
                    'EndMemoryOperandToken', 'FloatingPointToken', 'AnnotationToken',
                    'CodeRelativeAddressToken', 'ArgumentNameToken', 'HexDumpByteValueToken',
                    'HexDumpSkippedByteToken', 'HexDumpInvalidByteToken', 'HexDumpTextToken',
                    'OpcodeToken', 'StringToken', 'CharacterConstantToken', 'KeywordToken',
                    'TypeNameToken', 'FieldNameToken', 'NameSpaceToken', 'NameSpaceSeparatorToken',
                    'TagToken', 'StructOffsetToken', 'StructOffsetByteValueToken',
                    'StructureHexDumpTextToken', 'GotoLabelToken', 'CommentToken',
                    'PossibleValueToken', 'PossibleValueTypeToken', 'ArrayIndexToken',
                    'IndentationToken', 'CodeSymbolToken', 'DataSymbolToken', 'LocalVariableToken',
                    'ImportToken', 'AddressDisplayToken', 'IndirectImportToken',
                    'ExternalSymbolToken']

TokenContext = Literal['NoTokenContext', 'ocalVariableTokenContext', 'DataVariableTokenContext',
                       'unctionReturnTokenContext', 'InstructionAddressTokenContext',
                       'LInstructionIndexTokenContext',]


class Token(TypedDict):
    tokenType: TokenType
    text: str
    value: int
    size: int
    operand: int
    context: TokenContext
    address: int


def tokens_from_server(ts: List[Token]) -> DisassemblyTextLine:
    tokens = [
        InstructionTextToken(
            token_type=getattr(InstructionTextTokenType, t['tokenType']),
            text=t['text'],
            value=t['value'],
            size=t['size'],
            operand=t['operand'],
            context=getattr(InstructionTextTokenContext, t['context']),
            address=t['address'],
        ) for t in ts
    ]
    return DisassemblyTextLine(tokens)


class BasicBlockNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    end: Address
    nodeData: List[List[Token]]


class CallNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    callDest: CallDest
    nodeData: List[List[Token]]


class EnterFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: List[List[Token]]


class LeaveFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: List[List[Token]]


CfNodeUnion = Union[BasicBlockNode, CallNode, EnterFuncNode, LeaveFuncNode]


class CfNode(TypedDict):
    tag: Literal['BasicBlock', 'Call', 'EnterFunc', 'LeaveFunc']
    contents: CfNodeUnion


class CfEdge(TypedDict):
    src: CfNode
    dst: CfNode
    branchType: Literal['TrueBranch', 'FalseBranch', 'UnconditionalBranch']


class Cfg(TypedDict):
    edges: List[CfEdge]
    root: UUID
    nodes: Dict[UUID, CfNode]


class ServerCfg(TypedDict):
    edges: List[CfEdge]
    root: CfNode
    nodes: List[Tuple[CfNode, CfNode]]


class SnapshotInfo(TypedDict):
    name: Optional[str]
    created: Any  # TODO: utc time
    modified: Any  # TODO: utc time
    snapshotType: Literal['Autosave', 'Immutable']


class ServerBranchTree(TypedDict):
    edges: List[Tuple[Unit, Tuple[CfgId, CfgId]]]
    nodes: List[Tuple[CfgId, Unit]]


class BranchTree(TypedDict):
    edges: List[Tuple[CfgId, CfgId]]


class ServerBranch(TypedDict):
    hostBinaryPath: HostBinaryPath
    bndbHash: BinaryHash
    originFuncAddr: Address
    originFuncName: str
    branchName: Optional[str]
    rootNode: CfgId
    snapshotInfo: List[Tuple[CfgId, SnapshotInfo]]
    tree: ServerBranchTree


class Branch(TypedDict, total=True):
    hostBinaryPath: HostBinaryPath
    bndbHash: BinaryHash
    originFuncAddr: Address
    originFuncName: str
    branchName: Optional[str]
    snapshotInfo: Dict[CfgId, SnapshotInfo]
    rootNode: CfgId
    tree: BranchTree


class BranchTreeListItem(TypedDict, total=True):
    cfgId: CfgId
    snapshotInfo: SnapshotInfo
    children: List['BranchTreeListItem']


BranchTreeList = List[BranchTreeListItem]


class SnapshotServerToBinjaTotal(TypedDict, total=True):
    tag: Literal['SnapshotBranch', 'BranchesOfFunction', 'BranchesOfBinary', 'BranchesOfClient']


ServerBranchesOfClient = List[Tuple[HostBinaryPath, List[Tuple[BranchId, ServerBranch]]]]


class SnapshotServerToBinja(SnapshotServerToBinjaTotal, total=False):
    branchId: BranchId
    funcAddress: Address
    hostBinaryPath: HostBinaryPath
    branch: ServerBranch
    branches: List[Tuple[BranchId, ServerBranch]]
    branchesOfClient: ServerBranchesOfClient


class SnapshotBinjaToServerTotal(TypedDict, total=True):
    tag: Literal['GetAllBranchesOfClient', 'GetAllBranchesOfBinary', 'GetBranchesOfFunction',
                 'RenameBranch', 'LoadSnapshot', 'SaveSnapshot', 'RenameSnapshot']


class SnapshotBinjaToServer(SnapshotBinjaToServerTotal, total=False):
    originFuncAddr: Optional[Address]
    branchId: Optional[BranchId]
    name: Optional[str]
    cfgId: Optional[CfgId]


class ServerToBinjaTotal(TypedDict, total=True):
    tag: Literal['SBLogInfo', 'SBLogWarn', 'SBLogError', 'SBCfg', 'SBNoop', 'SBSnapshot']


class ServerToBinja(ServerToBinjaTotal, total=False):
    bndbHash: Optional[BinaryHash]
    message: Optional[str]
    cfgId: Optional[CfgId]
    cfg: Optional[ServerCfg]
    snapshotMsg: Optional[SnapshotServerToBinja]


class BinjaToServerTotal(TypedDict, total=True):
    tag: Literal['BSConnect', 'BSTextMessage', 'BSTypeCheckFunction', 'BSCfgNew', 'BSCfgExpandCall',
                 'BSCfgRemoveBranch', 'BSCfgRemoveNode', 'BSSnapshot', 'BSNoop', 'BSCfgFocus'
                 'BSCfgConfirmChanges', 'BSCfgRevertChanges']


class BinjaToServer(BinjaToServerTotal, total=False):
    message: Optional[str]
    bndbHash: Optional[BinaryHash]
    address: Optional[Word64]
    startFuncAddress: Optional[Word64]
    cfgId: Optional[CfgId]
    callNode: Optional[CallNode]
    edge: Optional[Tuple[CfNode, CfNode]]
    snapshotMsg: Optional[SnapshotBinjaToServer]
    node: Optional[CfNode]
    targetAddress: Optional[Word64]


class BinjaMessage(TypedDict):
    clientId: ClientId
    hostBinaryPath: HostBinaryPath
    action: Union[BinjaToServer, ServerToBinja]


# From binaryninja-api/ui/action.h
class MenuOrder(enum.IntEnum):
    FIRST = 0
    EARLY = 64
    NORMAL = 128
    LATE = 192
    LAST = 255

    def to_int(self) -> Literal[0, 64, 128, 192, 255]:
        i = int(self)
        assert i in {0, 64, 128, 192, 255}
        return cast(Literal[0, 64, 128, 192, 255], i)
