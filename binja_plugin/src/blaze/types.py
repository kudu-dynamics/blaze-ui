#!/usr/bin/env python3

import enum
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, TypedDict, Union, cast

from binaryninja.enums import InstructionTextTokenContext, InstructionTextTokenType
from binaryninja.function import DisassemblyTextLine, InstructionTextToken

Address = int
ByteOffset = int
Word64 = int
UUID = str
BranchId = UUID
CfgId = UUID
ClientId = UUID
PoiId = UUID
BinaryHash = str
BndbHash = str
HostBinaryPath = str

# What Aeson encodes the unit value `()` as
# TODO: This used to be a Literal[[]] type, but that is actually an invalid Literal.
#       Is there a way to change how Aeson (on the server) encodes unit? And is there an alternative
#       representation that won't introduce ambiguities?
Unit = List[Any]

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
            type=getattr(InstructionTextTokenType, t['tokenType']),
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


class CallNodeRatingTotal(TypedDict, total=True):
    tag: Literal['Unreachable', 'Reachable']


class CallNodeRating(CallNodeRatingTotal, total=False):
    score: float


class ServerPoiSearchResults(TypedDict, total=True):
    callNodeRatings: List[Tuple[UUID, CallNodeRating]]
    presentTargetNodes: List[UUID]


class PoiSearchResults(TypedDict, total=True):
    callNodeRatings: Dict[UUID, CallNodeRating]
    presentTargetNodes: Set[UUID]


BranchTreeList = List[BranchTreeListItem]

ServerBranchesOfClient = List[Tuple[HostBinaryPath, List[Tuple[BranchId, ServerBranch]]]]


class SnapshotServerToBinjaTotal(TypedDict, total=True):
    tag: Literal['SnapshotBranch', 'BranchesOfFunction', 'BranchesOfBinary', 'BranchesOfClient']


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
    originFuncAddr: Address
    branchId: BranchId
    name: str
    cfgId: CfgId


### Poi Messages


class Poi(TypedDict):
    poiId: PoiId
    clientId: Optional[ClientId]
    hostBinaryPath: HostBinaryPath
    binaryHash: BinaryHash
    created: str  # Parseable with util.servertime_to_clienttime
    funcAddr: Address
    instrAddr: Address
    name: Optional[str]
    description: Optional[str]
    isGlobalPoi: bool


class PoiServerToBinjaTotal(TypedDict, total=True):
    tag: Literal['PoisOfBinary', 'GlobalPoisOfBinary']


class PoiServerToBinja(PoiServerToBinjaTotal, total=False):
    pois: List[Poi]
    globalPois: List[Poi]


class PoiBinjaToServerTotal(TypedDict, total=True):
    tag: Literal['GetPoisOfBinary', 'AddPoi', 'DeletePoi', 'RenamePoi', 'DescribePoi',
                 'ActivatePoiSearch', 'DeactivatePoiSearch']


class PoiBinjaToServer(PoiBinjaToServerTotal, total=False):
    funcAddr: Address
    instrAddr: Address
    name: Optional[str]
    description: Optional[str]
    poiId: PoiId
    activeCfg: Optional[str]


# Constraint messages
class ConstraintError(TypedDict):
    tag: Literal['VarNameNotFound', 'InvalidOperator', 'ParseError']
    contents: Union[str, str, str]


class ConstraintServerToBinjaTotal(TypedDict, total=True):
    pass  # tag: Literal['SBInvalidConstraint']


class ConstraintServerToBinja(ConstraintServerToBinjaTotal, total=False):
    parseError: ConstraintError


class ConstraintBinjaToServerTotal(TypedDict, total=True):
    pass  # tag: Literal['AddConstraint']


class ConstraintBinjaToServer(ConstraintBinjaToServerTotal, total=False):
    cfgId: CfgId
    node: UUID
    stmtIndex: Word64
    exprText: str


class ServerPendingChanges(TypedDict, total=True):
    removedNodes: List[UUID]
    removedEdges: List[List[UUID]]


@dataclass
class PendingChanges:
    removed_nodes: Set[UUID]
    removed_edges: Set[Tuple[UUID, UUID]]

    @property
    def has_changes(self) -> bool:
        return bool(self.removed_nodes) or bool(self.removed_edges)


def pending_changes_from_server(p: ServerPendingChanges) -> PendingChanges:
    return PendingChanges(
        removed_nodes=set(p['removedNodes']),
        removed_edges=set(cast(Tuple[UUID, UUID], tuple(e)) for e in p['removedEdges']),
    )


class ServerToBinjaTotal(TypedDict, total=True):
    tag: Literal['SBLogInfo', 'SBLogWarn', 'SBLogError', 'SBCfg', 'SBNoop', 'SBSnapshot', 'SBPoi']


class ServerToBinja(ServerToBinjaTotal, total=False):
    bndbHash: BinaryHash
    message: str
    cfgId: CfgId
    cfg: ServerCfg
    snapshotMsg: SnapshotServerToBinja
    poiMsg: PoiServerToBinja
    poiSearchResults: Optional[PoiSearchResults]
    pendingChanges: Optional[ServerPendingChanges]


class BinjaToServerTotal(TypedDict, total=True):
    tag: Literal['BSConnect', 'BSTextMessage', 'BSTypeCheckFunction', 'BSCfgNew', 'BSCfgExpandCall',
                 'BSCfgRemoveBranch', 'BSCfgRemoveNode', 'BSSnapshot', 'BSNoop', 'BSCfgFocus',
                 'BSCfgConfirmChanges', 'BSCfgRevertChanges', 'BSPoi', 'BSConstraint', 'BSComment']


class BinjaToServer(BinjaToServerTotal, total=False):
    message: str
    bndbHash: BinaryHash
    address: Word64
    comment: str
    startFuncAddress: Word64
    cfgId: CfgId
    callNode: CallNode
    edge: Tuple[CfNode, CfNode]
    snapshotMsg: SnapshotBinjaToServer
    node: CfNode
    nodeId: UUID
    stmtIndex: Word64
    targetAddress: Word64
    poiMsg: PoiBinjaToServer
    constraintMsg: ConstraintBinjaToServer


class BinjaMessage(TypedDict):
    clientId: ClientId
    hostBinaryPath: HostBinaryPath
    binaryHash: BinaryHash
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
