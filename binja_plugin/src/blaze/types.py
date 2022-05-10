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
CtxId = int
Sym = int
StmtIndex = int


# What Aeson encodes the unit value `()` as
# TODO: This used to be a Literal[[]] type, but that is actually an invalid Literal.
#       Is there a way to change how Aeson (on the server) encodes unit? And is there an alternative
#       representation that won't introduce ambiguities?
Unit = List[Any]

# Binary Ninja uses different event types to coordinate UI events in
# the Binary Ninja application. These event IDs have changed in the past
# and may need to be updated again in the future.
BINARYNINJAUI_CUSTOM_EVENT = 0xfff8


class Symbol(TypedDict):
    _symbolName: str
    _symbolRawName: str


FuncParamInfo = Any


class Function(TypedDict):
    symbol: Optional[Symbol]
    name: str
    address: Address
    params: List[FuncParamInfo]


class Ctx(TypedDict):
    func: Function
    ctxId: CtxId


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


def tokens_from_server(ts: List[Token], max_str_length: Optional[int]) -> DisassemblyTextLine:
    def truncate(t: Token) -> str:
        if t['tokenType'] != 'StringToken':
            return t['text']

        if max_str_length is None or len(t['text']) - 2 <= max_str_length:
            return t['text']

        quote = t['text'][0]
        return t['text'][:max_str_length + 1] + '…' + quote

    tokens = [
        InstructionTextToken(
            type=getattr(InstructionTextTokenType, t['tokenType']),
            text=truncate(t),
            value=t['value'],
            size=t['size'],
            operand=t['operand'],
            context=getattr(InstructionTextTokenContext, t['context']),
            address=t['address'],
        ) for t in ts
    ]
    return DisassemblyTextLine(tokens)


IndexedStmt = Tuple[Optional[StmtIndex], List[Token]]


class BasicBlockNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    end: Address
    nodeData: List[IndexedStmt]


class CallNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    callDest: CallDest
    nodeData: List[IndexedStmt]


class EnterFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: List[IndexedStmt]


class LeaveFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: List[IndexedStmt]


class GroupingNode(TypedDict):
    uuid: UUID
    termNode: 'CfNode'
    grouping: 'ServerCfg'
    nodeData: List[IndexedStmt]


CfNodeUnion = Union[BasicBlockNode, CallNode, EnterFuncNode, LeaveFuncNode, GroupingNode]


class CfNode(TypedDict):
    tag: Literal['BasicBlock', 'Call', 'EnterFunc', 'LeaveFunc', 'Grouping']
    contents: CfNodeUnion


class CfEdge(TypedDict):
    src: CfNode
    dst: CfNode
    branchType: Literal['TrueBranch', 'FalseBranch', 'UnconditionalBranch']


class TypeError(TypedDict):
    stmtOrigin: int
    sym: Sym
    error: List[Token]
    
    
class TypeInfo(TypedDict):
    varSymMap: Dict[str, Sym]
    varEqMap: Dict[Sym, List[Sym]]
    symTypes: Dict[Sym, List[Token]]
    typeErrors: List[TypeError]


class Cfg(TypedDict):
    edges: List[CfEdge]
    root: UUID
    nodes: Dict[UUID, CfNode]
    nextCtxIndex: CtxId


class ServerCfg(TypedDict):
    transportEdges: List[CfEdge]
    transportRoot: CfNode
    transportNodes: List[Tuple[CfNode, CfNode]]
    transportNextCtxIndex: CtxId


class ServerTypedCfg(TypedDict):
    typeInfo: TypeInfo
    typeSymCfg: ServerCfg


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
    tag: Literal['SnapshotBranch', 'BranchesOfFunction', 'BranchesOfBinary', 'BranchesOfClient', 'DeleteSnapshotConfirmationRequest']


class SnapshotServerToBinja(SnapshotServerToBinjaTotal, total=False):
    branchId: BranchId
    funcAddress: Address
    hostBinaryPath: HostBinaryPath
    branch: ServerBranch
    branches: List[Tuple[BranchId, ServerBranch]]
    branchesOfClient: ServerBranchesOfClient
    snapshotRequestedForDeletion: CfgId
    deletedNodes: List[CfgId]
    willWholeBranchBeDeleted: bool


class SnapshotBinjaToServerTotal(TypedDict, total=True):
    tag: Literal['GetAllBranchesOfClient', 'GetAllBranchesOfBinary', 'GetBranchesOfFunction',
                 'RenameBranch', 'LoadSnapshot', 'SaveSnapshot', 'RenameSnapshot',
                 'PreviewDeleteSnapshot', 'ConfirmDeleteSnapshot']


class SnapshotBinjaToServer(SnapshotBinjaToServerTotal, total=False):
    originFuncAddr: Address
    branchId: BranchId
    name: str
    cfgId: CfgId


### Poi Messages


class Poi(TypedDict):
    poiId: PoiId
    clientId: Optional[ClientId]
    hostBinaryPath: Optional[HostBinaryPath]
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


class ServerGroupOptions(TypedDict, total=True):
    startNode: UUID
    endNodes: List[UUID]


@dataclass
class GroupOptions:
    start_node: UUID
    end_nodes: Set[UUID]


def group_options_from_server(g: ServerGroupOptions) -> GroupOptions:
    return GroupOptions(start_node=g['startNode'],
                        end_nodes=set(g['endNodes']))


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
    typeInfo: TypeInfo


class BinjaToServerTotal(TypedDict, total=True):
    tag: Literal['BSConnect', 'BSTextMessage', 'BSTypeCheckFunction', 'BSCfgNew',
                 'BSCfgExpandCall', 'BSCfgRemoveBranch', 'BSCfgRemoveNode',
                 'BSSnapshot', 'BSNoop', 'BSCfgFocus', 'BSCfgConfirmChanges',
                 'BSCfgRevertChanges', 'BSPoi', 'BSConstraint', 'BSComment',
                 'BSGroupStart', 'BSGroupDefine', 'BSGroupExpand']


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
    startNodeId: UUID
    endNodeId: UUID
    groupingNodeId: UUID
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
