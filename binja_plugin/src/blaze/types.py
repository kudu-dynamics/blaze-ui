#!/usr/bin/env python3

import enum
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, Union, cast

# T = TypeVar('T')
# TypedDict cannot be polymorphic/generic
# See https://github.com/python/mypy/issues/3863
T = List[str]

Address = int
Word64 = int
UUID = str
CfgId = UUID
ClientId = UUID
BinaryHash = str
HostBinaryPath = str

BINARYNINJAUI_CUSTOM_EVENT = 0xfff6

class Symbol(TypedDict):
    _symbolName: str
    _symbolRawName: str


class BlazeConfig(TypedDict):
    client_id: ClientId

    
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


class CallDest(TypedDict):
    tag: Literal['CallAddr', 'CallFunc', 'CallExpr', 'CallExprs']
    contents: Union[Address, Function, PilExpr, List[PilExpr]]


class BasicBlockNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    end: Address
    nodeData: T


class CallNode(TypedDict):
    uuid: UUID
    ctx: Ctx
    start: Address
    callDest: CallDest
    nodeData: T


class EnterFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: T


class LeaveFuncNode(TypedDict):
    uuid: UUID
    prevCtx: Ctx
    nextCtx: Ctx
    nodeData: T


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


class ServerToBinja(TypedDict, total=False):
    tag: Literal['SBLogInfo', 'SBLogWarn', 'SBLogError', 'SBCfg', 'SBNoop']
    message: Optional[str]
    cfgId: Optional[CfgId]
    cfg: Optional[ServerCfg]


class BinjaToServer(TypedDict, total=False):
    tag: Literal['BSConnect', 'BSTextMessage', 'BSTypeCheckFunction', 'BSCfgNew', 'BSCfgExpandCall',
                 'BSCfgRemoveBranch', 'BSNoop']
    message: Optional[str]
    address: Optional[Word64]
    startFuncAddress: Optional[Word64]
    cfgId: Optional[CfgId]
    callNode: Optional[CallNode]
    edge: Optional[Tuple[CfNode, CfNode]]


class BinjaMessage(TypedDict):
    clientId: ClientId
    hostBinaryPath: HostBinaryPath
    bndbHash: BinaryHash
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
