#!/usr/bin/env python3

from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, Union

# T = TypeVar('T')
# TypedDict cannot be polymorphic/generic
# See https://github.com/python/mypy/issues/3863
T = List[str]

Address = int
Word64 = int
UUID = int
CfgId = UUID


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
    bvFilePath: str
    action: Union[BinjaToServer, ServerToBinja]
