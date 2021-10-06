#!/usr/bin/env python3

from typing import Optional, Tuple, overload

from binaryninja import AddressRange, BinaryDataNotification, BinaryView, FlowGraph, Function
from binaryninja._binaryninjacore import BNTagReference
from binaryninja.binaryview import BinaryView
from binaryninja.flowgraph import FlowGraphEdge, FlowGraphNode
from binaryninja.function import AddressRange
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QAbstractScrollArea, QWidget

from ._action import HighlightTokenState
from ._preview import PreviewScrollHandler
from ._viewframe import View


class FlowGraphWidget(QAbstractScrollArea, View, PreviewScrollHandler, BinaryDataNotification):
    def __init__(
            self,
            parent: QWidget,
            view: BinaryView,
            graph: FlowGraph = FlowGraph(),
            /,
    ) -> None:
        ...

    def OnAnalysisFunctionUpdated(self, data: BinaryView, func: Function, /) -> None:
        ...

    def OnAnalysisFunctionUpdateRequested(self, data: BinaryView, func: Function, /) -> None:
        ...

    def OnDataMetadataUpdated(self, data: BinaryView, offset: int, /) -> None:
        ...

    def OnTagUpdated(self, data: BinaryView, tagRef: BNTagReference, /) -> None:
        ...

    @overload
    def setInitialGraph(self, graph: FlowGraph, /) -> None:
        ...

    @overload
    def setInitialGraph(self, graph: FlowGraph, addr: int, /) -> None:
        ...

    @overload
    def setGraph(self, graph: FlowGraph, /) -> None:
        ...

    @overload
    def setGraph(self, graph: FlowGraph, addr: int, /) -> None:
        ...

    @overload
    def setRelatedGraph(self, graph: FlowGraph, /) -> None:
        ...

    @overload
    def setRelatedGraph(self, graph: FlowGraph, addr: int, /) -> None:
        ...

    def updateToGraph(self, graph: FlowGraph, /) -> None:
        ...

    def getData(self) -> BinaryView:
        ...

    def getCurrentOffset(self) -> int:
        ...

    def getSelectionOffsets(self) -> AddressRange:
        ...

    # def getSelectionForXref(self) -> SelectionInfoForXref: ...
    def setSelectionOffsets(self, range: AddressRange, /) -> None:
        ...

    # virtual bool navigate(uint64_t pos) override;
    # virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;
    # virtual bool navigateToViewLocation(const ViewLocation& viewLocation) override;
    # bool navigateWithHistoryEntry(uint64_t addr, FlowGraphHistoryEntry* entry);
    # bool navigateWithHistoryEntry(FunctionRef func, uint64_t addr, FlowGraphHistoryEntry* entry);
    # void setNavigationTarget(View* target) { m_navigationTarget = target; }

    # virtual void clearRelatedHighlights();
    # virtual void setRelatedIndexHighlights(const std::set<size_t>& related);
    # virtual void setRelatedInstructionHighlights(const std::set<uint64_t>& related);

    # virtual void zoom(bool direction);
    # virtual void zoomActual();
    # virtual bool event(QEvent* event) override;
    # void disableZoom();
    # virtual void sendWheelEvent(QWheelEvent* event) override;

    # virtual void cut() override;
    # virtual void copy(TransformRef xform) override;
    # virtual void paste(TransformRef xform) override;

    # virtual bool canAssemble() override;
    # virtual bool canCompile() override;
    # virtual bool canPaste() override;

    # virtual void closing() override;

    # virtual HistoryEntry* getHistoryEntry() override;
    # void populateDefaultHistoryEntry(FlowGraphHistoryEntry* entry);
    # virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

    # virtual FunctionRef getCurrentFunction() override;
    # virtual BasicBlockRef getCurrentBasicBlock() override;
    # virtual ArchitectureRef getCurrentArchitecture() override;

    # virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
    # virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;
    # virtual size_t getCurrentILInstructionIndex() override;

    # void scrollToCursor();
    # bool isUpdating();

    # QFont getFont() override { return m_render.getFont(); }
    # virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }
    # QRect getMiniRenderRect() const { return m_miniRenderRect; }
    # void paintMiniGraphAndViewport(QWidget* owner);
    # bool paintMiniGraph(QWidget* owner, QPainter& p);

    # void paintNode(QPainter& p, FlowGraphNodeRef& node, int minY, int maxY);
    # void paintHighlight(QPainter& p, const std::vector<BinaryNinja::DisassemblyTextLine>& lines,
    #     int nodeX, int nodeWidth, int x, int y, size_t line, int tagIndent);
    # void paintEdge(QPainter& p, const FlowGraphNodeRef& node, const BinaryNinja::FlowGraphEdge& edge);

    # void showAddress(uint64_t addr, bool select = false);
    # void showIndex(size_t index);
    # void showTopNode();
    def showNode(self, node: FlowGraphNode, /) -> None:
        ...

    # void showLineInNode(FlowGraphNodeRef node, size_t lineIndex);
    # void ensureCursorVisible();

    # void viewInTypesView(std::string typeName, uint64_t offset = 0);

    # void setInstructionHighlight(BNHighlightColor color);
    # void setBlockHighlight(BNHighlightColor color);

    # virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;

    # void setHighlightToken(const HighlightTokenState& state, bool notify = true);

    # virtual void notifyUpdateInProgress(FunctionRef func);
    # virtual void onFunctionSelected(FunctionRef func);
    # virtual void onHighlightChanged(const HighlightTokenState& highlight);

    # static std::string getPossibleValueSetStateName(BNRegisterValueType state);
    # static std::string getStringForRegisterValue(ArchitectureRef arch, BinaryNinja::RegisterValue value);
    # static std::string getStringForPossibleValueSet(ArchitectureRef arch, const BinaryNinja::PossibleValueSet& values);

    def getNodeForMouseEvent(self, event: QMouseEvent, /) -> Optional[FlowGraphNode]:
        ...

    def getEdgeForMouseEvent(self, event: QMouseEvent, /) -> Optional[Tuple[FlowGraphEdge, bool]]:
        '''Returns `None` if no edge was clicked, or `(edge, is_incoming)` if an edge was
        clicked. `is_incoming` is `True` if the edge was clicked near the target of the
        edge, and `False` if it was clicked neat the source of the edge.'''

    #def getLineForMouseEvent(self, event: QMouseEvent, /) -> Optional[Any]: ...
    def getTokenForMouseEvent(self, event: QMouseEvent, /) -> HighlightTokenState:
        ...
