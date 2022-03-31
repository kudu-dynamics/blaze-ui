import asyncio
import enum
import json
import logging as _logging
import os
import os.path
import queue
import random
import threading
import urllib.parse
from typing import (
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

import binaryninja
import requests
import websockets
from websockets.exceptions import ConnectionClosed
from binaryninja import BackgroundTaskThread, BinaryView
from binaryninja.interaction import (
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    TextLineField,
    get_form_input,
    get_save_filename_input,
    show_message_box,
)
from binaryninja.mainthread import execute_on_main_thread_and_wait
from binaryninjaui import DockHandler, FileContext, UIContext, UIContextNotification, ViewFrame
from websockets.client import WebSocketClientProtocol
import hashlib

WEB_API_PING_TIMEOUT = 5  # 5 seconds
UPLOAD_TIMEOUT = 300  # 5 minutes

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget

from .cfg import ICFGDockWidget, ICFGFlowGraph, cfg_from_server
from .exceptions import BlazeNetworkError
from .poi import PoiListDockWidget
from .settings import BlazeSettings
from .snaptree import SnapTreeDockWidget
from .types import (
    BinaryHash,
    BinjaMessage,
    BinjaToServer,
    BndbHash,
    BranchId,
    CfgId,
    PoiBinjaToServer,
    PoiSearchResults,
    PoiServerToBinja,
    ServerBranch,
    ServerBranchesOfClient,
    ServerCfg,
    ServerPendingChanges,
    ServerToBinja,
    SnapshotBinjaToServer,
    SnapshotServerToBinja,
    group_options_from_server,
    pending_changes_from_server,
)
from .util import (
    bv_key,
    get_functions_containing,
    register_for_address,
    register_for_function,
    try_debug,
)

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'
SEND_FAIL_LOG_MSG = "failed to send analysis database because it is not yet saved"

log = _logging.getLogger(__name__)


def has_bndb_extension(filename: str) -> bool:
    return filename.endswith('.bndb')

class BlazeInstance():
    def __init__(self, bv: BinaryView, blaze: 'BlazePlugin'):
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.graph: Optional[ICFGFlowGraph] = None
        self.bndbHash: Optional[BndbHash] = None
        self.binaryHash: BinaryHash = self.get_bin_hash()
        self._icfg_dock_widget: Optional[ICFGDockWidget] = None
        self._snaptree_dock_widget: Optional[SnapTreeDockWidget] = None
        self._poi_list_dock_widget: Optional[PoiListDockWidget] = None

        log.debug('Initialized object: %r', self)

    def __repr__(self):
        return f'<BlazeInstance({self.bv!r}, {self.blaze!r}) at {hex(id(self))}>'

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def send(self, msg: BinjaToServer):
        self.blaze.send(self.bv, msg)

    def get_bin_hash(self) -> BinaryHash:
        r = self.bv.file.raw

        if r is None:
            raise ValueError('BlazeInstance.get_bin_hash cannot open file')

        else:
            f = r.read(0,len(r))
            if f is None:
                raise ValueError('BlazeInstance.get_bin_hash cannot open file')
            return hashlib.md5(f).hexdigest()

    @property
    def bv_key(self) -> str:
        return bv_key(self.bv)

    @property
    def icfg_dock_widget(self) -> ICFGDockWidget:
        if self._icfg_dock_widget is None:
            raise ValueError('BlazeInstance._icfg_dock_widget accessed before being set')

        return self._icfg_dock_widget

    @icfg_dock_widget.setter
    def icfg_dock_widget(self, dw: ICFGDockWidget) -> None:
        self._icfg_dock_widget = dw

    @property
    def snaptree_dock_widget(self) -> SnapTreeDockWidget:
        if self._snaptree_dock_widget is None:
            raise ValueError('BlazeInstance._snaptree_dock_widget accessed before being set')

        return self._snaptree_dock_widget

    @snaptree_dock_widget.setter
    def snaptree_dock_widget(self, dw: SnapTreeDockWidget) -> None:
        self._snaptree_dock_widget = dw

    @property
    def poi_list_dock_widget(self) -> PoiListDockWidget:
        if self._poi_list_dock_widget is None:
            raise ValueError('BlazeInstance._poi_list_dock_widget accessed before being set')

        return self._poi_list_dock_widget

    @poi_list_dock_widget.setter
    def poi_list_dock_widget(self, dw: PoiListDockWidget) -> None:
        self._poi_list_dock_widget = dw

    def with_bndb_hash(self, callback: Callable[[BinaryHash], None]) -> None:
        def set_hash_and_do_callback(h: BinaryHash) -> None:
            self.bndbHash = h
            callback(h)

        if self.bndbHash == None or self.bv.file.analysis_changed or self.bv.file.modified:
            u = UploadBndb(
                f'Uploading {self.bv.file.filename!r} to Blaze server...', self.blaze, self.bv, self.binaryHash,
                set_hash_and_do_callback)
            u.start()
        else:
            callback(self.bndbHash)


class UploadBndb(BackgroundTaskThread):
    def __init__(
        self,
        msg: str,
        blaze: 'BlazePlugin',
        bv: BinaryView,
        binaryHash: BinaryHash,
        callback: Callable[[BinaryHash], None],
    ) -> None:
        BackgroundTaskThread.__init__(self, msg, False)
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.binaryHash: BinaryHash = binaryHash
        self.callback: Callable[[BinaryHash], None] = callback

    def run(self):
        try:
            self.blaze.upload_bndb(self.bv, self.binaryHash, self.callback)
        except Exception as e:
            log.exception('Failed to upload BNDB: ' + str(e))


class BlazePlugin():
    def __init__(self) -> None:
        self._instance_by_bv: Dict[BinaryView, BlazeInstance] = {}
        self._instances_by_key: DefaultDict[str, Set[BlazeInstance]] = DefaultDict(set)
        self.out_queue: "queue.Queue[Union[Literal['SHUTDOWN'], BinjaMessage]]" = queue.Queue()

        self.websocket_thread: Optional[threading.Thread] = None
        self.settings: BlazeSettings = BlazeSettings()

        self.dock_handler: DockHandler = DockHandler.getActiveDockHandler()
        assert self.dock_handler

        # -- Add ICFG View

        def create_icfg_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = ICFGDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.ensure_instance(bv).icfg_dock_widget = widget
            return widget

        self.dock_handler.addDockWidget(
            "Blaze ICFG",
            create_icfg_widget,
            Qt.DockWidgetArea.RightDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Created ICFG dock widget')

        # -- Add SnapTree View

        def create_snaptree_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = SnapTreeDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.ensure_instance(bv).snaptree_dock_widget = widget
            return widget

        self.dock_handler.addDockWidget(
            "Blaze Snapshot Tree",
            create_snaptree_widget,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Created snaptree dock widget')

        # -- Add POI List View

        def create_poi_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = PoiListDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.ensure_instance(bv).poi_list_dock_widget = widget
            return widget

        self.dock_handler.addDockWidget(
            "Blaze POI List",
            create_poi_widget,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Created POI list widget')

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def instance_by_bv(self, bv: BinaryView) -> Optional[BlazeInstance]:
        return self._instance_by_bv.get(bv)

    def instances_by_key(self, key: str) -> Set[BlazeInstance]:
        return self._instances_by_key[key]

    def _init_thread(self) -> None:
        if not self.websocket_thread or not self.websocket_thread.is_alive():
            log.info('Starting or restarting websocket thread')
            self.out_queue = queue.Queue()
            t = threading.Thread(target=lambda: asyncio.run(self.main_websocket_loop()))
            t.name = 'Blaze websocket thread'
            t.start()
            self.websocket_thread = t
            log.info('Started websocket thread')

    def shutdown(self) -> None:
        if self.websocket_thread and self.websocket_thread.is_alive():
            log.info('Shutting down websocket thread')
            try:
                self.out_queue.put(BLAZE_WS_SHUTDOWN, timeout=1)
            except queue.Full:
                log.error('websocket queue is full, cannot shutdown')
                return

            self.websocket_thread.join(timeout=1)
            if self.websocket_thread.is_alive():
                log.warn('websocket thread is still alive after timeout')

    def web_api_url(self, path: Optional[str] = None, query: Optional[str] = None) -> str:
        return urllib.parse.ParseResult(
            scheme='http',
            netloc=f'{self.settings.host}:{self.settings.http_port}',
            path=path or '',
            query=query or '',
            params='',
            fragment='',
        ).geturl()

    def ping_server(
        self,
        data: Optional[bytes] = None,
        timeout: float = WEB_API_PING_TIMEOUT,
    ) -> None:
        if isinstance(data, bytes) and len(data) > 64:
            raise ValueError('len(data) should be <= 64')

        if data is None:
            # TODO Change to randybytes(64) in Python 3.9+
            data = bytes(random.getrandbits(8) for _ in range(64))

        try:
            r = requests.post(self.web_api_url('ping'), data=data, timeout=timeout)
        except requests.RequestException as e:
            raise BlazeNetworkError(
                f'Could not connect to server {self.web_api_url()}. Are your client settings correct and is the server up?'
            ) from e

        if r.status_code != requests.codes['ok']:
            raise BlazeNetworkError(f'Server returned {r.status_code} for ping request')

        if r.content != data:
            raise BlazeNetworkError(
                f'Server responded to ping request with {r.content!r}, but we were expecting {data!r}'
            )

    def upload_bndb(self, bv: BinaryView, binaryHash: BinaryHash, callback: Callable[[BinaryHash], None]) -> None:
        if (not has_bndb_extension(bv.file.filename) or
            (has_bndb_extension(bv.file.filename) and
             not os.path.isfile(bv.file.filename))):

            # Possible existing BNDB
            bndb_filename = f"{bv.file.filename}.bndb"
            if (os.path.isfile(bndb_filename)):
                msg = f"This action will overwrite the existing analysis database {bndb_filename}. If you prefer to use your existing BNDB, please open it and try again.\n\nContinue with ICFG creation?"
            else:
                msg = f"This action requires generation of an analysis database (BNDB).\n\nContinue with ICFG creation?"
            # FIXME: Need to wrap the result of show_message_box until BN 3.x API is fixed.
            to_save: Optional[MessageBoxButtonResult] = MessageBoxButtonResult(
                show_message_box(
                    "Blaze",
                    msg,
                    buttons=MessageBoxButtonSet.YesNoButtonSet,
                    icon=MessageBoxIcon.WarningIcon))

            if to_save == MessageBoxButtonResult.NoButton:
                log.error(SEND_FAIL_LOG_MSG)
                return
            else:
                bndb_filename : Optional[str] = get_save_filename_input("Choose database filename", "bndb", bndb_filename)
                if bndb_filename:
                    old_key = bv_key(bv)
                    new_key = bv_key(bndb_filename)
                    inst: Optional[BlazeInstance] = self.ensure_instance(bv)

                    self.move_instance(inst, old_key, new_key)

                    bv.create_database(bndb_filename)

                    self.ensure_instance(bv)
                else:
                    log.error(SEND_FAIL_LOG_MSG)
                    return

        # by now, bv is saved as bndb and bv.file.filename is bndb
        bv_filename: str = bv.file.filename

        if bv.file.analysis_changed:
            bv.create_database(bv_filename)

        with open(bv_filename, 'rb') as f:
            files = {'bndb': f}
            post_data = {
                'hostBinaryPath': bv_filename,
                'clientId': self.settings.client_id,
                'binaryHash': binaryHash,
            }
            self.ping_server()
            r = requests.post(
                self.web_api_url('upload'), data=post_data, files=files, timeout=UPLOAD_TIMEOUT)

        if r.status_code != requests.codes['ok']:
            log.error(
                'Backend server returned error (HTTP status %s): %r',
                r.status_code,
                r.text,
                extra={'error_payload': r.text})
            return

        rj = r.json()

        callback(rj)

    def ensure_instance(self, bv: BinaryView) -> BlazeInstance:
        '''
        Get the `BlazeInstance` associated with `bv`, or create one if none exists.

        :return: the `BlazeInstance` for this `bv`, or if none exists, the one
            that was created
        '''

        # TODO: This commented code should work, but it appears the
        #       _instance_by_bv is updated without the _instances_by_key being
        #       updated.
        #       NB: If the key is not being updated, then this implies we have
        #       a space leak.
        # if ((self._instance_by_bv.get(bv) is not None) and
        #     (bv in self._instances_by_key.get(bv_key(bv)))):
        #     return self._instance_by_bv.get(bv)
        if (instance := self._instance_by_bv.get(bv)) is not None:
            return instance

        log.info('Creating new blaze instance for BV: %r', bv)
        instance = BlazeInstance(bv, self)
        self._instance_by_bv[bv] = instance
        self._instances_by_key[bv_key(bv)].add(instance)

        return instance

    def move_instance(self, moving_inst: BlazeInstance, old_key: str, new_key: str) -> bool:
        '''
        Move all instances to another key. This is useful when a `BinaryView` is about
        to be modified/replaced with, e.g.,  a call to `create_database`.
        '''
        log.debug(f'Moving instances from old key {old_key} to new key {new_key}.')

        found = False

        if old_key == new_key:
            # Do nothing
            log.debug(f'Matching keys: {old_key}')
            return found

        insts: Set[BlazeInstance] = self._instances_by_key[old_key]

        if moving_inst not in insts:
            log.debug(f'Instance for {old_key} not found.')
            return found
        else:
            found = True

        insts.remove(moving_inst)
        if not insts:
            # Remove entry if the set of instances is now empty
            del self._instances_by_key[old_key]

        self._instances_by_key[new_key].add(moving_inst)

        moving_inst.bndbHash = None

        return found

    def send(self, bv: BinaryView, msg: BinjaToServer) -> None:
        self._init_thread()
        bhash = self.ensure_instance(bv).binaryHash
        new_msg = BinjaMessage(
            clientId=self.settings.client_id, hostBinaryPath=bv_key(bv), binaryHash=bhash, action=msg)
        # log.debug('enqueueing %s', new_msg)
        self.out_queue.put(new_msg)

    async def main_websocket_loop(self):
        uri = f'ws://{self.settings.host}:{self.settings.ws_port}/binja'

        log.info('connecting to websocket...')
        try:
            async with websockets.connect(uri, max_size=None) as websocket:  # type: ignore
                websocket = cast(WebSocketClientProtocol, websocket)
                log.info('connected to websocket')
                consumer_task = asyncio.ensure_future(self.recv_loop(websocket))
                producer_task = asyncio.ensure_future(self.send_loop(websocket))
                _, pending = await asyncio.wait(
                    [consumer_task, producer_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        except Exception as e:
            raise BlazeNetworkError(
                f'There was an error connecting to {uri}. Are your client settings correct and is the server up?'
            ) from e

    async def recv_loop(self, websocket: WebSocketClientProtocol) -> None:
        while True:
            try:
                ws_msg = await websocket.recv()
            except ConnectionClosed:
                log.info("Websocket disconnected.")
                self.shutdown()
                return

            try:
                msg = json.loads(ws_msg)

            except json.JSONDecodeError:
                log.exception(
                    'Backend returned malformed message', extra={'websocket_message': ws_msg})
                continue

            log.debug(
                'Received websocket message',
                extra={
                    'hostBinaryPath': msg['hostBinaryPath'],
                    'action.tag': msg['action']['tag'],
                },
            )

            relevant_instances: Set[BlazeInstance] = \
                self.instances_by_key(bv_key(msg['hostBinaryPath']))

            if not relevant_instances:
                log.error(
                    "Couldn't find existing blaze instance for %r",
                    msg['hostBinaryPath'],
                    extra={'blaze_instances': repr(self._instance_by_bv)})
                continue

            # log.debug('Blaze: received %r', msg)
            def run_message_handler():
                try:
                    self.message_handler(relevant_instances, msg['action'])
                except Exception:
                    log.exception("Couldn't handle message", extra={'websocket_message': msg})

            execute_on_main_thread_and_wait(run_message_handler)

    async def send_loop(self, websocket: WebSocketClientProtocol) -> None:
        while True:
            msg = await asyncio.get_running_loop().run_in_executor(None, self.out_queue.get)
            if msg == BLAZE_WS_SHUTDOWN:
                self.out_queue.task_done()
                return
            elif isinstance(msg, str):
                assert False

            try:
                json_msg = json.dumps(msg)
            except Exception:
                log.exception('Could not JSON encode message to send to backend: %r', msg)
                continue

            log.debug(
                'Sending websocket message...',
                extra={
                    'hostBinaryPath': msg['hostBinaryPath'],
                    'action.tag': msg['action']['tag'],
                })

            try:
                await websocket.send(json_msg)
            except Exception:
                log.exception('Failed to send message to backend')
                return

            log.debug('Sent websocket message')
            self.out_queue.task_done()

    def message_handler(
        self,
        relevant_instances: Iterable[BlazeInstance],
        msg: ServerToBinja,
    ) -> None:

        tag = msg['tag']
        # log.debug('Got message: %s', json.dumps(msg, indent=2))

        if tag == 'SBLogInfo':
            log.info(msg.get('message'))

        elif tag == 'SBLogWarn':
            log.warn(msg.get('message'))

        elif tag == 'SBLogError':
            log.error(msg.get('message'))

        elif tag == 'SBNoop':
            log.info("got Noop")

        elif tag == 'SBCfg':
            cfg_id = cast(CfgId, msg.get('cfgId'))
            cfg = cfg_from_server(cast(ServerCfg, msg.get('cfg')))
            server_pending_changes = msg.get('pendingChanges')
            server_poi_search_results = msg.get('poiSearchResults')
            server_group_options = msg.get('groupOptions')

            if server_poi_search_results:
                poi_search_results = PoiSearchResults(
                    callNodeRatings=dict(server_poi_search_results.get('callNodeRatings') or []),
                    presentTargetNodes=set(
                        server_poi_search_results.get('presentTargetNodes') or []))
            else:
                poi_search_results = None

            if server_pending_changes is None:
                server_pending_changes = ServerPendingChanges(removedNodes=[], removedEdges=[])

            pending_changes = pending_changes_from_server(server_pending_changes)

            if server_group_options:
                group_options = group_options_from_server(server_group_options)
            else:
                group_options = None

            for instance in relevant_instances:
                instance.graph = ICFGFlowGraph(
                    instance.bv, cfg, cfg_id, poi_search_results, pending_changes, group_options)
                instance.icfg_dock_widget.set_graph(instance.graph)
                instance.snaptree_dock_widget.snaptree_widget.focus_icfg(cfg_id)

        elif tag == 'SBSnapshot':
            snap_msg = cast(SnapshotServerToBinja, msg.get('snapshotMsg'))

            for instance in relevant_instances:
                if snap_msg['tag'] == 'BranchesOfClient':
                    for bpath, data in cast(ServerBranchesOfClient,
                                            snap_msg.get('branchesOfClient')):
                        if bpath == instance.bv_key:
                            instance.snaptree_dock_widget.snaptree_widget.update_branches_of_binary(
                                data)
                            break

                if snap_msg['tag'] == 'BranchesOfBinary':
                    if snap_msg.get('hostBinaryPath') == instance.bv_key:
                        instance.snaptree_dock_widget.snaptree_widget.update_branches_of_binary(
                            cast(List[Tuple[BranchId, ServerBranch]], snap_msg.get('branches')))

                if snap_msg['tag'] == 'DeleteSnapshotConfirmationRequest':
                    deleted_nodes = cast(List[CfgId], snap_msg.get('deletedNodes'))
                    will_whole_branch_be_deleted = cast(bool, snap_msg.get('willWholeBranchBeDeleted'))
                    snapshot_request_for_deletion = cast(CfgId, snap_msg.get('snapshotRequestedForDeletion'))
                    if len(deleted_nodes) == 0:
                        return
                    elif len(deleted_nodes) == 1:
                        msg = f"Are you sure you want to delete this snapshot?"
                    elif will_whole_branch_be_deleted:
                        msg = f"Delete the entire branch and its {len(deleted_nodes) - 1} child snapshots?"
                    elif len(deleted_nodes) > 1:
                        msg = f"Delete this snapshot and its {len(deleted_nodes) - 1} child snapshots?"

                    # TODO: add something 
                    confirm_delete_snapshots: Optional[MessageBoxButtonResult] = MessageBoxButtonResult(
                        show_message_box(
                            "Blaze",
                            msg,
                            buttons=MessageBoxButtonSet.YesNoButtonSet,
                            icon=MessageBoxIcon.WarningIcon))

                    if confirm_delete_snapshots:
                        snap_msg = SnapshotBinjaToServer(
                            tag='ConfirmDeleteSnapshot', cfgId=snapshot_request_for_deletion)
                        instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snap_msg))
                    else:
                        log.info("Snapshot deletion aborted.")
                        


        elif tag == 'SBPoi':
            poi_msg = cast(PoiServerToBinja, msg.get('poiMsg'))
            for instance in relevant_instances:
                instance.poi_list_dock_widget.handle_server_msg(poi_msg)

        else:
            log.error("Unknown message type: %r", tag)


class BlazeNotificationListener(UIContextNotification):
    # NOTE: We have to keep a reference around to the
    # `BlazeNotificationListener` instance, otherwise it will get garbage
    # collected and allocated over, even though `registerNotification` will have
    # kept a pointer to it, resulting in a segfault (or at the very least,
    # totally incorrect behavior) when any relevant notification fires
    instance: 'BlazeNotificationListener'

    def __init__(self, blaze_plugin: BlazePlugin):
        super().__init__()
        self.blaze_plugin: BlazePlugin = blaze_plugin

    def OnAfterCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None:
        bv = frame.getCurrentViewInterface().getData()

        log.debug(
            'BinaryView for %r closed',
            file.getFilename(),
            extra={
                'bv': bv,
                'bv_filename': file.getFilename()
            })

        instance = self.blaze_plugin._instance_by_bv[bv]
        del self.blaze_plugin._instance_by_bv[bv]
        self.blaze_plugin._instances_by_key[bv_key(bv)].discard(instance)

    def OnBeforeSaveFile(self, _context: UIContext, file: FileContext, frame: ViewFrame) -> bool:
        log.info("OnBeforeSaveFile called.")

        bv = frame.getCurrentViewInterface().getData()

        old_key = bv_key(file.getFilename())
        new_key = bv_key(bv)

        log.debug(
            'BinaryView for %r saved (new filename %r)',
            old_key,
            new_key,
            extra={
                'bv': bv,
                'old_key': old_key,
                'new_key': new_key,
            })

        instance = self.blaze_plugin._instance_by_bv[bv]
        self.blaze_plugin.move_instance(instance, old_key, new_key)

        return True


blaze = BlazePlugin()
BlazeNotificationListener.instance = BlazeNotificationListener(blaze)
UIContext.registerNotification(BlazeNotificationListener.instance)


class Action(str, enum.Enum):
    SAY_HELLO = r'Blaze\Say Hello'
    SEND_INSTRUCTION = r'Blaze\Send Instruction'
    TYPE_CHECK_FUNCTION = r'Blaze\Type Check Function'
    START_CFG = r'Blaze\Create ICFG'
    MARK_POI = r'Blaze\Mark POI'


@register_for_function(Action.START_CFG, 'Create ICFG')
def start_cfg(bv: BinaryView, func: binaryninja.Function):
    for instance in blaze.instances_by_key(bv_key(bv)):
        instance.icfg_dock_widget.icfg_widget.recenter_node_id = None

    blaze_instance = blaze.ensure_instance(bv)
    blaze_instance.with_bndb_hash(
        lambda h: blaze_instance.send(
            BinjaToServer(tag='BSCfgNew', startFuncAddress=func.start, bndbHash=h)))


@register_for_address(Action.MARK_POI, 'Mark POI')
def mark_poi(bv: BinaryView, addr: int):
    if funcs := get_functions_containing(bv, addr):
        # TODO: Decide how to handle multiple functions containing addr
        func = funcs[0]

        # Get constraint from user
        name_text_field = TextLineField('Name:')
        description_text_field = TextLineField('Description:')
        confirm: bool = get_form_input([name_text_field, description_text_field], 'Add POI')
        if not confirm:
            return
        poi_name: Optional[str] = name_text_field.result
        poi_description: Optional[str] = description_text_field.result

        poi_msg = PoiBinjaToServer(
            tag='AddPoi',
            funcAddr=func.start,
            instrAddr=addr,
            name=poi_name,
            description=poi_description,
        )
        blaze_instance = blaze.ensure_instance(bv)
        blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))
    else:
        log.warn(r'No function containing address: 0x%x', addr)


@register_for_function(Action.TYPE_CHECK_FUNCTION, 'Type Check Function')
def type_check_function(bv: BinaryView, func: binaryninja.Function):
    blaze_instance = blaze.ensure_instance(bv)
    blaze_instance.with_bndb_hash(
        lambda h: blaze_instance.send(
            BinjaToServer(tag='BSTypeCheckFunction', address=func.start, bndbHash=h)))
