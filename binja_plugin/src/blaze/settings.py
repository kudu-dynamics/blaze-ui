import enum
import getpass
import json
from typing import Any, Callable, List, Literal, OrderedDict, Sequence, Tuple, TypedDict, Union
from typing_extensions import Annotated
import uuid

from binaryninja.settings import Settings

__all__ = ['BlazeSettings']


class SettingMetadataRequired(TypedDict):
    title: str
    type: Literal['array', 'boolean', 'number', 'string']
    description: str


class SettingMetadata(SettingMetadataRequired, total=False):
    elementType: str
    enum: Sequence[str]
    enumDescriptions: Sequence[str]
    minValue: Union[int, float]
    maxValue: Union[int, float]
    precision: int
    # If default needs to be larger than 99 or smaller than 0, you MUST change minValue and/or maxValue
    default: Any
    aliases: Sequence[str]
    description: str
    ignore: Sequence[Literal['SettingsUserScope', 'SettingsProjectScope', 'SettingsResourceScope']]
    readOnly: bool
    optional: bool


class BlazeSettings:
    class Key(str, enum.Enum):
        HOST = 'blaze.server.host'
        WS_PORT = 'blaze.server.ws_port'
        HTTP_PORT = 'blaze.server.http_port'
        UPLOAD_ENABLED = 'blaze.upload_enabled'
        CLIENT_ID = 'blaze.client_id'

    _group_config: List[Tuple[Annotated[str, 'group'], Annotated[str, 'title']]] = [
        ('blaze', 'Blaze'),
    ]

    _settings_config: OrderedDict[Key, SettingMetadata] = OrderedDict(
        [
            (
                Key.HOST,
                SettingMetadata(
                    title='Blaze Host',
                    description='Hostname of Blaze server',
                    type='string',
                    default='localhost',
                    optional=False,
                )),
            (
                Key.WS_PORT,
                SettingMetadata(
                    title='Blaze WebSocket Port',
                    description='WebSocket port of Blaze Server',
                    type='number',
                    default=31337,
                    minValue=0,
                    maxValue=65335,
                    optional=False,
                )),
            (
                Key.HTTP_PORT,
                SettingMetadata(
                    title='Blaze HTTP Port',
                    description='HTTP port of Blaze Server',
                    type='number',
                    default=31338,
                    minValue=0,
                    maxValue=65335,
                    optional=False,
                )),
            (
                Key.UPLOAD_ENABLED,
                SettingMetadata(
                    title='Enable Automatic Upload',
                    description='Automatically upload BNDB to Blaze for immediate processing',
                    type='boolean',
                    default=False,
                    optional=False,
                )),
            (
                Key.CLIENT_ID,
                SettingMetadata(
                    title='Unique Client ID',
                    description=(
                        'ID used to distinguish multiple BinaryNinja instances connecting to the same '
                        'Blaze server. This ID is used to look up your snapshots, so changing it can '
                        'prevent you from accessing your existing snapshots'),
                    type='string',
                    default='',
                    optional=False,
                )),
        ])

    def __init__(self, settings_factory: Callable[[], Settings] = Settings):
        self._s = settings_factory

        for group, title in self._group_config:
            self._s().register_group(group=group, title=title)

        for key, metadata in self._settings_config.items():
            self._s().register_setting(key, json.dumps(metadata))

        if self.client_id == '':
            self.client_id = f'{getpass.getuser()}_{uuid.uuid4()}'

    @property
    def host(self):
        return self._s().get_string(self.Key.HOST)

    @host.setter
    def host(self, val):
        return self._s().set_string(self.Key.HOST, val)

    @property
    def ws_port(self):
        return self._s().get_string(self.Key.WS_PORT)

    @ws_port.setter
    def ws_port(self, val):
        return self._s().set_string(self.Key.WS_PORT, val)

    @property
    def http_port(self):
        return self._s().get_string(self.Key.HTTP_PORT)

    @http_port.setter
    def http_port(self, val):
        return self._s().set_string(self.Key.HTTP_PORT, val)

    @property
    def client_id(self):
        return self._s().get_string(self.Key.CLIENT_ID)

    @client_id.setter
    def client_id(self, val):
        return self._s().set_string(self.Key.CLIENT_ID, val)

    @property
    def upload_enabled(self):
        return self._s().get_string(self.Key.UPLOAD_ENABLED)

    @upload_enabled.setter
    def upload_enabled(self, val):
        return self._s().set_string(self.Key.UPLOAD_ENABLED, val)
