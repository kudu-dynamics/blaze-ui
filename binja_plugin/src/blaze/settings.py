import enum
import getpass
import json
import uuid
from typing import Any, Callable, List, Literal, Optional, OrderedDict, Sequence, Tuple, TypedDict, Union

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
        STRING_TRUNCATION_LENGTH = 'blaze.ICFG.string_truncation_length'

    # [(group, title), ...]
    _group_config: List[Tuple[str, str]] = [
        ('blaze', 'Blaze'),
    ]

    DEFAULT_HOST: str = 'localhost'
    DEFAULT_CLIENT_ID: str = ''

    _settings_config: OrderedDict[Key, SettingMetadata] = OrderedDict(
        [
            (
                Key.HOST,
                SettingMetadata(
                    title='Blaze Host',
                    description='Hostname of Blaze server',
                    type='string',
                    default=DEFAULT_HOST,
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
                    default=DEFAULT_CLIENT_ID,
                    optional=False,
                )),
            (
                Key.STRING_TRUNCATION_LENGTH,
                SettingMetadata(
                    title='String Constant Maximum Display Length',
                    description=(
                        'When displaying string constants, truncate strings longer than this. '
                        'Use 0 for no trucation'),
                    type='number',
                    default=30,
                    minValue=0,
                    maxValue=1000,
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
    def host(self) -> str:
        s = self._s().get_string(self.Key.HOST)
        assert isinstance(s, str)
        return s

    @host.setter
    def host(self, val: str) -> bool:
        return self._s().set_string(self.Key.HOST, val)

    @property
    def ws_port(self) -> int:
        return self._s().get_integer(self.Key.WS_PORT)

    @ws_port.setter
    def ws_port(self, val: int) -> bool:
        return self._s().set_integer(self.Key.WS_PORT, val)

    @property
    def http_port(self) -> int:
        return self._s().get_integer(self.Key.HTTP_PORT)

    @http_port.setter
    def http_port(self, val: int) -> bool:
        return self._s().set_integer(self.Key.HTTP_PORT, val)

    @property
    def client_id(self) -> str:
        s = self._s().get_string(self.Key.CLIENT_ID)
        assert isinstance(s, str)
        return s

    @client_id.setter
    def client_id(self, val: str) -> bool:
        return self._s().set_string(self.Key.CLIENT_ID, val)

    @property
    def upload_enabled(self) -> bool:
        return self._s().get_bool(self.Key.UPLOAD_ENABLED)

    @upload_enabled.setter
    def upload_enabled(self, val: bool) -> bool:
        return self._s().set_bool(self.Key.UPLOAD_ENABLED, val)

    @property
    def string_truncation_length(self) -> Optional[int]:
        return self._s().get_integer(self.Key.STRING_TRUNCATION_LENGTH) or None

    @string_truncation_length.setter
    def string_truncation_length(self, val: Optional[int]) -> bool:
        return self._s().set_integer(self.Key.STRING_TRUNCATION_LENGTH, val or 0)
