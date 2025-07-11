import json
from typing import Annotated, Literal, Optional, Union
from abc import ABC, abstractmethod
import sys

from pydantic import BaseModel, Field, StringConstraints

if sys.version_info < (3, 13):
    from deprecated import deprecated
else:
    from warnings import deprecated


ChatCommand = Union[
    "ShowActiveUser",
    "CreateActiveUser",
    "ListUsers",
    "APISetActiveUser",
    "SetActiveUser",
    "SetAllContactReceipts",
    "APISetUserContactReceipts",
    "SetUserContactReceipts",
    "APISetUserGroupReceipts",
    "SetUserGroupReceipts",
    "APIHideUser",
    "APIUnhideUser",
    "APIMuteUser",
    "APIUnmuteUser",
    "HideUser",
    "UnhideUser",
    "MuteUser",
    "UnmuteUser",
    "APIDeleteUser",
    "DeleteUser",
    "StartChat",
    "CheckChatRunning",
    "APIStopChat",
    "APIActivateChat",
    "APISuspendChat",
    "ResubscribeAllConnections",
    "SetTempFolder",
    "SetFilesFolder",
    "SetRemoteHostsFolder",
    "APISetAppFilePaths",
    "APISetEncryptLocalFiles",
    "SetContactMergeEnabled",
#if !defined(dbPostgres)
    "APIExportArchive",
    "ExportArchive",
    "APIImportArchive",
    "APIDeleteStorage",
    "APIStorageEncryption",
    "TestStorageEncryption",
    "SlowSQLQueries",
#endif
    "ExecChatStoreSQL",
    "ExecAgentStoreSQL",
    "APISaveAppSettings",
    "APIGetAppSettings",
    "APIGetChatTags",
    "APIGetChats",
    "APIGetChat",
    "APIGetChatItems",
    "APIGetChatItemInfo",
    "APISendMessages",
    "APICreateChatTag",
    "APISetChatTags",
    "APIDeleteChatTag",
    "APIUpdateChatTag",
    "APIReorderChatTags",
    "APICreateChatItems",
    "APIReportMessage",
    "ReportMessage",
    "APIUpdateChatItem",
    "APIDeleteChatItem",
    "APIDeleteMemberChatItem",
    "APIArchiveReceivedReports",
    "APIDeleteReceivedReports",
    "APIChatItemReaction",
    "APIGetReactionMembers",
    "APIPlanForwardChatItems",
    "APIForwardChatItems",
    "APIUserRead",
    "UserRead",
    "APIChatRead",
    "APIChatItemsRead",
    "APIChatUnread",
    "APIDeleteChat",
    "APIClearChat",
    "APIAcceptContact",
    "APIRejectContact",
    "APISendCallInvitation",
    "SendCallInvitation",
    "APIRejectCall",
    "APISendCallOffer",
    "APISendCallAnswer",
    "APISendCallExtraInfo",
    "APIEndCall",
    "APIGetCallInvitations",
    "APICallStatus",
    "APIGetNetworkStatuses",
    "APIUpdateProfile",
    "APISetContactPrefs",
    "APISetContactAlias",
    "APISetGroupAlias",
    "APISetConnectionAlias",
    "APISetUserUIThemes",
    "APISetChatUIThemes",
    "APIGetNtfToken",
    "APIRegisterToken",
    "APIVerifyToken",
    "APICheckToken",
    "APIDeleteToken",
    "APIGetNtfConns",
    "APIGetConnNtfMessages",
    "APIAddMember",
    "APIJoinGroup",
    "APIAcceptMember",
    "APIMembersRole",
    "APIBlockMembersForAll",
    "APIRemoveMembers",
    "APILeaveGroup",
    "APIListMembers",
    "APIUpdateGroupProfile",
    "APICreateGroupLink",
    "APIGroupLinkMemberRole",
    "APIDeleteGroupLink",
    "APIGetGroupLink",
    "APICreateMemberContact",
    "APISendMemberContactInvitation",
    "GetUserProtoServers",
    "SetUserProtoServers",
    "APITestProtoServer",
    "TestProtoServer",
    "APIGetServerOperators",
    "APISetServerOperators",
    "SetServerOperators",
    "APIGetUserServers",
    "APISetUserServers",
    "APIValidateServers",
    "APIGetUsageConditions",
    "APISetConditionsNotified",
    "APIAcceptConditions",
    "APISetChatItemTTL",
    "SetChatItemTTL",
    "APIGetChatItemTTL",
    "GetChatItemTTL",
    "APISetChatTTL",
    "SetChatTTL",
    "GetChatTTL",
    "APISetNetworkConfig",
    "APIGetNetworkConfig",
    "SetNetworkConfig",
    "APISetNetworkInfo",
    "ReconnectAllServers",
    "ReconnectServer",
    "APISetChatSettings",
    "APISetMemberSettings",
    "APIContactInfo",
    "APIGroupInfo",
    "APIGroupMemberInfo",
    "APIContactQueueInfo",
    "APIGroupMemberQueueInfo",
    "APISwitchContact",
    "APISwitchGroupMember",
    "APIAbortSwitchContact",
    "APIAbortSwitchGroupMember",
    "APISyncContactRatchet",
    "APISyncGroupMemberRatchet",
    "APIGetContactCode",
    "APIGetGroupMemberCode",
    "APIVerifyContact",
    "APIVerifyGroupMember",
    "APIEnableContact",
    "APIEnableGroupMember",
    "SetShowMessages",
    "SetSendReceipts",
    "SetShowMemberMessages",
    "ContactInfo",
    "ShowGroupInfo",
    "GroupMemberInfo",
    "ContactQueueInfo",
    "GroupMemberQueueInfo",
    "SwitchContact",
    "SwitchGroupMember",
    "AbortSwitchContact",
    "AbortSwitchGroupMember",
    "SyncContactRatchet",
    "SyncGroupMemberRatchet",
    "GetContactCode",
    "GetGroupMemberCode",
    "VerifyContact",
    "VerifyGroupMember",
    "EnableContact",
    "EnableGroupMember",
    "ChatHelp",
    "Welcome",
    "APIAddContact",
    "AddContact",
    "APISetConnectionIncognito",
    "APIChangeConnectionUser",
    "APIConnectPlan",
    "APIConnect",
    "Connect",
    "APIConnectContactViaAddress",
    "ConnectSimplex",
    "DeleteContact",
    "ClearContact",
    "APIListContacts",
    "ListContacts",
    "APICreateMyAddress",
    "CreateMyAddress",
    "APIDeleteMyAddress",
    "DeleteMyAddress",
    "APIShowMyAddress",
    "ShowMyAddress",
    "APISetProfileAddress",
    "SetProfileAddress",
    "APIAddressAutoAccept",
    "AddressAutoAccept",
    "AcceptContact",
    "RejectContact",
    "ForwardMessage",
    "ForwardGroupMessage",
    "ForwardLocalMessage",
    "SendMessage",
    "SendMemberContactMessage",
    "SendLiveMessage",
    "SendMessageQuote",
    "SendMessageBroadcast",
    "DeleteMessage",
    "DeleteMemberMessage",
    "EditMessage",
    "UpdateLiveMessage",
    "ReactToMessage",
    "APINewGroup",
    "NewGroup",
    "AddMember",
    "JoinGroup",
    "MemberRole",
    "BlockForAll",
    "RemoveMembers",
    "LeaveGroup",
    "DeleteGroup",
    "ClearGroup",
    "ListMembers",
    "APIListGroups",
    "ListGroups",
    "UpdateGroupNames",
    "ShowGroupProfile",
    "UpdateGroupDescription",
    "ShowGroupDescription",
    "CreateGroupLink",
    "GroupLinkMemberRole",
    "DeleteGroupLink",
    "ShowGroupLink",
    "SendGroupMessageQuote",
    "ClearNoteFolder",
    "LastChats",
    "LastMessages",
    "LastChatItemId",
    "ShowChatItem",
    "ShowChatItemInfo",
    "ShowLiveItems",
    "SendFile",
    "SendImage",
    "ForwardFile",
    "ForwardImage",
    "SendFileDescription",
    "ReceiveFile",
    "SetFileToReceive",
    "CancelFile",
    "FileStatus",
    "ShowProfile",
    "UpdateProfile",
    "UpdateProfileImage",
    "ShowProfileImage",
    "SetUserFeature",
    "SetContactFeature",
    "SetGroupFeature",
    "SetGroupFeatureRole",
    "SetUserTimedMessages",
    "SetContactTimedMessages",
    "SetGroupTimedMessages",
    "SetLocalDeviceName",
    "ListRemoteHosts",
    "StartRemoteHost",
    "SwitchRemoteHost",
    "StopRemoteHost",
    "DeleteRemoteHost",
    "StoreRemoteFile",
    "GetRemoteFile",
    "ConnectRemoteCtrl",
    "FindKnownRemoteCtrl",
    "ConfirmRemoteCtrl",
    "VerifyRemoteCtrlSession",
    "ListRemoteCtrls",
    "StopRemoteCtrl",
    "DeleteRemoteCtrl",
    "APIUploadStandaloneFile",
    "APIDownloadStandaloneFile",
    "APIStandaloneFileInfo",
    "QuitChat",
    "ShowVersion",
    "DebugLocks",
    "DebugEvent",
    "GetAgentSubsTotal",
    "GetAgentServersSummary",
    "ResetAgentServersStats",
    "GetAgentSubs",
    "GetAgentSubsDetails",
    "GetAgentWorkers",
    "GetAgentWorkersDetails",
    "GetAgentQueuesInfo",
    # The parser will return this command for strings that start from "//".
    # This command should be processed in preCmdHook
    "CustomChatCommand",
]


UserId = int
# TODO validate UserName
# must not start with #, @, ', or a character with value <0x20
# Must EITHER not contain whitespace or commas, OR not contain ' (OR both) (quoting concerns)
UserName = str
UserPwd = str
FilePath = str
ChatTagId = int
GroupId = int
# TODO make ChatRef a struct of ChatType and id?
ChatRef = Annotated[str, StringConstraints(pattern=r"^[@#*:]\d+$")]
ChatItemId = int
IncognitoEnabled = bool
ContactId = int
LocalAlias = str
GroupMemberRole = Literal["owner", "admin", "moderator", "member", "observer"]
GroupMemberId = int
GroupName = str
ContactName = str
CreateShortLink = bool
FileTransferId = int
ImageData = str  # TODO data:image/(png|jpg);base64,{valid base64}
RemoteHostId = int
RemoteCtrlId = int
CbNonce = str
# Doesn't exist in Haskell
VerifyCode = Annotated[str, StringConstraints(pattern=r"^[^\d ]$")]

CallMedia = Literal["audio", "video"]

class CallCapabilities(BaseModel):
    encryption: bool

class CallType(BaseModel):
    media: CallMedia
    capabilities: CallCapabilities

class UserMsgReceiptSettings(BaseModel):
    enable: bool
    clear_overrides: bool = Field(..., alias="clearOverrides")

    def __str__(self) -> str:
        return f"{to_on_off(self.enable)} clear_overrides={self.clear_overrides}"

class AppFilePathsConfig(BaseModel):
    files_folder: FilePath = Field(..., alias="appFilesFolder")
    temp_folder: FilePath = Field(..., alias="appTempFolder")
    assets_folder: FilePath = Field(..., alias="appAssetsFolder")
    remote_hosts_folder: Optional[FilePath] = Field(..., alias="appRemoteHostsFolder")

class ArchiveConfig(BaseModel):
    archive_path: FilePath = Field(..., alias="archivePath")
    disable_compression: Optional[bool] = Field(..., alias="disableCompression")
    parent_temp_directory: Optional[FilePath] = Field(..., alias="parentTempDirectory")

DBEncryptionKey = str

class DBEncryptionConfig(BaseModel):
    current_key: DBEncryptionKey = Field(..., alias="currentKey")
    new_key: DBEncryptionKey = Field(..., alias="newKey")
    keep_key: Optional[bool] = Field(..., alias="keepKey")

SocksMode = Literal["always", "onion"]
HostMode = Literal["onionViaSocks", "onion", "public"]
TransportSessionMode = Literal["user", "session", "server", "entity"]
SMPProxyMode = Literal["always", "unknown", "unprotected", "never"]
SMPProxyFallback = Literal["allow", "allowProtected", "prohibited"]
SMPWebPortServers = Literal["all", "preset", "off"]

# class NetworkConfig(BaseModel):
#     socksProxy: Optional[SocksProxyWithAuth]
#     socksMode: SocksMode
#     hostMode: HostMode
#     requiredHostMode: bool
#     sessionMode: TransportSessionMode
#     smpProxyMode: SMPProxyMode
#     smpProxyFallback: SMPProxyFallback
#     smpWebPortServers: SMPWebPortServers
#     tcpConnectTimeout: int
#     tcpTimeout: int
#     tcpTimeoutPerKb: int
#     rcvConcurrency: int
#     tcpKeepAlive: Optional[KeepAliveOpts]
#     smpPingInterval: int
#     smpPingCount: int
#     logTLSErrors: bool


# class AppSettings(BaseModel):
#     appPlatform: Optional[AppPlatform]
#     networkConfig: Optional[NetworkConfig]
#     networkProxy: Optional[NetworkProxy]
#     privacyEncryptLocalFiles: Optional[bool]
#     privacyAskToApproveRelays: Optional[bool]
#     privacyAcceptImages: Optional[bool]
#     privacyLinkPreviews: Optional[bool]
#     privacyShowChatPreviews: Optional[bool]
#     privacySaveLastDraft: Optional[bool]
#     privacyProtectScreen: Optional[bool]
#     privacyMediaBlurRadius: Optional[int]
#     notificationMode: Optional[NotificationMode]
#     notificationPreviewMode: Optional[NotificationPreviewMode]
#     webrtcPolicyRelay: Optional[bool]
#     webrtcICEServers: Optional[list[str]]
#     confirmRemoteSessions: Optional[bool]
#     connectRemoteViaMulticast: Optional[bool]
#     connectRemoteViaMulticastAuto: Optional[bool]
#     developerTools: Optional[bool]
#     confirmDBUpgrades: Optional[bool]
#     androidCallOnLockScreen: Optional[LockScreenCalls]
#     iosCallKitEnabled: Optional[bool]
#     iosCallKitCallsInRecents: Optional[bool]
#     uiProfileImageCornerRadius: Optional[float]
#     uiChatItemRoundness: Optional[float]
#     uiChatItemTail: Optional[bool]
#     uiColorScheme: Optional[UIColorScheme]
#     uiDarkColorScheme: Optional[DarkColorScheme]
#     uiCurrentThemeIds: Optional[(Map ThemeColorScheme Text)]
#     uiThemes: Optional[list[UITheme]]
#     oneHandUI: Optional[bool]
#     chatBottomBar: Optional[bool]

ChatType = Literal["direct", "group", "local", "contactRequest", "contactConnection"]

class ChatName(BaseModel):
    chatType: ChatType
    chatName: str

    def __str__(self) -> str:
        if self.chatType == "direct":               t = "@"
        elif self.chatType == "group":              t = "#"
        elif self.chatType == "local":              t = "*"
        elif self.chatType == "contactConnection":  t = ":"
        elif self.chatType == "group":              t = "#"
        else:
            # TODO contactRequest unreachable(?)
            raise ValueError(f"Illegal chat type: {self.chatType}")
        name = quote_display_name(self.chatName)

        return t + name

SbKey = str

class CryptoFileArgs(BaseModel):
    fileKey: SbKey
    fileNonce: CbNonce

class CryptoFile(BaseModel):
    filePath: FilePath
    cryptoArgs: Optional[CryptoFileArgs]

    def __str__(self) -> str:
        if self.cryptoArgs is not None:
            args_part = f" key={self.cryptoArgs.fileKey} nonce={self.cryptoArgs.fileKey}"
        else:
            args_part = ""

        return f"{args_part}{self.filePath}"

class ChatDeleteMode(BaseModel):
    mode: Literal["full", "entity", "messages"]
    notify: Optional[bool]

    def __str__(self) -> str:
        assert (self.mode == "messages") == (self.notify is None)
        notify_part = (" notify=" + to_on_off(self.notify)) if self.notify is not None else ""
        return f" {self.mode}{notify_part}"

class WebRTCSession(BaseModel):
    rtcSession: str
    rtcIceCandidates: str

class WebRTCCallOffer(BaseModel):
    callType: CallType
    rtcSession: WebRTCSession

class WebRTCExtraInfo(BaseModel):
    rtcIceCandidates: str

WebRTCCallStatus = Literal["connecting", "connected", "disconnected", "failed"]

FeatureAllowed = Literal["always", "yes", "no"]

class TimedMessagesPreference(BaseModel):
    allow: FeatureAllowed
    ttl: Optional[int]
class FullDeletePreference(BaseModel):
    allow: FeatureAllowed
class ReactionsPreference(BaseModel):
    allow: FeatureAllowed
class VoicePreference(BaseModel):
    allow: FeatureAllowed
class CallsPreference(BaseModel):
    allow: FeatureAllowed

class Preferences(BaseModel):
    timedMessages: Optional[TimedMessagesPreference]
    fullDelete: Optional[FullDeletePreference]
    reactions: Optional[ReactionsPreference]
    voice: Optional[VoicePreference]
    calls: Optional[CallsPreference]

UIColorMode = Literal["light", "dark"]
UIColor = str

class UIColors(BaseModel):
    accent: Optional[UIColor]
    accentVariant: Optional[UIColor]
    secondary: Optional[UIColor]
    secondaryVariant: Optional[UIColor]
    background: Optional[UIColor]
    menus: Optional[UIColor]
    title: Optional[UIColor]
    accentVariant2: Optional[UIColor]
    sentMessage: Optional[UIColor]
    sentReply: Optional[UIColor]
    receivedMessage: Optional[UIColor]
    receivedReply: Optional[UIColor]

ChatWallpaperScale = Literal["fill", "fit", "repeat"]

class ChatWallpaper(BaseModel):
    preset: Optional[str]
    imageFile: Optional[FilePath]
    background: Optional[UIColor]
    tint: Optional[UIColor]
    scaleType: Optional[ChatWallpaperScale]
    scale: Optional[float]

class UIThemeEntityOverride(BaseModel):
    mode: UIColorMode
    wallpaper: Optional[ChatWallpaper]
    colors: UIColors

class UIThemeEntityOverrides(BaseModel):
    light: Optional[UIThemeEntityOverride]
    dark: Optional[UIThemeEntityOverride]

def quote_display_name(name: str) -> str:
    # TODO address minor difference between Haskell isSpace and python str.isspace
    if all(not c.isspace() for c in name) and "," not in name:
        return name
    elif "'" not in name:
        return "'" + name + "'"
    else:
        raise ValueError(f"Invalid UserName: {name}")

def to_on_off(b: bool) -> str:
    return "on" if b else "off"

def quote_msg(msg: str) -> str:
    if ")" in msg:
        raise ValueError(f"Invalid quoted message: {msg}")
    return "(" + msg + ")"

# -------------------------------------------------------------

class BaseChatCommand(BaseModel, ABC):
    @abstractmethod
    def __str__(self) -> str: ...


class ShowActiveUser(BaseChatCommand):
    def __str__(self) -> str: return "/user"

class ListUsers(BaseChatCommand):
    def __str__(self) -> str: return "/users"

class APISetActiveUser(BaseChatCommand):
    user_id: UserId
    user_pwd: Optional[UserPwd]

    def __str__(self) -> str:
        cmd = f"/_user {self.user_id}"
        if self.user_pwd is not None:
            cmd += " " + json.dumps(self.user_pwd)
        return cmd

class SetActiveUser(BaseChatCommand):
    user_name: UserName
    user_pwd: Optional[UserPwd]

    def __str__(self) -> str:
        cmd = f"/user {quote_display_name(self.user_name)}"
        if self.user_pwd is not None:
            cmd += " " + json.dumps(self.user_pwd)
        return cmd

class SetAllContactReceipts(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/set receipts all {to_on_off(self.on_or_off)}"

class APISetUserContactReceipts(BaseChatCommand):
    user_id: UserId
    settings: UserMsgReceiptSettings

    def __str__(self) -> str:
        return f"/_set receipts contacts {self.user_id} {self.settings}"

class SetUserContactReceipts(BaseChatCommand):
    settings: UserMsgReceiptSettings

    def __str__(self) -> str:
        return f"/set receipts contacts {self.settings}"

class APISetUserGroupReceipts(BaseChatCommand):
    user_id: UserId
    settings: UserMsgReceiptSettings

    def __str__(self) -> str:
        return f"/_set receipts groups {self.user_id} {self.settings}"

class SetUserGroupReceipts(BaseChatCommand):
    settings: UserMsgReceiptSettings

    def __str__(self) -> str:
        return f"/set receipts groups {self.settings}"

class APIHideUser(BaseChatCommand):
    user_id: UserId
    user_pwd: UserPwd

    def __str__(self) -> str:
        return f"/_hide user {self.user_id} {json.dumps(self.user_pwd)}"

class APIUnhideUser(BaseChatCommand):
    user_id: UserId
    user_pwd: UserPwd

    def __str__(self) -> str:
        return f"/_unhide user {self.user_id} {json.dumps(self.user_pwd)}"

class APIMuteUser(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_mute user {self.user_id}"

class APIUnmuteUser(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_unmute user {self.user_id}"

class HideUser(BaseChatCommand):
    user_pwd: UserPwd

    def __str__(self) -> str:
        return f"/hide user {json.dumps(self.user_pwd)}"

class UnhideUser(BaseChatCommand):
    user_pwd: UserPwd

    def __str__(self) -> str:
        return f"/unhide user {json.dumps(self.user_pwd)}"

class MuteUser(BaseChatCommand):
    def __str__(self) -> str: return "/mute user"

class UnmuteUser(BaseChatCommand):
    def __str__(self) -> str: return "/unmute user"

class APIDeleteUser(BaseChatCommand):
    user_id: UserId
    delete_smp_queues: bool
    user_pwd: Optional[UserPwd]

    def __str__(self) -> str:
        cmd = f"/_delete user {self.user_id} del_smp={to_on_off(self.delete_smp_queues)}"
        if self.user_pwd is not None:
            cmd += " " + json.dumps(self.user_pwd)
        return cmd

class DeleteUser(BaseChatCommand):
    user_name: UserName
    # Always true
    # delete_smp_queues: bool = True
    user_pwd: Optional[UserPwd]

    def __str__(self) -> str:
        cmd = f"/delete user {quote_display_name(self.user_name)}"
        if self.user_pwd is not None:
            cmd += " " + json.dumps(self.user_pwd)
        return cmd

class StartChat(BaseChatCommand):
    main_app: bool
    enable_snd_files: bool

    def __str__(self) -> str:
        main = to_on_off(self.main_app)
        snd_files = to_on_off(self.enable_snd_files)
        return f"_start main={main} snd_files={snd_files}"

class CheckChatRunning(BaseChatCommand):
    def __str__(self) -> str: return "/_check running"

class APIStopChat(BaseChatCommand):
    def __str__(self) -> str: return "/_stop"

class APIActivateChat(BaseChatCommand):
    restore_chat: bool

    def __str__(self) -> str:
        return f"/_app activate restore={to_on_off(self.restore_chat)}"

class APISuspendChat(BaseChatCommand):
    suspend_timeout: int

    def __str__(self) -> str:
        return f"/_app suspend {self.suspend_timeout}"

class ResubscribeAllConnections(BaseChatCommand):
    def __str__(self) -> str: return "/_resubscribe all"

@deprecated("Use APISetAppFilePaths instead")
class SetTempFolder(BaseChatCommand):
    path: FilePath

    def __str__(self) -> str:
        return f"/_temp_folder {self.path}"

@deprecated("Use APISetAppFilePaths instead")
class SetFilesFolder(BaseChatCommand):
    path: FilePath

    def __str__(self) -> str:
        return f"/files_folder {self.path}"

@deprecated("Use APISetAppFilePaths instead")
class SetRemoteHostsFolder(BaseChatCommand):
    path: FilePath

    def __str__(self) -> str:
        return f"/remote_hosts_folder {self.path}"

class APISetAppFilePaths(BaseChatCommand):
    config: AppFilePathsConfig

    def __str__(self) -> str:
        return f"/set file paths {self.config.model_dump_json()}"

class APISetEncryptLocalFiles(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/_files_encrypt {to_on_off(self.on_or_off)}"

class SetContactMergeEnabled(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/contact_merge {to_on_off(self.on_or_off)}"

class APIExportArchive(BaseChatCommand):
    config: ArchiveConfig

    def __str__(self) -> str:
        return f"/_db export {self.config.model_dump_json()}"

class ExportArchive(BaseChatCommand):
    def __str__(self) -> str: return "/db export"

class APIImportArchive(BaseChatCommand):
    config: ArchiveConfig

    def __str__(self) -> str:
        return f"/_db import {self.config.model_dump_json()}"

class APIDeleteStorage(BaseChatCommand):
    def __str__(self) -> str: return "/_db delete"

class APIStorageEncryption(BaseChatCommand):
    config: DBEncryptionConfig

    def __str__(self) -> str:
        return f"/_db encryption {self.config.model_dump_json()}"

class TestStorageEncryption(BaseChatCommand):
    key: DBEncryptionKey

    def __str__(self) -> str:
        return f"/db test key {self.key}"

class SlowSQLQueries(BaseChatCommand):
    def __str__(self) -> str: return "/sql slow"

class ExecChatStoreSQL(BaseChatCommand):
    query: str

    def __str__(self) -> str:
        return f"/sql chat {self.query}"

class ExecAgentStoreSQL(BaseChatCommand):
    query: str

    def __str__(self) -> str:
        return f"/sql agent {self.query}"

class APIGetChatTags(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_get tags {self.user_id}"

class APIGetChatItemInfo(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: ChatItemId

    def __str__(self) -> str:
        return f"/_get item info {self.chat_ref} {self.chat_item_id}"

class APIDeleteChatTag(BaseChatCommand):
    chat_tag_id: ChatTagId

    def __str__(self) -> str:
        return f"/_delete tag {self.chat_tag_id}"

class APIArchiveReceivedReports(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_archive reports #{self.group_id}"

class APIUserRead(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_read user {self.user_id}"

class UserRead(BaseChatCommand):
    def __str__(self) -> str: return "/read user"

class APIChatRead(BaseChatCommand):
    chat_ref: ChatRef

    def __str__(self) -> str:
        return f"/_read chat {self.chat_ref}"

class APIChatUnread(BaseChatCommand):
    chat_ref: ChatRef
    on_or_off: bool

    def __str__(self) -> str:
        return f"/_unread chat {self.chat_ref} {to_on_off(self.on_or_off)}"

class APIDeleteChat(BaseChatCommand):
    chat_ref: ChatRef
    mode: ChatDeleteMode

    def __str__(self) -> str:
        return f"/_delete {self.chat_ref}{self.mode}"

class APIClearChat(BaseChatCommand):
    chat_ref: ChatRef

    def __str__(self) -> str:
        return f"/_clear chat {self.chat_ref}"

class APIAcceptContact(BaseChatCommand):
    incognito: IncognitoEnabled
    conn_req_id: int

    def __str__(self) -> str:
        return f"/_accept incognito={to_on_off(self.incognito)} {self.conn_req_id}"

class APIRejectContact(BaseChatCommand):
    incognito: IncognitoEnabled
    conn_req_id: int

    def __str__(self) -> str:
        return f"/_reject {self.conn_req_id}"

class APISendCallInvitation(BaseChatCommand):
    contact_id: ContactId
    call_type: CallType

    def __str__(self) -> str:
        return f"/_call invite @{self.contact_id} {self.call_type.model_dump_json()}"

class SendCallInvitation(BaseChatCommand):
    contact_name: ContactName
    # Always type=video encrypted=true
    # call_type: CallType

    def __str__(self) -> str:
        return f"/call @{quote_display_name(self.contact_name)}"

class APIRejectCall(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_call reject @{self.contact_id}"

class APISendCallOffer(BaseChatCommand):
    contact_id: ContactId
    offer: WebRTCCallOffer

    def __str__(self) -> str:
        return f"/_call offer @{self.contact_id} {self.offer.model_dump_json()}"

class APISendCallAnswer(BaseChatCommand):
    contact_id: ContactId
    session: WebRTCSession

    def __str__(self) -> str:
        return f"/_call answer @{self.contact_id} {self.session.model_dump_json()}"

class APISendCallExtraInfo(BaseChatCommand):
    contact_id: ContactId
    extra_info: WebRTCExtraInfo

    def __str__(self) -> str:
        return f"/_call extra @{self.contact_id} {self.extra_info.model_dump_json()}"

class APIEndCall(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_call end @{self.contact_id}"

class APIGetCallInvitations(BaseChatCommand):
    def __str__(self) -> str: return "/_call get"

class APICallStatus(BaseChatCommand):
    contact_id: ContactId
    status: WebRTCCallStatus

    def __str__(self) -> str:
        return f"/_call status @{self.contact_id} {self.status}"

class APIGetNetworkStatuses(BaseChatCommand):
    def __str__(self) -> str: return "/_network_statuses"

class APISetContactPrefs(BaseChatCommand):
    contact_id: ContactId
    preferences: Preferences

    def __str__(self) -> str:
        return f"/_set prefs @{self.contact_id} {self.preferences.model_dump_json()}"

class APISetContactAlias(BaseChatCommand):
    contact_id: ContactId
    local_alias: LocalAlias

    def __str__(self) -> str:
        alias_part = (" " + self.local_alias) if self.local_alias else ""
        return f"/_set alias @{self.contact_id}" + alias_part

class APISetGroupAlias(BaseChatCommand):
    group_id: GroupId
    local_alias: LocalAlias

    def __str__(self) -> str:
        alias_part = (" " + self.local_alias) if self.local_alias else ""
        return f"/_set alias #{self.group_id}" + alias_part

class APISetConnectionAlias(BaseChatCommand):
    connection_id: int
    local_alias: LocalAlias

    def __str__(self) -> str:
        alias_part = (" " + self.local_alias) if self.local_alias else ""
        return f"/_set alias :{self.connection_id}" + alias_part

class APISetUserUIThemes(BaseChatCommand):
    user_id: UserId
    themes: Optional[UIThemeEntityOverrides]

    def __str__(self) -> str:
        themes_part = self.themes.model_dump_json() if self.themes is not None else ""
        return f"/_set theme user {self.user_id}{themes_part}"

class APISetChatUIThemes(BaseChatCommand):
    chat_ref: ChatRef
    themes: Optional[UIThemeEntityOverrides]

    def __str__(self) -> str:
        themes_part = self.themes.model_dump_json() if self.themes is not None else ""
        return f"/_set theme user {self.chat_ref}{themes_part}"

class APIGetNtfToken(BaseChatCommand):
    def __str__(self) -> str: return "/_ntf get"

class APIGetNtfConns(BaseChatCommand):
    nonce: CbNonce
    enc_ntf_info: str

    def __str__(self) -> str:
        return f"/_ntf conns {self.nonce} {self.enc_ntf_info}"

class APIAddMember(BaseChatCommand):
    group_id: GroupId
    contact_id: ContactId
    role: GroupMemberRole

    def __str__(self) -> str:
        return f"/_add #{self.group_id} {self.contact_id} {self.role}"

class APIAcceptMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    role: GroupMemberRole

    def __str__(self) -> str:
        return f"/_accept member #{self.group_id} {self.member_id} {self.role}"

class APILeaveGroup(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_leave #{self.group_id}"

class APIListMembers(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_members #{self.group_id}"

class APICreateGroupLink(BaseChatCommand):
    group_id: GroupId
    role: GroupMemberRole
    short: CreateShortLink

    def __str__(self) -> str:
        return f"/_create link #{self.group_id} {self.role} short={to_on_off(self.short)}"

class APIGroupLinkMemberRole(BaseChatCommand):
    group_id: GroupId
    role: GroupMemberRole

    def __str__(self) -> str:
        return f"/_set link role #{self.group_id} {self.role}"

class APIDeleteGroupLink(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_delete link #{self.group_id}"

class APIGetGroupLink(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_delete link #{self.group_id}"

class APICreateMemberContact(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_create member contact #{self.group_id} {self.member_id}"

class APIGetServerOperators(BaseChatCommand):
    def __str__(self) -> str: return "/_operators"

class APIGetUserServers(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_servers {self.user_id}"

class APIGetUsageConditions(BaseChatCommand):
    def __str__(self) -> str: return "/_conditions"

class APISetConditionsNotified(BaseChatCommand):
    condition_id: int

    def __str__(self) -> str:
        return f"/_conditions_notified {self.condition_id}"

class APISetChatItemTTL(BaseChatCommand):
    user_id: UserId
    new_ttl: int

    def __str__(self) -> str:
        return f"/_ttl {self.user_id} {self.new_ttl}"

class SetChatItemTTL(BaseChatCommand):
    new_ttl: Literal["day", "week", "month", "year", "none"]

    def __str__(self) -> str:
        return f"/ttl {self.new_ttl}"

class APIGetChatItemTTL(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_ttl {self.user_id}"

class GetChatItemTTL(BaseChatCommand):
    def __str__(self) -> str: return "/ttl"

class APISetChatTTL(BaseChatCommand):
    user_id: UserId
    chat_ref: ChatRef
    new_ttl: Optional[int]

    def __str__(self) -> str:
        ttl = "default" if self.new_ttl is None else str(self.new_ttl)
        return f"/_ttl {self.user_id} {self.chat_ref} {ttl}"

class APIGetNetworkConfig(BaseChatCommand):
    def __str__(self) -> str: return "/network"

class ReconnectAllServers(BaseChatCommand):
    def __str__(self) -> str: return "/reconnect"

class APIContactInfo(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_info @{self.contact_id}"

class APIGroupInfo(BaseChatCommand):
    group_id: GroupId

    def __str__(self) -> str:
        return f"/_info #{self.group_id}"

class APIGroupMemberInfo(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_info #{self.group_id} {self.member_id}"

class APIContactQueueInfo(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_queue info @{self.contact_id}"

class APIGroupMemberQueueInfo(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_queue info #{self.group_id} {self.member_id}"

class APISwitchContact(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_switch @{self.contact_id}"

class APISwitchGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_switch #{self.group_id} {self.member_id}"

class APIAbortSwitchContact(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_abort switch @{self.contact_id}"

class APIAbortSwitchGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_abort switch #{self.group_id} {self.member_id}"

class APISyncContactRatchet(BaseChatCommand):
    contact_id: ContactId
    force: bool

    def __str__(self) -> str:
        force_part = " force=on" if self.force else ""
        return f"/_sync @{self.contact_id}" + force_part

class APISyncGroupMemberRatchet(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    force: bool

    def __str__(self) -> str:
        force_part = " force=on" if self.force else ""
        return f"/_sync #{self.group_id} {self.member_id}" + force_part

class APIGetContactCode(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_get code @{self.contact_id}"

class APIGetGroupMemberCode(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_get code #{self.group_id} {self.member_id}"

class APIVerifyContact(BaseChatCommand):
    contact_id: ContactId
    verify_code: VerifyCode

    def __str__(self) -> str:
        code_part = (" " + self.verify_code) if self.verify_code is not None else ""
        return f"/_verify code @{self.contact_id}" + code_part

class APIVerifyGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    verify_code: VerifyCode

    def __str__(self) -> str:
        code_part = (" " + self.verify_code) if self.verify_code is not None else ""
        return f"/_verify code #{self.group_id} {self.member_id}" + code_part

class APIEnableContact(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_enable @{self.contact_id}"

class APIEnableGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_enable #{self.group_id} {self.member_id}"

class SetShowMemberMessages(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    on_or_off: bool

    def __str__(self) -> str:
        name = "unblock" if self.on_or_off else "block"
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/{name} #{group} @{contact}"

class ContactInfo(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/info @{quote_display_name(self.contact_name)}"

class ShowGroupInfo(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/info #{quote_display_name(self.group_name)}"

class GroupMemberInfo(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/info #{group} @{contact}"

class ContactQueueInfo(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/queue info @{quote_display_name(self.contact_name)}"

class GroupMemberQueueInfo(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/queue info #{group} @{contact}"

class SwitchContact(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/switch @{quote_display_name(self.contact_name)}"

class SwitchGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/switch #{group} @{contact}"

class AbortSwitchContact(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/abort switch @{quote_display_name(self.contact_name)}"

class AbortSwitchGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/abort switch #{group} @{contact}"

class SyncContactRatchet(BaseChatCommand):
    contact_name: ContactName
    force: bool

    def __str__(self) -> str:
        force_part = " force=on" if self.force else ""

        return f"/sync @{quote_display_name(self.contact_name)}" + force_part

class SyncGroupMemberRatchet(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    force: bool

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)
        force_part = " force=on" if self.force else ""

        return f"/sync #{group} @{contact}" + force_part

class GetContactCode(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/code @{quote_display_name(self.contact_name)}"

class GetGroupMemberCode(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/code #{group} @{contact}"

class VerifyContact(BaseChatCommand):
    contact_name: ContactName
    verify_code: VerifyCode

    def __str__(self) -> str:
        code_part = (" " + self.verify_code) if self.verify_code is not None else ""

        return f"/code @{quote_display_name(self.contact_name)}" + code_part

class VerifyGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    verify_code: VerifyCode

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)
        code_part = (" " + self.verify_code) if self.verify_code is not None else ""

        return f"/code #{group} @{contact}" + code_part

class EnableContact(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/enable @{quote_display_name(self.contact_name)}"

class EnableGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/enable #{group} @{contact}"

class ChatHelp(BaseChatCommand):
    help_section: Optional[Literal[
        "files",
        "groups",
        "contacts",
        "address",
        "incognito",
        "markdown",
        "messages",
        "remote",
        "settings",
        "db",
    ]]

    def __str__(self) -> str:
        if self.help_section is None:
            return "/help"
        elif self.help_section == "markdown":
            return "/markdown"
        elif self.help_section == "incognito":
            return "/incognito"
        else:
            return f"/help {self.help_section}"

class Welcome(BaseChatCommand):
    def __str__(self) -> str: return "/welcome"

class APIAddContact(BaseChatCommand):
    user_id: UserId
    short: CreateShortLink
    incognito: IncognitoEnabled

    def __str__(self) -> str:
        short = " short" if self.short else ""
        incognito = " incognito" if self.incognito else ""

        return f"/_connect {self.user_id} {short} {incognito}"

class AddContact(BaseChatCommand):
    short: CreateShortLink
    incognito: IncognitoEnabled

    def __str__(self) -> str:
        short = " short" if self.short else ""
        incognito = " incognito" if self.incognito else ""

        return f"/connect {short} {incognito}"

class APISetConnectionIncognito(BaseChatCommand):
    connection_id: int
    incognito: IncognitoEnabled

    def __str__(self) -> str:
        return f"/_set incognito :{self.connection_id} {to_on_off(self.incognito)}"

class APIChangeConnectionUser(BaseChatCommand):
    connection_id: int
    new_user_id: UserId

    def __str__(self) -> str:
        return f"/_set conn user :{self.connection_id} {self.new_user_id}"

class APIConnectContactViaAddress(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_connect contact {self.user_id} incognito={to_on_off(self.incognito)} {self.contact_id}"

class ConnectSimplex(BaseChatCommand):
    incognito: IncognitoEnabled

    def __str__(self) -> str:
        incognito = " incognito" if self.incognito else ""
        return "/simple" + incognito

class ClearContact(BaseChatCommand):
    contact_name: ContactName

    def __str__(self) -> str:
        return f"/clear @{quote_display_name(self.contact_name)}"

class APIListContacts(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_contacts {self.user_id}"

class ListContacts(BaseChatCommand):
    def __str__(self) -> str: return "/contacts"

class APICreateMyAddress(BaseChatCommand):
    user_id: UserId
    short: CreateShortLink

    def __str__(self) -> str:
        return f"/_address {self.user_id} short={to_on_off(self.short)}"

class CreateMyAddress(BaseChatCommand):
    short: CreateShortLink

    def __str__(self) -> str:
        short = " short" if self.short else ""

        return "/address" + short

class APIDeleteMyAddress(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_delete_address {self.user_id}"

class DeleteMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/delete_address"

class APIShowMyAddress(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_show_address {self.user_id}"

class ShowMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/show_address"

class APISetProfileAddress(BaseChatCommand):
    user_id: UserId
    enabled: bool

    def __str__(self) -> str:
        return f"/_profile_address {self.user_id} {to_on_off(self.enabled)}"

class SetProfileAddress(BaseChatCommand):
    enabled: bool

    def __str__(self) -> str:
        return f"/profile_address {to_on_off(self.enabled)}"

class AcceptContact(BaseChatCommand):
    incognito: IncognitoEnabled
    contact_name: ContactName

    def __str__(self) -> str:
        incognito = " incognito" if self.incognito else ""
        return f"/accept{incognito} @{quote_display_name(self.contact_name)}"

class SendMemberContactMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName  # TODO consistently change to member_name?
    msg: str

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)
        msg = json.dumps(self.msg)

        return f"@#{group} @{contact} {msg}"

class DeleteMemberMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    deleted_msg: str

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)
        msg = self.deleted_msg

        return f"\\\\#{group} @{contact} {msg}"

class AddMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    role: GroupMemberRole

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/add #{group} @{contact} {self.role}"

class MemberRole(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    role: GroupMemberRole

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/member role #{group} @{contact} {self.role}"

class BlockForAll(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    blocked: bool

    def __str__(self) -> str:
        name = "block" if self.blocked else "unblock"
        group = quote_display_name(self.group_name)
        contact = quote_display_name(self.contact_name)

        return f"/{name} for all #{group} @{contact}"

class LeaveGroup(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/leave #{self.group_name}"

class DeleteGroup(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/delete #{self.group_name}"

class ClearGroup(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/clear #{self.group_name}"

class ListMembers(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/members #{self.group_name}"

class APIListGroups(BaseChatCommand):
    user_id: UserId
    contact_id: Optional[ContactId]
    search: Optional[str]

    def __str__(self) -> str:
        # TODO file issue: no space between _groups and id
        # also, what if search begins with @?
        contact = f" @{self.contact_id}" if self.contact_id is not None else ""
        search = (" " + self.search) if self.search is not None else ""

        return f"/_groups{self.user_id}{contact}{search}"

class ListGroups(BaseChatCommand):
    contact_name: Optional[ContactName]
    search: Optional[str]

    def __str__(self) -> str:
        contact = f" @{quote_display_name(self.contact_name)}" if self.contact_name is not None else ""
        search = (" " + self.search) if self.search is not None else ""

        return f"/groups{contact}{search}"

class ShowGroupProfile(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/group_profile #{quote_display_name(self.group_name)}"

class UpdateGroupDescription(BaseChatCommand):
    group_name: GroupName
    description: Optional[str]

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        if self.description is not None:
            return f"/set welcome #{group} {json.dumps(self.description)}"
        else:
            return f"/delete welcome #{group}"

class ShowGroupDescription(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/show welcome #{quote_display_name(self.group_name)}"

class CreateGroupLink(BaseChatCommand):
    group_name: GroupName
    role: GroupMemberRole
    short: CreateShortLink

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        short = " short" if self.short else ""

        return f"/create link #{group} {self.role}{short}"

class GroupLinkMemberRole(BaseChatCommand):
    group_name: GroupName
    role: GroupMemberRole

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)

        return f"/set link role #{group} {self.role}"

class DeleteGroupLink(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/delete link #{quote_display_name(self.group_name)}"

class ShowGroupLink(BaseChatCommand):
    group_name: GroupName

    def __str__(self) -> str:
        return f"/show link #{quote_display_name(self.group_name)}"

class SendGroupMessageQuote(BaseChatCommand):
    group_name: GroupName
    contact_name: Optional[ContactName]
    quoted_msg: str
    msg: str

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        contact = (" " + quote_display_name(self.contact_name)) if self.contact_name is not None else ""
        quoted = quote_msg(self.quoted_msg)
        msg = json.dumps(self.msg)

        return f">#{group}{contact} {quoted} {msg}"

class ClearNoteFolder(BaseChatCommand):
    def __str__(self) -> str: return "/clear *"

class LastChats(BaseChatCommand):
    count: Optional[int]

    def __str__(self) -> str:
        count_part = "all" if self.count is None else str(self.count)
        return f"/chats {count_part}"

class ShowChatItem(BaseChatCommand):
    chat_item_id: Optional[ChatItemId]

    def __str__(self) -> str:
        assert self.chat_item_id is not None, "bug in parser?"  # TODO
        return f"/show {self.chat_item_id}"

class ShowLiveItems(BaseChatCommand):
    enabled: bool

    def __str__(self) -> str:
        return f"/show {to_on_off(self.enabled)}"

class SendFile(BaseChatCommand):
    chat_name: ChatName
    crypto_file: CryptoFile

    def __str__(self) -> str:
        return f"/file {self.chat_name} {self.crypto_file}"

class SendImage(BaseChatCommand):
    chat_name: ChatName
    crypto_file: CryptoFile

    def __str__(self) -> str:
        return f"/image {self.chat_name} {self.crypto_file}"

class ForwardFile(BaseChatCommand):
    chat_name: ChatName
    file_id: FileTransferId

    def __str__(self) -> str:
        return f"/fforward {self.chat_name} {self.file_id}"

class ForwardImage(BaseChatCommand):
    chat_name: ChatName
    file_id: FileTransferId

    def __str__(self) -> str:
        return f"/image_forward {self.chat_name} {self.file_id}"

class SendFileDescription(BaseChatCommand):
    chat_name: ChatName
    file_path: FilePath

    def __str__(self) -> str:
        return f"/fdescription {self.chat_name} {self.file_path}"

class ReceiveFile(BaseChatCommand):
    file_transfer_id: FileTransferId  # TODO fileId?
    user_approved_relays: bool
    store_encrypted: Optional[bool]
    file_inline: Optional[bool]
    file_path: Optional[FilePath]

    def __str__(self) -> str:
        file_id = str(self.file_transfer_id)
        approved = " approved_relays=" + to_on_off(self.user_approved_relays)
        encrypt = (" encrypt=" + to_on_off(self.store_encrypted)) if self.store_encrypted is not None else ""
        inline = (" inline=" + to_on_off(self.file_inline)) if self.file_inline is not None else ""
        file_path = (" " + self.file_path) if self.file_path is not None else ""

        return f"/freceive " + file_id + approved + encrypt + inline + file_path

class SetFileToReceive(BaseChatCommand):
    file_transfer_id: FileTransferId  # TODO fileId?
    user_approved_relays: bool
    store_encrypted: Optional[bool]

    def __str__(self) -> str:
        file_id = str(self.file_transfer_id)
        approved = " approved_relays=" + to_on_off(self.user_approved_relays)
        encrypt = (" encrypt=" + to_on_off(self.store_encrypted)) if self.store_encrypted is not None else ""

        return "/_set_file_to_receive " + file_id + approved + encrypt

class CancelFile(BaseChatCommand):
    file_transfer_id: FileTransferId

    def __str__(self) -> str:
        return f"/fcancel {self.file_transfer_id}"

class FileStatus(BaseChatCommand):
    file_transfer_id: FileTransferId

    def __str__(self) -> str:
        return f"/fstatus {self.file_transfer_id}"

class ShowProfile(BaseChatCommand):
    def __str__(self) -> str: return "/profile"

class UpdateProfile(BaseChatCommand):
    display_name: ContactName
    full_name: str

    def __str__(self) -> str:
        return f"/profile {quote_display_name(self.display_name)} {self.full_name}"

class UpdateProfileImage(BaseChatCommand):
    image_data: Optional[ImageData]

    def __str__(self) -> str:
        if self.image_data is None:
            return "/delete profile image"
        else:
            return f"/set profile image {self.image_data}"

class ShowProfileImage(BaseChatCommand):
    def __str__(self) -> str: return "/show profile image"

class SetUserTimedMessages(BaseChatCommand):
    disappear: bool

    def __str__(self) -> str:
        return "/set disappear " + ("yes" if self.disappear else "no")

class SetGroupTimedMessages(BaseChatCommand):
    group_name: GroupName
    timed_ttl: Optional[int]

    def __str__(self) -> str:
        group = quote_display_name(self.group_name)
        ttl = f"on {self.timed_ttl}" if self.timed_ttl is not None else "off"

        return f"/set disappear #{group} {ttl}"

class SetLocalDeviceName(BaseChatCommand):
    name: str

    def __str__(self) -> str:
        return f"/set device name {self.name}"

class ListRemoteHosts(BaseChatCommand):
    def __str__(self) -> str: return "/list remote hosts"

class SwitchRemoteHost(BaseChatCommand):
    remote_host_id: Optional[RemoteHostId]

    def __str__(self) -> str:
        host_part = "local" if self.remote_host_id is None else str(self.remote_host_id)

        return "/switch remote host " + host_part

class DeleteRemoteHost(BaseChatCommand):
    remote_host_id: RemoteHostId

    def __str__(self) -> str:
        return f"/delete remote host {self.remote_host_id}"

class StoreRemoteFile(BaseChatCommand):
    remote_host_id: RemoteHostId
    store_encrypted: Optional[bool]
    local_path: FilePath

    def __str__(self) -> str:
        encrypted_part = (" encrypt=" + to_on_off(self.store_encrypted)) if self.store_encrypted is not None else ""

        return f"/store remote file {self.remote_host_id}{encrypted_part} {self.local_path}"

class FindKnownRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/find remote ctrl"

class ConfirmRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId

    def __str__(self) -> str:
        return f"/confirm remote ctrl {self.remote_ctrl_id}"

class VerifyRemoteCtrlSession(BaseChatCommand):
    session_id: str

    def __str__(self) -> str:
        return f"/verify remote ctrl {self.session_id}"

class ListRemoteCtrls(BaseChatCommand):
    def __str__(self) -> str: return "/list remote ctrls"

class StopRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/stop remote ctrl"

class DeleteRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId

    def __str__(self) -> str:
        return f"/delete remote ctrl {self.remote_ctrl_id}"

class QuitChat(BaseChatCommand):
    def __str__(self) -> str: return "/quit"

class ShowVersion(BaseChatCommand):
    def __str__(self) -> str: return "/version"

class DebugLocks(BaseChatCommand):
    def __str__(self) -> str: return "/debug locks"

class GetAgentSubsTotal(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/get subs total {self.user_id}"

class GetAgentServersSummary(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/get servers summary {self.user_id}"

class ResetAgentServersStats(BaseChatCommand):
    def __str__(self) -> str: return "/reset servers stats"

class GetAgentSubs(BaseChatCommand):
    def __str__(self) -> str: return "/get subs"

class GetAgentSubsDetails(BaseChatCommand):
    def __str__(self) -> str: return "/get subs details"

class GetAgentWorkers(BaseChatCommand):
    def __str__(self) -> str: return "/get workers"

class GetAgentWorkersDetails(BaseChatCommand):
    def __str__(self) -> str: return "/get workers details"

class GetAgentQueuesInfo(BaseChatCommand):
    def __str__(self) -> str: return "/get queues"

class CustomChatCommand(BaseChatCommand):
    command: str

    def __str__(self) -> str:
        return "//" + self.command
