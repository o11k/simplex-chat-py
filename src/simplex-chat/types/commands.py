import json
from typing import Annotated, Any, Literal, Optional, TypeVar, Union, Callable
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
    clearOverrides: bool

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
    currentKey: DBEncryptionKey
    newKey: DBEncryptionKey
    keepKey: Optional[bool]

SocksProxyWithAuth = str  # TODO validate
SocksMode = Literal["always", "onion"]
HostMode = Literal["onionViaSocks", "onion", "public"]
TransportSessionMode = Literal["user", "session", "server", "entity"]
SMPProxyMode = Literal["always", "unknown", "unprotected", "never"]
SMPProxyFallback = Literal["allow", "allowProtected", "prohibited"]
SMPWebPortServers = Literal["all", "preset", "off"]

class KeepAliveOpts(BaseModel):
    keepIdle: int
    keepIntvl: int
    keepCnt: int

class NetworkConfig(BaseModel):
    socksProxy: Optional[SocksProxyWithAuth]
    socksMode: SocksMode
    hostMode: HostMode
    requiredHostMode: bool
    sessionMode: TransportSessionMode
    smpProxyMode: SMPProxyMode
    smpProxyFallback: SMPProxyFallback
    smpWebPortServers: SMPWebPortServers
    tcpConnectTimeout: int
    tcpTimeout: int
    tcpTimeoutPerKb: int
    rcvConcurrency: int
    tcpKeepAlive: Optional[KeepAliveOpts]
    smpPingInterval: int
    smpPingCount: int
    logTLSErrors: bool

class SimpleNetCfg(BaseModel):
    socksProxy: Optional[SocksProxyWithAuth]
    socksMode: SocksMode
    hostMode: HostMode
    requiredHostMode: bool
    smpProxyMode: Optional[SMPProxyMode]
    smpProxyFallback: Optional[SMPProxyFallback]
    smpWebPortServers: SMPWebPortServers
    tcpTimeout: Optional[int]  # Multiplied by 1,000,000(?)
    logTLSErrors: bool

ChatType = Literal["direct", "group", "local", "contactRequest", "contactConnection"]

class ChatName(BaseModel):
    chatType: ChatType
    chatName: str

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

# class UpdatedUserOperatorServers(BaseModel):
#     operator: Optional[ServerOperator]
#     smpServers: list[AUserServer ''PSMP]
#     xftpServers: list[AUserServer ''PXFTP]

MsgFilter = Literal["none", "all", "mentions"]

AProtocolType = Literal["smp", "ntf", "xftp"]
AProtoServerWithAuth = str  # TODO validation

GroupFeatureEnabled = Literal["on", "off"]

class TimedMessagesGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    ttl: Optional[int]

class DirectMessagesGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    role: Optional[GroupMemberRole]

class FullDeleteGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    role: Optional[GroupMemberRole]

class ReactionsGroupPreference(BaseModel):
    enable: GroupFeatureEnabled

class VoiceGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    role: Optional[GroupMemberRole]

class FilesGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    role: Optional[GroupMemberRole]

class SimplexLinksGroupPreference(BaseModel):
    enable: GroupFeatureEnabled
    role: Optional[GroupMemberRole]

class ReportsGroupPreference(BaseModel):
    enable: GroupFeatureEnabled

class HistoryGroupPreference(BaseModel):
    enable: GroupFeatureEnabled

class GroupPreferences(BaseModel):
    timedMessages: Optional[TimedMessagesGroupPreference]
    directMessages: Optional[DirectMessagesGroupPreference]
    fullDelete: Optional[FullDeleteGroupPreference]
    reactions: Optional[ReactionsGroupPreference]
    voice: Optional[VoiceGroupPreference]
    files: Optional[FilesGroupPreference]
    simplexLinks: Optional[SimplexLinksGroupPreference]
    reports: Optional[ReportsGroupPreference]
    history: Optional[HistoryGroupPreference]

MemberCriteria = Literal["all"]

class GroupMemberAdmission(BaseModel):
    review: Optional[MemberCriteria]

class GroupProfile(BaseModel):
    displayName: GroupName
    fullName: str
    description: Optional[str]
    image: Optional[ImageData]
    groupPreferences: Optional[GroupPreferences]
    memberAdmission: Optional[GroupMemberAdmission]

DarkColorScheme = Literal["DARK", "BLACK", "SIMPLEX"]
ThemeColorScheme = Union[Literal["LIGHT"], DarkColorScheme]
UIColorScheme = Union[Literal["SYSTEM"], ThemeColorScheme]

class UITheme(BaseModel):
    themeId: str
    base: ThemeColorScheme
    wallpaper: Optional[ChatWallpaper]
    colors: UIColors

AppPlatform = Literal["iOS", "android", "desktop"]
NetworkProxyAuth = Literal["username", "isolate"]
NotificationMode = Literal["off", "periodic", "instant"]
NotificationPreviewMode = Literal["hidden", "contant", "message"]
LockScreenCalls = Literal["disable", "show", "accept"]

class NetworkProxy(BaseModel):
    host: str
    port: int
    auth: NetworkProxyAuth
    username: str
    password: str

class AppSettings(BaseModel):
    appPlatform: Optional[AppPlatform]
    networkConfig: Optional[NetworkConfig]
    networkProxy: Optional[NetworkProxy]
    privacyEncryptLocalFiles: Optional[bool]
    privacyAskToApproveRelays: Optional[bool]
    privacyAcceptImages: Optional[bool]
    privacyLinkPreviews: Optional[bool]
    privacyShowChatPreviews: Optional[bool]
    privacySaveLastDraft: Optional[bool]
    privacyProtectScreen: Optional[bool]
    privacyMediaBlurRadius: Optional[int]
    notificationMode: Optional[NotificationMode]
    notificationPreviewMode: Optional[NotificationPreviewMode]
    webrtcPolicyRelay: Optional[bool]
    webrtcICEServers: Optional[list[str]]
    confirmRemoteSessions: Optional[bool]
    connectRemoteViaMulticast: Optional[bool]
    connectRemoteViaMulticastAuto: Optional[bool]
    developerTools: Optional[bool]
    confirmDBUpgrades: Optional[bool]
    androidCallOnLockScreen: Optional[LockScreenCalls]
    iosCallKitEnabled: Optional[bool]
    iosCallKitCallsInRecents: Optional[bool]
    uiProfileImageCornerRadius: Optional[float]
    uiChatItemRoundness: Optional[float]
    uiChatItemTail: Optional[bool]
    uiColorScheme: Optional[UIColorScheme]
    uiDarkColorScheme: Optional[DarkColorScheme]
    uiCurrentThemeIds: Optional[dict[ThemeColorScheme, str]]
    uiThemes: Optional[list[UITheme]]
    oneHandUI: Optional[bool]
    chatBottomBar: Optional[bool]

ConnLinkContact = str  # TODO never used. Set to str because typescript library does it

class Profile(BaseModel):
    displayName: ContactName
    fullName: str
    image: Optional[ImageData]
    contactLink: Optional[ConnLinkContact]
    preferences: Optional[Preferences]

class NewUser(BaseModel):
    profile: Optional[Profile]
    pastTimestamp: bool

class PaginationByTime(BaseModel):
    count: int
    type: Literal["before", "after", "last"]
    # Not relevant for "last"
    time: Optional[str] = None  # TODO

class CLQFilters(BaseModel):
    favorite: bool
    unread: bool
class CLQSearch(BaseModel):
    search: str
ChatListQuery = Union[CLQFilters, CLQSearch]


# -------------------------------------------------------------

T = TypeVar("T")

# What is <$?>
class A:
    space = " "
    @staticmethod
    def decimal(n: int) -> str: return str(n)
def AsepBy1(): ...
def Achar(): ...
def AtakeTill(): ...

def char_(c: str) -> str: return c  # Can also return ""
def textP(s: str) -> str: return s
def strP(s: str) -> str: return s  # TODO base64?
def jsonP(obj: Any) -> str:
    if isinstance(obj, BaseModel): return obj.model_dump_json()
    else: return json.dumps(obj)
def stringP(s: str) -> str: return s
def _strP(): ...

def optional(maybe: Optional[T], transform: Callable[[T], str]=str):
    return transform(maybe) if maybe is not None else ""

def onOffP(b: bool) -> str: return "on" if b else "off"
def shortP(b: bool) -> str: return A.space + "short" if b else ""
def incognitoP(b: bool) -> str: return A.space + "incognito" if b else ""
def shortOnOffP(b: bool) -> str: return A.space + "short=" + onOffP(b)
def incognitoOnOffP(b: bool) -> str: return A.space + "incognito=" + onOffP(b)

def liveMessageP(): ...
def sendMessageTTLP(): ...
def msgTextP(): ...
def msgContentP(): ...
def composedMessagesTextP(): ...
def updatedMessagesTextP(): ...
def quotedMsg(): ...

def chatNameP(): ...
def displayNameP(name: str) -> str:
    if name == "":
        raise ValueError("Empty display name")
    if ord(name[0]) <= ord(" ") or name[0] in ("#", "@", "'"):
        raise ValueError(f"Invalid first character in display name: {name}")
    # Unquoted (TODO python str.isspace not exacly equivalent to haskell isSpace)
    if not any(c.isspace() for c in name) and "," not in name:
        return name
    # Quoted
    elif "'" not in name:
        return "'" + name + "'"
    else:
        raise ValueError(f"Unquotable display name: {name}")

filePath = stringP
def newUserP(): ...
def pwdP(pwd: str) -> str: return jsonP(pwd)
def receiptSettings(settings: UserMsgReceiptSettings) -> str:
    return onOffP(settings.enable) + " clear_overrides=" + onOffP(settings.clearOverrides)

def dbKeyP(key: DBEncryptionKey) -> str:
    if key == "": raise ValueError("Empty key")
    return strP(key)

def dbEncryptionConfig(): ...
def paginationByTimeP(): ...
def chatRefP(ref: ChatRef) -> str: return ref
def chatPaginationP(): ...
def sendRefP(): ...
def knownReaction(): ...
def chatDeleteMode(mode: ChatDeleteMode):
    if (mode.mode == "messages") != (mode.notify is not None):
        raise ValueError(f"Invalid delete mode: {mode.mode}_{mode.notify}")
    return " "+mode.mode + optional(mode.notify, lambda n: " notify=" + onOffP(n))

def connMsgsP(): ...
def memberRole(role: GroupMemberRole) -> str: return " " + role
def protocolServersP(): ...
def operatorRolesP(): ...
def ciTTLDecimal(): ...
def ciTTL(): ...
def netCfgP(): ...
def verifyCodeP(): ...
def groupProfile(): ...
def connLinkP(): ...


# -------------------------------------------------------------

class BaseChatCommand(BaseModel, ABC):
    @abstractmethod
    def format(self) -> str: ...

class ShowActiveUser(BaseChatCommand):
    def format(self) -> str:
        return "/user"

class CreateActiveUser(BaseChatCommand):
    new_user: NewUser
    def format(self) -> str:
        return "/_create user " + jsonP(self.new_user)

class ListUsers(BaseChatCommand):
    def format(self) -> str:
        return "/users"

class APISetActiveUser(BaseChatCommand):
    user_id: UserId
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/_user " + A.decimal(self.user_id) + optional(self.user_pwd, lambda p: A.space + jsonP(p))

class SetActiveUser(BaseChatCommand):
    user_name: UserName
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/user " + displayNameP(self.user_name) + optional(self.user_pwd, lambda p: A.space + pwdP(p))

class SetAllContactReceipts(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return "/set receipts all " + onOffP(self.on_or_off)

class APISetUserContactReceipts(BaseChatCommand):
    user_id: UserId
    settings: UserMsgReceiptSettings
    def format(self) -> str:
        return "/_set receipts contacts " + A.decimal(self.user_id) + A.space + receiptSettings(self.settings)

class SetUserContactReceipts(BaseChatCommand):
    settings: UserMsgReceiptSettings
    def format(self) -> str:
        return "/set receipts contacts " + receiptSettings(self.settings)

class APISetUserGroupReceipts(BaseChatCommand):
    user_id: UserId
    settings: UserMsgReceiptSettings
    def format(self) -> str:
        return "/_set receipts groups " + A.decimal(self.user_id) + A.space + receiptSettings(self.settings)

class SetUserGroupReceipts(BaseChatCommand):
    settings: UserMsgReceiptSettings
    def format(self) -> str:
        return "/set receipts groups " + receiptSettings(self.settings)

class APIHideUser(BaseChatCommand):
    user_id: UserId
    user_pwd: UserPwd
    def format(self) -> str:
        return "/_hide user " + A.decimal(self.user_id) + A.space + jsonP(self.user_pwd)

class APIUnhideUser(BaseChatCommand):
    user_id: UserId
    user_pwd: UserPwd
    def format(self) -> str:
        return "/_unhide user " + A.decimal(self.user_id) + A.space + jsonP(self.user_pwd)

class APIMuteUser(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_mute user " + A.decimal(self.user_id)

class APIUnmuteUser(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_unmute user " + A.decimal(self.user_id)

class HideUser(BaseChatCommand):
    user_pwd: UserPwd
    def format(self) -> str:
        return "/hide user " + pwdP(self.user_pwd)

class UnhideUser(BaseChatCommand):
    user_pwd: UserPwd
    def format(self) -> str:
        return "/unhide user " + pwdP(self.user_pwd)

class MuteUser(BaseChatCommand):
    def format(self) -> str:
        return "/mute user"

class UnmuteUser(BaseChatCommand):
    def format(self) -> str:
        return "/unmute user"

class APIDeleteUser(BaseChatCommand):
    user_id: UserId
    delete_smp_queues: bool
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/_delete user " + A.decimal(self.user_id) + " del_smp=" + onOffP(self.delete_smp_queues) + optional(self.user_pwd, lambda p: A.space + jsonP(p))

class DeleteUser(BaseChatCommand):
    user_name: UserName
    # Always true
    # delete_smp_queues: bool = True
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/delete user " + displayNameP(self.user_name) + optional(self.user_pwd, lambda p: A.space + pwdP(p))

class StartChat(BaseChatCommand):
    main_app: bool
    enable_snd_files: bool  # Default =main_app
    def format(self) -> str:
        return "/_start " + \
            "main=" + onOffP(self.main_app) + \
            " snd_files=" + onOffP(self.enable_snd_files)

class CheckChatRunning(BaseChatCommand):
    def format(self) -> str:
        return "/_check running"

class APIStopChat(BaseChatCommand):
    def format(self) -> str:
        return "/_stop"

class APIActivateChat(BaseChatCommand):
    restore_chat: bool
    def format(self) -> str:
        return "/_app activate restore=" + onOffP(self.restore_chat)

class APISuspendChat(BaseChatCommand):
    suspend_timeout: int
    def format(self) -> str:
        return "/_app suspend " + A.decimal(self.suspend_timeout)

class ResubscribeAllConnections(BaseChatCommand):
    def format(self) -> str:
        return "/_resubscribe all"

@deprecated("Use APISetAppFilePaths instead")
class SetTempFolder(BaseChatCommand):
    path: FilePath
    def format(self) -> str:
        return "/_temp_folder " + filePath(self.path)

@deprecated("Use APISetAppFilePaths instead")
class SetFilesFolder(BaseChatCommand):
    path: FilePath
    def format(self) -> str:
        return "/files_folder " + filePath(self.path)

@deprecated("Use APISetAppFilePaths instead")
class SetRemoteHostsFolder(BaseChatCommand):
    path: FilePath
    def format(self) -> str:
        return "/remote_hosts_folder " + filePath(self.path)

class APISetAppFilePaths(BaseChatCommand):
    config: AppFilePathsConfig
    def format(self) -> str:
        return "/set file paths " + jsonP(self.config)

class APISetEncryptLocalFiles(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return "/_files_encrypt " + onOffP(self.on_or_off)

class SetContactMergeEnabled(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return "/contact_merge " + onOffP(self.on_or_off)

class APIExportArchive(BaseChatCommand):
    config: ArchiveConfig
    def format(self) -> str:
        return "/_db export " + jsonP(self.config)

class ExportArchive(BaseChatCommand):
    def format(self) -> str:
        return "/db export"

class APIImportArchive(BaseChatCommand):
    config: ArchiveConfig
    def format(self) -> str:
        return "/_db import " + jsonP(self.config)

class APIDeleteStorage(BaseChatCommand):
    def format(self) -> str:
        return "/_db delete"

class APIStorageEncryption(BaseChatCommand):
    config: DBEncryptionConfig
    def format(self) -> str:
        return "/_db encryption " + jsonP(self.config)

class TestStorageEncryption(BaseChatCommand):
    key: DBEncryptionKey
    def format(self) -> str:
        return "/db test key " + dbKeyP(self.key)

class SlowSQLQueries(BaseChatCommand):
    def format(self) -> str:
        return "/sql slow"

class ExecChatStoreSQL(BaseChatCommand):
    query: str
    def format(self) -> str:
        return "/sql chat " + textP(self.query)

class ExecAgentStoreSQL(BaseChatCommand):
    query: str
    def format(self) -> str:
        return "/sql agent " + textP(self.query)

class APISaveAppSettings(BaseChatCommand):
    settings: AppSettings
    def format(self) -> str:
        return "/_save app settings" + jsonP(self.settings)

class APIGetAppSettings(BaseChatCommand):
    settings: Optional[AppSettings]
    def format(self) -> str:
        return "/_get app settings" + optional(self.settings, lambda s: A.space + jsonP(s))

class APIGetChatTags(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_get tags " + A.decimal(self.user_id)

class APIGetChats(BaseChatCommand):
    user_id: UserId
    pending_connections: bool = False
    pagination: PaginationByTime = PaginationByTime(type="last", count=5000)
    query: ChatListQuery = CLQFilters(favorite=False, unread=False)
    def format(self) -> str:
        return "/_get chats " \
        + (
               A.decimal(self.user_id)
              + (" pcc=on"  if self.pending_connections else " pcc=off")
              + (A.space + paginationByTimeP(self.pagination))
              + (A.space + jsonP(self.query))
        )

class APIGetChat(BaseChatCommand):
    chat_ref: ChatRef
    msg_content_tag: Optional[MsgContentTag]
    pagination: ChatPagination
    search: Optional[str]
    def format(self) -> str:
        return "/_get chat " + chatRefP(self.chat_ref) + optional(self.msg_content_tag, lambda t: " content=" + strP(t)) + A.space + chatPaginationP(self.pagination) + optional(self.search, lambda s: " search=" + stringP(s))

class APIGetChatItems(BaseChatCommand):
    pagination: ChatPagination
    search: Optional[str]
    def format(self) -> str:
        return "/_get items " + chatPaginationP(self.pagination) + optional(self.search, lambda s: " search=" + stringP(s))

class APIGetChatItemInfo(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: ChatItemId
    def format(self) -> str:
        return "/_get item info " + chatRefP(self.chat_ref) + A.space + A.decimal(self.chat_item_id)

class APISendMessages(BaseChatCommand):
    send_ref: SendRef
    live_message: bool
    ttl: Optional[int]
    composed_messages: list[ComposedMessage]  # NonEmpty
    def format(self) -> str:
        return "/_send " + sendRefP(self.send_ref) + liveMessageP(self.live_message) + sendMessageTTLP(self.ttl) + " json " + jsonP(self.composed_messages)

class APICreateChatTag(BaseChatCommand):
    chat_tag_data: ChatTagData
    def format(self) -> str:
        return "/_create tag " + jsonP(self.chat_tag_data)

class APISetChatTags(BaseChatCommand):
    chat_ref: ChatRef
    chat_tag_ids: Optional[list[ChatTagId]]  # NonEmpty
    def format(self) -> str:
        # TODO _strP(list[ChatTagId]) ???
        return "/_tags " + chatRefP(self.chat_ref) + optional(self.chat_tag_ids, lambda t: _strP(t))

class APIDeleteChatTag(BaseChatCommand):
    chat_tag_id: ChatTagId
    def format(self) -> str:
        return "/_delete tag " + A.decimal(self.chat_tag_id)

class APIUpdateChatTag(BaseChatCommand):
    chat_tag_id: ChatTagId
    chat_tag_data: ChatTagData
    def format(self) -> str:
        return "/_update tag " + A.decimal(self.chat_tag_id) + A.space + jsonP(self.chat_tag_data)

class APIReorderChatTags(BaseChatCommand):
    chat_tag_ids: list[ChatTagId]  # NonEmpty
    def format(self) -> str:
        return "/_reorder tags " + strP(self.chat_tag_ids)

class APICreateChatItems(BaseChatCommand):
    note_folder_id: NoteFolderId
    composed_messages: list[ComposedMessage]  # NonEmpty
    def format(self) -> str:
        return "/_create *" + A.decimal(self.note_folder_id) + " json " + jsonP(self.composed_messages)

class APIReportMessage(BaseChatCommand):
    group_id: GroupId
    chat_item_id: ChatItemId
    report_reason: ReportReason
    report_text: str
    def format(self) -> str:
        return "/_report #" + A.decimal(self.group_id) + A.space + A.decimal(self.chat_item_id) + " reason=" + strP(self.report_reason) + A.space + textP(self.report_text)

class ReportMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: Optional[ContactName]
    report_reason: ReportReason
    reported_message: str
    def format(self) -> str:
        return "/report #" + displayNameP(self.group_name) + optional(self.contact_name, lambda n: " @" + displayNameP(n)) + _strP(self.report_reason) + A.space + msgTextP(self.reported_message)

class APIUpdateChatItem(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: ChatItemId
    live_message: bool
    updated_message: UpdatedMessage
    def format(self) -> str:
        return "/_update item " + chatRefP(self.chat_ref) + A.space + A.decimal(self.chat_item_id) + liveMessageP(self.live_message) + " json" + jsonP(self.updated_message)

class APIDeleteChatItem(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: list[ChatItemId]  # NonEmpty
    mode: CIDeleteMode
    def format(self) -> str:
        return "/_delete item " + chatRefP(self.chat_ref) + _strP(self.chat_item_id) + _strP(self.mode)

class APIDeleteMemberChatItem(BaseChatCommand):
    group_id: GroupId
    chat_item_id: list[ChatItemId]  # NonEmpty
    def format(self) -> str:
        return "/_delete member item #" + A.decimal(self.group_id) + _strP(self.chat_item_id)

class APIArchiveReceivedReports(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_archive reports #" + A.decimal(self.group_id)

class APIDeleteReceivedReports(BaseChatCommand):
    group_id: GroupId
    chat_item_id: list[ChatItemId]  # NonEmpty
    mode: CIDeleteMode
    def format(self) -> str:
        return "/_delete reports #" + A.decimal(self.group_id) + _strP(self.chat_item_id) + _strP(self.mode)

class APIChatItemReaction(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: ChatItemId
    add: bool
    reaction: MsgReaction  # knownReaction?
    def format(self) -> str:
        return "/_reaction " + chatRefP(self.chat_ref) + A.space + A.decimal(self.chat_item_id) + A.space + onOffP(self.add) + A.space + jsonP(self.reaction)

class APIGetReactionMembers(BaseChatCommand):
    user_id: UserId
    group_id: GroupId
    chat_item_id: ChatItemId
    reaction: MsgReaction  # knownReaction?
    def format(self) -> str:
        return "/_reaction members " + A.decimal(self.user_id) + " #" + A.decimal(self.group_id) + A.space + A.decimal(self.chat_item_id) + A.space + jsonP(self.reaction)

class APIPlanForwardChatItems(BaseChatCommand):
    from_chat_ref: ChatRef
    chat_item_ids: list[ChatItemId]  # NonEmpty
    def format(self) -> str:
        return "/_forward plan " + chatRefP(self.from_chat_ref) + _strP(self.chat_item_ids)

class APIForwardChatItems(BaseChatCommand):
    to_chat_ref: ChatRef
    from_chat_ref: ChatRef
    chat_item_ids: list[ChatItemId]  # NonEmpty
    ttl: Optional[int]
    def format(self) -> str:
        return "/_forward " + chatRefP(self.to_chat_ref) + A.space + chatRefP(self.from_chat_ref) + _strP(self.chat_item_ids) + sendMessageTTLP(self.ttl)

class APIUserRead(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_read user " + A.decimal(self.user_id)

class UserRead(BaseChatCommand):
    def format(self) -> str:
        return "/read user"

class APIChatRead(BaseChatCommand):
    chat_ref: ChatRef
    def format(self) -> str:
        return "/_read chat " + chatRefP(self.chat_ref)

class APIChatItemsRead(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: list[ChatItemId] # NonEmpty
    def format(self) -> str:
        return "/_read chat items " + chatRefP(self.chat_ref) + _strP(self.chat_item_id)

class APIChatUnread(BaseChatCommand):
    chat_ref: ChatRef
    on_or_off: bool
    def format(self) -> str:
        return "/_unread chat " + chatRefP(self.chat_ref) + A.space + onOffP(self.on_or_off)

class APIDeleteChat(BaseChatCommand):
    chat_ref: ChatRef
    mode: ChatDeleteMode
    def format(self) -> str:
        return "/_delete " + chatRefP(self.chat_ref) + chatDeleteMode(self.mode)

class APIClearChat(BaseChatCommand):
    chat_ref: ChatRef
    def format(self) -> str:
        return "/_clear chat " + chatRefP(self.chat_ref)

class APIAcceptContact(BaseChatCommand):
    incognito: IncognitoEnabled
    conn_req_id: int
    def format(self) -> str:
        return "/_accept" + incognitoOnOffP(self.incognito) + A.space + A.decimal(self.conn_req_id)

class APIRejectContact(BaseChatCommand):
    conn_req_id: int
    def format(self) -> str:
        return "/_reject " + A.decimal(self.conn_req_id)

class APISendCallInvitation(BaseChatCommand):
    contact_id: ContactId
    call_type: CallType
    def format(self) -> str:
        return "/_call invite @" + A.decimal(self.contact_id) + A.space + jsonP(self.call_type)

class SendCallInvitation(BaseChatCommand):
    contact_name: ContactName
    # Always type=video encrypted=true
    # call_type: CallType
    def format(self) -> str:
        return "/call " + char_('@') + displayNameP(self.contact_name)

class APIRejectCall(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_call reject @" + A.decimal(self.contact_id)

class APISendCallOffer(BaseChatCommand):
    contact_id: ContactId
    offer: WebRTCCallOffer
    def format(self) -> str:
        return "/_call offer @" + A.decimal(self.contact_id) + A.space + jsonP(self.offer)

class APISendCallAnswer(BaseChatCommand):
    contact_id: ContactId
    session: WebRTCSession
    def format(self) -> str:
        return "/_call answer @" + A.decimal(self.contact_id) + A.space + jsonP(self.session)

class APISendCallExtraInfo(BaseChatCommand):
    contact_id: ContactId
    extra_info: WebRTCExtraInfo
    def format(self) -> str:
        return "/_call extra @" + A.decimal(self.contact_id) + A.space + jsonP(self.extra_info)

class APIEndCall(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_call end @" + A.decimal(self.contact_id)

class APIGetCallInvitations(BaseChatCommand):
    def format(self) -> str:
        return "/_call get"

class APICallStatus(BaseChatCommand):
    contact_id: ContactId
    status: WebRTCCallStatus
    def format(self) -> str:
        return "/_call status @" + A.decimal(self.contact_id) + A.space + strP(self.status)

class APIGetNetworkStatuses(BaseChatCommand):
    def format(self) -> str:
        return "/_network_statuses"

class APIUpdateProfile(BaseChatCommand):
    user_id: UserId
    profile: Profile
    def format(self) -> str:
        return "/_profile " + A.decimal(self.user_id) + A.space + jsonP(self.profile)

class APISetContactPrefs(BaseChatCommand):
    contact_id: ContactId
    preferences: Preferences
    def format(self) -> str:
        return "/_set prefs @" + A.decimal(self.contact_id) + A.space + jsonP(self.preferences)

class APISetContactAlias(BaseChatCommand):
    contact_id: ContactId
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias @" + A.decimal(self.contact_id) + (A.space + textP(self.local_alias) if self.local_alias else "")

class APISetGroupAlias(BaseChatCommand):
    group_id: GroupId
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias #" + A.decimal(self.group_id) + (A.space + textP(self.local_alias) if self.local_alias else "")

class APISetConnectionAlias(BaseChatCommand):
    connection_id: int
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias :" + A.decimal(self.connection_id) + (A.space + textP(self.local_alias) if self.local_alias else "")

class APISetUserUIThemes(BaseChatCommand):
    user_id: UserId
    ui_themes: Optional[UIThemeEntityOverrides]
    def format(self) -> str:
        return "/_set theme user " + A.decimal(self.user_id) + optional(self.ui_themes, lambda t: A.space + jsonP(t))

class APISetChatUIThemes(BaseChatCommand):
    chat_ref: ChatRef
    ui_themes: Optional[UIThemeEntityOverrides]
    def format(self) -> str:
        return "/_set theme " + chatRefP(self.chat_ref) + optional(self.ui_themes, lambda t: A.space + jsonP(t))

class APIGetNtfToken(BaseChatCommand):
    def format(self) -> str:
        return "/_ntf get"

class APIRegisterToken(BaseChatCommand):
    device_token: DeviceToken
    notifications_mode: NotificationsMode
    def format(self) -> str:
        return "/_ntf register " + strP_(self.device_token) + strP(self.notifications_mode)

class APIVerifyToken(BaseChatCommand):
    device_token: DeviceToken
    nonce: CbNonce
    enc_ntf_info: str
    def format(self) -> str:
        return "/_ntf verify " + strP(self.device_token) + A.space + strP(self.nonce) + A.space + strP(self.enc_ntf_info)

class APICheckToken(BaseChatCommand):
    device_token: DeviceToken
    def format(self) -> str:
        return "/_ntf check " + strP(self.device_token)

class APIDeleteToken(BaseChatCommand):
    device_token: DeviceToken
    def format(self) -> str:
        return "/_ntf delete " + strP(self.device_token)

class APIGetNtfConns(BaseChatCommand):
    nonce: CbNonce
    enc_ntf_info: ByteString
    def format(self) -> str:
        return "/_ntf conns " + strP(self.nonce) + A.space + strP(self.enc_ntf_info)

class APIGetConnNtfMessages(BaseChatCommand):
    conn_msgs: list[ConnMsgReq]  # NonEmpty
    def format(self) -> str:
        return "/_ntf conn messages " + connMsgsP(self.conn_msgs)

class APIAddMember(BaseChatCommand):
    group_id: GroupId
    contact_id: ContactId
    role: GroupMemberRole
    def format(self) -> str:
        return "/_add #" + A.decimal(self.group_id) + A.space + A.decimal(self.contact_id) + memberRole(self.role)

class APIJoinGroup(BaseChatCommand):
    group_id: GroupId
    # Always "all"
    # enable_ntfs: MsgFilter
    def format(self) -> str:
        return "/_join #" + A.decimal(self.group_id)

class APIAcceptMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    role: GroupMemberRole
    def format(self) -> str:
        return "/_accept member #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id) + memberRole(self.role)

class APIMembersRole(BaseChatCommand):
    group_id: GroupId
    member_ids: list[GroupMemberId]  # NonEmpty
    role: GroupMemberRole
    def format(self) -> str:
        return "/_member role #" + A.decimal(self.group_id) + _strP(self.member_ids) + memberRole(self.role)

class APIBlockMembersForAll(BaseChatCommand):
    group_id: GroupId
    member_ids: list[GroupMemberId]  # NonEmpty
    blocked: bool
    def format(self) -> str:
        return "/_block #" + A.decimal(self.group_id) + _strP(self.member_ids) + " blocked=" + onOffP(self.blocked)

# TODO
class APIRemoveMembers(BaseChatCommand):
    group_id: GroupId
    member_ids: Set GroupMemberId
    with_messages: Bool
    def format(self) -> str:
        return "/_remove #" + A.decimal + _strP + (" messages=" + onOffP <|> pure False)

class APILeaveGroup(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_leave #" + A.decimal(self.group_id)

class APIListMembers(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_members #" + A.decimal(self.group_id)

class APIUpdateGroupProfile(BaseChatCommand):
    group_id: GroupId
    profile: GroupProfile
    def format(self) -> str:
        return "/_group_profile #" + A.decimal(self.group_id) + A.space + jsonP(self.profile)

class APICreateGroupLink(BaseChatCommand):
    group_id: GroupId
    role: GroupMemberRole = "member"
    short: CreateShortLink
    def format(self) -> str:
        return "/_create link #" + A.decimal(self.group_id) + memberRole(self.role) + shortOnOffP(self.short)

class APIGroupLinkMemberRole(BaseChatCommand):
    group_id: GroupId
    role: GroupMemberRole
    def format(self) -> str:
        return "/_set link role #" + A.decimal(self.group_id) + memberRole(self.role)

class APIDeleteGroupLink(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_delete link #" + A.decimal(self.group_id)

class APIGetGroupLink(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_get link #" + A.decimal(self.group_id)

class APICreateMemberContact(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_create member contact #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APISendMemberContactInvitation(BaseChatCommand):
    contact_id: ContactId
    msg_content: Optional[MsgContent]
    def format(self) -> str:
        return "/_invite member contact @" + A.decimal(self.contact_id) + optional(self.msg_content, lambda c: A.space + msgContentP(c))

class GetUserProtoServers(BaseChatCommand):
    protocol_type: AProtocolType
    def format(self) -> str:
        if self.protocol_type == "smp":
            return "/smp"
        elif self.protocol_type == "xftp":
            return "/xftp"
        else:
            # TODO why no ntf?
            raise ValueError(f"Invalid protocol type: {self.protocol_type}")

# TODO
class SetUserProtoServers(BaseChatCommand):
    a_protocol_type: AProtocolType
    a_proto_server_with_auth: list[AProtoServerWithAuth]
    def format(self) -> str:
        return "/smp " + ( (AProtocolType SPSMP) . map (AProtoServerWithAuth SPSMP)  protocolServersP)
        return "/xftp " + ( (AProtocolType SPXFTP) . map (AProtoServerWithAuth SPXFTP)  protocolServersP)

class APITestProtoServer(BaseChatCommand):
    user_id: UserId
    server: AProtoServerWithAuth
    def format(self) -> str:
        return "/_server test " + A.decimal(self.user_id) + A.space + strP(self.server)

class TestProtoServer(BaseChatCommand):
    a_proto_server_with_auth: AProtoServerWithAuth
    def format(self) -> str:
        return "/smp test " + ( . AProtoServerWithAuth SPSMP  strP)
        return "/xftp test " + ( . AProtoServerWithAuth SPXFTP  strP)
        return "/ntf test " + ( . AProtoServerWithAuth SPNTF  strP)

class APIGetServerOperators(BaseChatCommand):
    def format(self) -> str:
        return "/_operators"

class APISetServerOperators(BaseChatCommand):
    operators: list[ServerOperator]  # NonEmpty
    def format(self) -> str:
        return "/_operators " + jsonP(self.operators)

class SetServerOperators(BaseChatCommand):
    roles: list[ServerOperatorRoles]  # NonEmpty
    def format(self) -> str:
        return "/operators " + ( . L.fromList  operatorRolesP `A.sepBy1` A.char ',')

class APIGetUserServers(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_servers " + A.decimal(self.user_id)

class APISetUserServers(BaseChatCommand):
    user_id: UserId
    user_servers: list[UpdatedUserOperatorServers]  # NonEmpty
    def format(self) -> str:
        return "/_servers " + A.decimal(self.user_id) + A.space + jsonP(self.user_servers)

class APIValidateServers(BaseChatCommand):
    user_id: UserId
    user_servers: list[UpdatedUserOperatorServers]
    def format(self) -> str:
        return "/_validate_servers " + A.decimal(self.user_id) + A.space + jsonP(self.user_servers)

class APIGetUsageConditions(BaseChatCommand):
    def format(self) -> str:
        return "/_conditions"

class APISetConditionsNotified(BaseChatCommand):
    condition_id: int
    def format(self) -> str:
        return "/_conditions_notified " + A.decimal(self.condition_id)

class APIAcceptConditions(BaseChatCommand):
    condition_id: int
    operator_ids: list[int]  # NonEmpty
    def format(self) -> str:
        return "/_accept_conditions " + A.decimal(self.condition_id) + _strP(self.operator_ids)

class APISetChatItemTTL(BaseChatCommand):
    user_id: UserId
    new_ttl: int
    def format(self) -> str:
        return "/_ttl " + A.decimal(self.user_id) + A.space + A.decimal(self.new_ttl)

class SetChatItemTTL(BaseChatCommand):
    new_ttl: int
    def format(self) -> str:
        return "/ttl " + ciTTL(self.new_ttl)

class APIGetChatItemTTL(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_ttl " + A.decimal(self.user_id)

class GetChatItemTTL(BaseChatCommand):
    def format(self) -> str:
        return "/ttl"

class APISetChatTTL(BaseChatCommand):
    user_id: UserId
    chat_ref: ChatRef
    new_ttl: Optional[int]
    def format(self) -> str:
        return "/_ttl " + A.decimal(self.user_id) + A.space + chatRefP(self.chat_ref) + A.space + ciTTLDecimal(self.new_ttl)

class SetChatTTL(BaseChatCommand):
    chat_name: ChatName
    new_ttl: Optional[int]
    def format(self) -> str:
        return "/ttl " + chatNameP(self.chat_name) + A.space + ("default" if self.new_ttl is None else ciTTL(self.new_ttl))

class GetChatTTL(BaseChatCommand):
    chat_name: ChatName
    def format(self) -> str:
        return "/ttl " + chatNameP(self.chat_name)

class APISetNetworkConfig(BaseChatCommand):
    config: NetworkConfig
    def format(self) -> str:
        return "/_network " + jsonP(self.config)

class APIGetNetworkConfig(BaseChatCommand):
    def format(self) -> str:
        return "/network"

class SetNetworkConfig(BaseChatCommand):
    config: SimpleNetCfg
    def format(self) -> str:
        return "/network " + netCfgP(self.config)

class APISetNetworkInfo(BaseChatCommand):
    user_network_info: UserNetworkInfo
    def format(self) -> str:
        return "/_network info " + jsonP

class ReconnectAllServers(BaseChatCommand):
    def format(self) -> str:
        return "/reconnect"

class ReconnectServer(BaseChatCommand):
    user_id: UserId
    smp_server: SMPServer
    def format(self) -> str:
        return "/reconnect " + A.decimal + A.space + strP

class APISetChatSettings(BaseChatCommand):
    chat_ref: ChatRef
    settings: ChatSettings
    def format(self) -> str:
        return "/_settings " + chatRefP + A.space + jsonP

class APISetMemberSettings(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    group_member_settings: GroupMemberSettings
    def format(self) -> str:
        return "/_member settings #" + A.decimal + A.space + A.decimal + A.space + jsonP

class APIContactInfo(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_info @" + A.decimal(self.contact_id)

class APIGroupInfo(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_info #" + A.decimal(self.group_id)

class APIGroupMemberInfo(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_info #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APIContactQueueInfo(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_queue info @" + A.decimal(self.contact_id)

class APIGroupMemberQueueInfo(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_queue info #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APISwitchContact(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_switch @" + A.decimal(self.contact_id)

class APISwitchGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_switch #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APIAbortSwitchContact(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_abort switch @" + A.decimal(self.contact_id)

class APIAbortSwitchGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_abort switch #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APISyncContactRatchet(BaseChatCommand):
    contact_id: ContactId
    force: bool
    def format(self) -> str:
        return "/_sync @" + A.decimal(self.contact_id) + (" force=on" if self.force else "")

class APISyncGroupMemberRatchet(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    force: bool
    def format(self) -> str:
        return "/_sync #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id) + (" force=on" if self.force else "")

class APIGetContactCode(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_get code @" + A.decimal(self.contact_id)

class APIGetGroupMemberCode(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_get code #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class APIVerifyContact(BaseChatCommand):
    contact_id: ContactId
    verify_code: Optional[str]
    def format(self) -> str:
        return "/_verify code @" + A.decimal(self.contact_id) + optional(self.verify_code, lambda c: A.space + verifyCodeP(c))

class APIVerifyGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    verify_code: Optional[str]
    def format(self) -> str:
        return "/_verify code #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id) + optional(self.verify_code, lambda c: A.space + verifyCodeP(c))

class APIEnableContact(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_enable @" + A.decimal(self.contact_id)

class APIEnableGroupMember(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    def format(self) -> str:
        return "/_enable #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id)

class SetShowMessages(BaseChatCommand):
    chat_name: ChatName
    msg_filter: MsgFilter
    def format(self) -> str:
        if self.msg_filter == "none":
            return "/mute " + chatNameP(self.chat_name)
        elif self.msg_filter == "all":
            return "/unmute " + chatNameP(self.chat_name)
        elif self.msg_filter == "mentions":
            return "/unmute mentions " + chatNameP(self.chat_name)
        else:
            raise ValueError(f"Invalid message filter: {self.msg_filter}")

class SetSendReceipts(BaseChatCommand):
    chat_name: ChatName
    on_or_off: Optional[bool]
    def format(self) -> str:
        return "/receipts " + chatNameP(self.chat_name) + " " + (onOffP(self.on_or_off) if self.on_or_off is not None else "default")

class SetShowMemberMessages(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    show_messages: bool
    def format(self) -> str:
        if not self.show_messages:
            return "/block #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)
        else:
            return "/unblock #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class ContactInfo(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/info " + char_('@') + displayNameP(self.contact_name)

class ShowGroupInfo(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/info #" + displayNameP(self.group_name)

class GroupMemberInfo(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/info #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class ContactQueueInfo(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/queue info " + char_('@') + displayNameP(self.contact_name)

class GroupMemberQueueInfo(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/queue info #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class SwitchContact(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/switch " + char_('@') + displayNameP(self.contact_name)

class SwitchGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/switch #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class AbortSwitchContact(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/abort switch " + char_('@') + displayNameP(self.contact_name)

class AbortSwitchGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/abort switch #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class SyncContactRatchet(BaseChatCommand):
    contact_name: ContactName
    force: bool
    def format(self) -> str:
        return "/sync " + char_('@') + displayNameP(self.contact_name) + (" force=on" if self.force else "")

class SyncGroupMemberRatchet(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    force: bool
    def format(self) -> str:
        return "/sync #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + (" force=on" if self.force else "")

class GetContactCode(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/code " + char_('@') + displayNameP(self.contact_name)

class GetGroupMemberCode(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/code #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class VerifyContact(BaseChatCommand):
    contact_name: ContactName
    verify_code: Optional[str]
    def format(self) -> str:
        return "/verify " + char_('@') + displayNameP(self.contact_name) + optional(self.verify_code, lambda c: A.space + verifyCodeP(c))

class VerifyGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    verify_code: Optional[str]
    def format(self) -> str:
        return "/verify #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + optional(self.verify_code, lambda c: A.space + verifyCodeP(c))

class EnableContact(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/enable " + char_('@') + displayNameP(self.contact_name)

class EnableGroupMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    def format(self) -> str:
        return "/enable #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

HelpSection = Literal[
    "files",
    "groups",
    "contacts",
    "address",
    "incognito",
    "messages",
    "remote",
    "settings",
    "database",
    "main",
    "markdown"
]

class ChatHelp(BaseChatCommand):
    help_section: Optional[HelpSection]
    def format(self) -> str:
        if self.help_section is None or self.help_section == "main":
            return "/help"
        elif self.help_section == "files":
            return "/help files"
        elif self.help_section == "groups":
            return "/help groups"
        elif self.help_section == "contacts":
            return "/help contacts"
        elif self.help_section == "address":
            return "/help address"
        elif self.help_section == "incognito":
            return "/help incognito"
        elif self.help_section == "messages":
            return "/help messages"
        elif self.help_section == "remote":
            return "/help remote"
        elif self.help_section == "settings":
            return "/help settings"
        elif self.help_section == "database":
            return "/help db"
        elif self.help_section == "markdown":
            return "/markdown"
        else:
            raise ValueError(f"Invalid help section: {self.help_section}")

class Welcome(BaseChatCommand):
    def format(self) -> str:
        return "/welcome"

class APIAddContact(BaseChatCommand):
    user_id: UserId
    short: CreateShortLink
    incognito: IncognitoEnabled
    def format(self) -> str:
        return "/_connect " + A.decimal(self.user_id) + shortOnOffP(self.short) + incognitoOnOffP(self.incognito)

class AddContact(BaseChatCommand):
    short: CreateShortLink
    incognito: IncognitoEnabled
    def format(self) -> str:
        return "/connect" + shortP(self.short) + incognitoP(self.incognito)

class APISetConnectionIncognito(BaseChatCommand):
    connection_id: int
    incognito: IncognitoEnabled
    def format(self) -> str:
        return "/_set incognito :" + A.decimal(self.connection_id) + A.space + onOffP(self.incognito)

class APIChangeConnectionUser(BaseChatCommand):
    connection_id: int
    user_id: UserId
    def format(self) -> str:
        return "/_set conn user :" + A.decimal(self.connection_id) + A.space + A.decimal(self.user_id)

class APIConnectPlan(BaseChatCommand):
    user_id: UserId
    a_connection_link: AConnectionLink
    def format(self) -> str:
        return "/_connect plan " + A.decimal + A.space + strP

class APIConnect(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    a_created_conn_link: Optional[ACreatedConnLink]
    def format(self) -> str:
        return "/_connect " + A.decimal + incognitoOnOffP + A.space + connLinkP

class Connect(BaseChatCommand):
    incognito: IncognitoEnabled
    a_connection_link: Optional[AConnectionLink]
    def format(self) -> str:
        return ("/connect" <|> "/c") + (  incognitoP + A.space + ((Just  strP) <|> A.takeTill isSpace  Nothing))

class APIConnectContactViaAddress(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    contact_id: ContactId
    def format(self) -> str:
        return "/_connect contact " + A.decimal(self.user_id) + incognitoOnOffP(self.incognito) + A.space + A.decimal(self.contact_id)

class ConnectSimplex(BaseChatCommand):
    incognito: IncognitoEnabled
    def format(self) -> str:
        return "/simplex" + incognitoP(self.incognito)

class DeleteContact(BaseChatCommand):
    contact_name: ContactName
    mode: ChatDeleteMode
    def format(self) -> str:
        return "/delete " + char_('@') + displayNameP(self.contact_name) + chatDeleteMode(self.mode)

class ClearContact(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/clear " + char_('@') + displayNameP(self.contact_name)

class APIListContacts(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_contacts " + A.decimal(self.user_id)

class ListContacts(BaseChatCommand):
    def format(self) -> str:
        return "/contacts"

class APICreateMyAddress(BaseChatCommand):
    user_id: UserId
    short: CreateShortLink
    def format(self) -> str:
        return "/_address " + A.decimal(self.user_id) + shortOnOffP(self.short)

class CreateMyAddress(BaseChatCommand):
    short: CreateShortLink
    def format(self) -> str:
        return "/address" + shortP(self.short)

class APIDeleteMyAddress(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_delete_address " + A.decimal(self.user_id)

class DeleteMyAddress(BaseChatCommand):
    def format(self) -> str:
        return "/delete_address"

class APIShowMyAddress(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_show_address " + A.decimal(self.user_id)

class ShowMyAddress(BaseChatCommand):
    def format(self) -> str:
        return "/show_address"

class APISetProfileAddress(BaseChatCommand):
    user_id: UserId
    on_or_off: bool
    def format(self) -> str:
        return "/_profile_address " + A.decimal(self.user_id) + A.space + onOffP(self.on_or_off)

class SetProfileAddress(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return "/profile_address " + onOffP(self.on_or_off)

class APIAddressAutoAccept(BaseChatCommand):
    user_id: UserId
    auto_accept: Optional[AutoAccept]
    def format(self) -> str:
        return "/_auto_accept " + A.decimal(self.user_id) + A.space + autoAcceptP(self.auto_accept)

class AddressAutoAccept(BaseChatCommand):
    auto_accept: Optional[AutoAccept]
    def format(self) -> str:
        return "/auto_accept " + autoAcceptP(self.auto_accept)

class AcceptContact(BaseChatCommand):
    incognito: IncognitoEnabled
    contact_name: ContactName
    def format(self) -> str:
        return "/accept" + incognitoP(self.incognito) + A.space + char_('@') + displayNameP(self.contact_name)

class RejectContact(BaseChatCommand):
    contact_name: ContactName
    def format(self) -> str:
        return "/reject " + char_('@') + displayNameP(self.contact_name)

class ForwardMessage(BaseChatCommand):
    to_chat_name: ChatName
    from_contact_name: ContactName
    forwarded_msg: str
    def format(self) -> str:
        return chatNameP(self.to_chat_name) + " <- @" + displayNameP(self.from_contact_name) + A.space + msgTextP(self.forwarded_msg)

class ForwardGroupMessage(BaseChatCommand):
    to_chat_name: ChatName
    from_group_name: GroupName
    from_member_name: Optional[ContactName]
    forwarded_msg: str
    def format(self) -> str:
        if self.from_member_name is not None:
            return chatNameP(self.to_chat_name) + " <- #" + displayNameP(self.from_group_name) + A.space + A.char('@') + displayNameP(self.from_member_name) + A.space + msgTextP(self.forwarded_msg)
        else:
            return chatNameP(self.to_chat_name) + " <- #" + displayNameP(self.from_group_name) + A.space + msgTextP(self.forwarded_msg)

class ForwardLocalMessage(BaseChatCommand):
    to_chat_name: ChatName
    forwarded_msg: str
    def format(self) -> str:
        return chatNameP(self.to_chat_name) + " <- * " + msgTextP(self.forwarded_msg)

class SendMessage(BaseChatCommand):
    chat_name: ChatName
    str: str
    def format(self) -> str:
        return   chatNameP + A.space + msgTextP
        return "/* " + ( (ChatName CTLocal "")  msgTextP)

class SendMemberContactMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    msg_text: str
    def format(self) -> str:
        return "@#" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + A.space + msgTextP(self.msg_text)

class SendLiveMessage(BaseChatCommand):
    chat_name: ChatName
    msg_text: str
    def format(self) -> str:
        return "/live " + chatNameP(self.chat_name) + A.space + msgTextP(self.msg_text)

class SendMessageQuote(BaseChatCommand):
    contact_name: ContactName
    msg_dir: AMsgDirection
    quoted_msg: str
    message: str
    def format(self) -> str:
        return (">@" <|> "> @") +  (AMsgDirection SMDRcv)
        return (">>@" <|> ">> @") +  (AMsgDirection SMDSnd)

class SendMessageBroadcast(BaseChatCommand):
    msg_content: MsgContent
    def format(self) -> str:
        return "/feed " + ( . MCText  msgTextP)

class DeleteMessage(BaseChatCommand):
    chat_name: ChatName
    str: str
    def format(self) -> str:
        return ("\\ " <|> "\\") + (  chatNameP + A.space + textP)

class DeleteMemberMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    str: str
    def format(self) -> str:
        return ("\\\\ #" <|> "\\\\#") + (  displayNameP + A.space + char_('@') + displayNameP + A.space + textP)

class EditMessage(BaseChatCommand):
    chat_name: ChatName
    edited_msg: Text
    message: Text
    def format(self) -> str:
        return ("! " <|> "!") + (  chatNameP + A.space + (quotedMsg <|> pure "") + msgTextP)

class UpdateLiveMessage(BaseChatCommand):
    chat_name: ChatName
    chat_item_id: ChatItemId
    live_message: bool
    message: str
    def format(self) -> str:
        # TODO no parsing?
        raise NotImplementedError()

class ReactToMessage(BaseChatCommand):
    add: bool
    reaction: MsgReaction
    chat_name: ChatName
    react_to_message: str
    def format(self) -> str:
        return ("+" if self.add else "-") + reactionP(self.reaction) + A.space + chatNameP_(self.chat_name) + A.space + textP(self.react_to_message)

class APINewGroup(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    group_profile: GroupProfile
    def format(self) -> str:
        return "/_group " + A.decimal(self.user_id) + incognitoOnOffP(self.incognito) + A.space + jsonP(self.group_profile)

class NewGroup(BaseChatCommand):
    incognito: IncognitoEnabled
    group_profile: GroupProfile
    def format(self) -> str:
        return "/group" + incognitoP(self.incognito) + A.space + char_('#') + groupProfile(self.group_profile)

class AddMember(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    role: GroupMemberRole = "member"
    def format(self) -> str:
        return "/add " + char_('#') + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + memberRole(self.role)

class JoinGroup(BaseChatCommand):
    group_name: GroupName
    enable_ntfs: MsgFilter
    def format(self) -> str:
        if self.enable_ntfs == "none": ntfs_part = " mute"
        elif self.enable_ntfs == "all": ntfs_part = ""
        else: raise ValueError(f"Invalid value: {self.enable_ntfs}")  # No "mentions"?

        return "/join " + char_('#') + displayNameP(self.group_name) + ntfs_part

class MemberRole(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    role: GroupMemberRole
    def format(self) -> str:
        return "/member role " + char_('#') + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + memberRole(self.role)

class BlockForAll(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    block: bool
    def format(self) -> str:
        if self.block:
            return "/block for all #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)
        else:
            return "/unblock for all #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name)

class RemoveMembers(BaseChatCommand):
    group_name: GroupName
    members: Set ContactName
    with_messages: Bool
    def format(self) -> str:
        return ("/remove " <|> "/rm ") + char_('#') + (  displayNameP + A.space + (S.fromList  (char_('@') + displayNameP) `A.sepBy1\'` A.char ',') + (" messages=" + onOffP <|> pure False))

class LeaveGroup(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/leave " + char_('#') + displayNameP(self.group_name)

class DeleteGroup(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/delete #" + displayNameP(self.group_name)

class ClearGroup(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/clear #" + displayNameP(self.group_name)

class ListMembers(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/members " + char_('#') + displayNameP(self.group_name)

class APIListGroups(BaseChatCommand):
    user_id: UserId
    contact_id: Optional[ContactId]
    search: Optional[str]
    def format(self) -> str:
        return "/_groups" + A.decimal(self.user_id) + optional(self.contact_id, lambda c: " @" + A.decimal(c)) + optional(self.search, lambda s: A.space + stringP(s))

class ListGroups(BaseChatCommand):
    contact_name: Optional[ContactName]
    search: Optional[str]
    def format(self) -> str:
        return "/groups" + optional(self.contact_name, lambda c: " @" + displayNameP(c)) + optional(self.search, lambda s: A.space + stringP(s))

class UpdateGroupNames(BaseChatCommand):
    group_name: GroupName
    group_profile: GroupProfile
    def format(self) -> str:
        return "/group_profile " + char_('#') + displayNameP(self.group_name) + A.space + groupProfile(self.group_profile)

class ShowGroupProfile(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/group_profile " + char_('#') + displayNameP(self.group_name)

class UpdateGroupDescription(BaseChatCommand):
    group_name: GroupName
    description: Optional[str]
    def format(self) -> str:
        return "/group_descr " + char_('#') + displayNameP(self.group_name) + optional(self.description, lambda d: A.space + msgTextP(d))

class ShowGroupDescription(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/show welcome " + char_('#') + displayNameP(self.group_name)

class CreateGroupLink(BaseChatCommand):
    group_name: GroupName
    role: GroupMemberRole = "member"
    short: CreateShortLink
    def format(self) -> str:
        return "/create link #" + displayNameP(self.group_name) + memberRole(self.role) + shortP(self.short)

class GroupLinkMemberRole(BaseChatCommand):
    group_name: GroupName
    role: GroupMemberRole
    def format(self) -> str:
        return "/set link role #" + displayNameP(self.group_name) + memberRole(self.role)

class DeleteGroupLink(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/delete link #" + displayNameP(self.group_name)

class ShowGroupLink(BaseChatCommand):
    group_name: GroupName
    def format(self) -> str:
        return "/show link #" + displayNameP(self.group_name)

class SendGroupMessageQuote(BaseChatCommand):
    group_name: GroupName
    contact_name_: Optional[ContactName]
    quoted_msg: str
    message: str
    def format(self) -> str:
        return (">#" <|> "> #") + (  displayNameP + A.space + pure Nothing + quotedMsg + msgTextP)
        return (">#" <|> "> #") + (  displayNameP + A.space + char_('@') + (Just  displayNameP) + A.space + quotedMsg + msgTextP)

class ClearNoteFolder(BaseChatCommand):
    def format(self) -> str:
        return "/clear *"

class LastChats(BaseChatCommand):
    count: Optional[int] = 20
    def format(self) -> str:
        return "/chats" + (" all" if self.count is None else (A.space + A.decimal(self.count)))

class LastMessages(BaseChatCommand):
    chat_name: Optional[ChatName]
    count: int
    search: Optional[str]
    def format(self) -> str:
        if self.search is None:
            return "/tail" + optional(self.chat_name, lambda c: A.space + chatNameP(c)) + msgCountP(self.count)
        else:
            return "/search" + optional(self.chat_name, lambda c: A.space + chatNameP(c)) + msgCountP(self.count) + A.space + stringP(self.search)

class LastChatItemId(BaseChatCommand):
    chat_name: Optional[ChatName]
    index: int = 0
    def format(self) -> str:
        return "/last_item_id" + optional(self.chat_name, lambda c: A.space + chatNameP(c)) + A.space + A.decimal(self.index)

class ShowChatItem(BaseChatCommand):
    chat_item_id: Optional[ChatItemId]
    def format(self) -> str:
        if self.chat_item_id is None:
            raise ValueError("Item ID chan't be None")  # Why?
        return "/show " + A.decimal(self.chat_item_id)

class ShowChatItemInfo(BaseChatCommand):
    chat_name: ChatName
    msg: str
    def format(self) -> str:
        return "/item info " + chatNameP(self.chat_name) + A.space + msgTextP(self.msg)

class ShowLiveItems(BaseChatCommand):
    on_or_off: bool = True
    def format(self) -> str:
        return "/show" + A.space + onOffP(self.on_or_off)

class SendFile(BaseChatCommand):
    chat_name: ChatName
    crypto_file: CryptoFile
    def format(self) -> str:
        return "/file " + chatNameP_(self.chat_name) + A.space + cryptoFileP(self.crypto_file)

class SendImage(BaseChatCommand):
    chat_name: ChatName
    crypto_file: CryptoFile
    def format(self) -> str:
        return "/image " + chatNameP_(self.chat_name) + A.space + cryptoFileP(self.crypto_file)

class ForwardFile(BaseChatCommand):
    chat_name: ChatName
    file_transfer_id: FileTransferId
    def format(self) -> str:
        return "/fforward " + chatNameP_(self.chat_name) + A.space + A.decimal(self.file_transfer_id)

class ForwardImage(BaseChatCommand):
    chat_name: ChatName
    file_transfer_id: FileTransferId
    def format(self) -> str:
        return "/image_forward " + chatNameP_(self.chat_name) + A.space + A.decimal(self.file_transfer_id)

class SendFileDescription(BaseChatCommand):
    chat_name: ChatName
    file_path: FilePath
    def format(self) -> str:
        return "/fdescription " + chatNameP_(self.chat_name) + A.space + filePath(self.file_path)

class ReceiveFile(BaseChatCommand):
    file_id: FileTransferId
    user_approved_relays: bool = False
    store_encrypted: Optional[bool]
    file_inline: Optional[bool]
    file_path: Optional[FilePath]
    def format(self) -> str:
        return "/freceive " + A.decimal(self.file_id) + \
            (" approved_relays=" + onOffP(self.user_approved_relays)) + \
            optional (self.store_encrypted, lambda e: " encrypt=" + onOffP(e)) + \
            optional (self.file_inline, lambda i: " inline=" + onOffP(i)) + \
            optional (self.file_path, lambda p: A.space + filePath(p))

class SetFileToReceive(BaseChatCommand):
    file_id: FileTransferId
    user_approved_relays: bool = False
    store_encrypted: Optional[bool]
    def format(self) -> str:
        return "/_set_file_to_receive " + A.decimal(self.file_id) + (" approved_relays=" + onOffP(self.user_approved_relays)) + optional(self.store_encrypted, lambda e: " encrypt=" + onOffP(e))

class CancelFile(BaseChatCommand):
    file_transfer_id: FileTransferId
    def format(self) -> str:
        return "/fcancel " + A.decimal(self.file_transfer_id)

class FileStatus(BaseChatCommand):
    file_transfer_id: FileTransferId
    def format(self) -> str:
        return "/fstatus " + A.decimal(self.file_transfer_id)

class ShowProfile(BaseChatCommand):
    def format(self) -> str:
        return "/profile"

class UpdateProfile(BaseChatCommand):
    display_name: ContactName
    full_name: str
    def format(self) -> str:
        return "/profile " + profileNames(self.display_name, self.full_name)

class UpdateProfileImage(BaseChatCommand):
    image_data: Optional[ImageData]
    def format(self) -> str:
        if self.image_data is not None:
            return "/set profile image " + imageP(self.image_data)
        else:
            return "/delete profile image"

class ShowProfileImage(BaseChatCommand):
    def format(self) -> str:
        return "/show profile image"

class SetUserFeature(BaseChatCommand):
    a_chat_feature: AChatFeature
    feature_allowed: FeatureAllowed
    def format(self) -> str:
        return "/set voice " + ( (ACF SCFVoice)  strP)
        return "/set calls " + ( (ACF SCFCalls)  strP)
        return "/set delete " + ( (ACF SCFFullDelete)  strP)

class SetContactFeature(BaseChatCommand):
    a_chat_feature: AChatFeature
    contact_name: ContactName
    feature_allowed: Optional[FeatureAllowed]
    def format(self) -> str:
        return "/set voice @" + ( (ACF SCFVoice)  displayNameP + optional (A.space + strP))
        return "/set calls @" + ( (ACF SCFCalls)  displayNameP + optional (A.space + strP))
        return "/set delete @" + ( (ACF SCFFullDelete)  displayNameP + optional (A.space + strP))

class SetGroupFeature(BaseChatCommand):
    a_group_feature_no_role: AGroupFeatureNoRole
    group_name: GroupName
    group_feature_enabled: GroupFeatureEnabled
    def format(self) -> str:
        return "/set history #" + ( (AGFNR SGFHistory)  displayNameP + (A.space + strP))
        return "/set reactions #" + ( (AGFNR SGFReactions)  displayNameP + (A.space + strP))
        return "/set reports #" + ( (AGFNR SGFReports)  displayNameP + _strP)

class SetGroupFeatureRole(BaseChatCommand):
    a_group_feature_role: AGroupFeatureRole
    group_name: GroupName
    group_feature_enabled: GroupFeatureEnabled
    role: Optional[GroupMemberRole]
    def format(self) -> str:
        return "/set voice #" + ( (AGFR SGFVoice)  displayNameP + _strP + optional memberRole)
        return "/set files #" + ( (AGFR SGFFiles)  displayNameP + _strP + optional memberRole)
        return "/set delete #" + ( (AGFR SGFFullDelete)  displayNameP + _strP + optional memberRole)
        return "/set direct #" + ( (AGFR SGFDirectMessages)  displayNameP + _strP + optional memberRole)
        return "/set links #" + ( (AGFR SGFSimplexLinks)  displayNameP + _strP + optional memberRole)

class SetUserTimedMessages(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return "/set disappear " + ("yes" if self.on_or_off else "no")

class SetContactTimedMessages(BaseChatCommand):
    contact_name: ContactName
    timed_messages_enabled: Optional[TimedMessagesEnabled]
    def format(self) -> str:
        return "/set disappear @" + displayNameP(self.contact_name) + optional(self.timed_messages_enabled, lambda t: A.space + timedMessagesEnabledP(t))

class SetGroupTimedMessages(BaseChatCommand):
    group_name: GroupName
    ttl: Optional[int]
    def format(self) -> str:
        return "/set disappear #" + displayNameP(self.group_name) + A.space + timedTTLOnOffP(self.ttl)

class SetLocalDeviceName(BaseChatCommand):
    name: str
    def format(self) -> str:
        return "/set device name " + textP(self.name)

class ListRemoteHosts(BaseChatCommand):
    def format(self) -> str:
        return "/list remote hosts"

class StartRemoteHost(BaseChatCommand):
    remote_host_id, bool: Optional[RemoteHostId, Bool]
    rc_ctrl_address: Optional[RCCtrlAddress]
    word16: Optional[Word16]
    def format(self) -> str:
        return "/start remote host " + ("new"  Nothing <|> (Just  ((,)  A.decimal + (" multicast=" + onOffP <|> pure False)))) + optional (A.space + rcCtrlAddressP) + optional (" port=" + A.decimal)

class SwitchRemoteHost(BaseChatCommand):
    remote_host_id: Optional[RemoteHostId]
    def format(self) -> str:
        return "/switch remote host " + ("local" if self.remote_host_id is None else A.decimal(self.remote_host_id))

class StopRemoteHost(BaseChatCommand):
    rh_key: RHKey
    def format(self) -> str:
        return "/stop remote host " + ("new"  RHNew <|> RHId  A.decimal)

class DeleteRemoteHost(BaseChatCommand):
    remote_host_id: RemoteHostId
    def format(self) -> str:
        return "/delete remote host " + A.decimal(self.remote_host_id)

class StoreRemoteFile(BaseChatCommand):
    remote_host_id: RemoteHostId
    store_encrypted: Optional[bool]
    local_path: FilePath
    def format(self) -> str:
        return "/store remote file " + A.decimal(self.remote_host_id) + optional(self.store_encrypted, lambda e: " encrypt=" + onOffP(e)) + A.space + filePath(self.local_path)

class GetRemoteFile(BaseChatCommand):
    remote_host_id: RemoteHostId
    file: RemoteFile
    def format(self) -> str:
        return "/get remote file " + A.decimal(self.remote_host_id) + A.space + jsonP(self.file)

class ConnectRemoteCtrl(BaseChatCommand):
    rc_signed_invitation: RCSignedInvitation
    def format(self) -> str:
        return "/connect remote ctrl "  + strP(self.rc_signed_invitation)

class FindKnownRemoteCtrl(BaseChatCommand):
    def format(self) -> str:
        return "/find remote ctrl"

class ConfirmRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId
    def format(self) -> str:
        return "/confirm remote ctrl " + A.decimal(self.remote_ctrl_id)

class VerifyRemoteCtrlSession(BaseChatCommand):
    session_id: str
    def format(self) -> str:
        return "/verify remote ctrl " + textP(self.session_id)

class ListRemoteCtrls(BaseChatCommand):
    def format(self) -> str:
        return "/list remote ctrls"

class StopRemoteCtrl(BaseChatCommand):
    def format(self) -> str:
        return "/stop remote ctrl"

class DeleteRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId
    def format(self) -> str:
        return "/delete remote ctrl " + A.decimal(self.remote_ctrl_id)

class APIUploadStandaloneFile(BaseChatCommand):
    user_id: UserId
    crypto_file: CryptoFile
    def format(self) -> str:
        return "/_upload " + A.decimal(self.user_id) + A.space + cryptoFileP(self.crypto_file)

class APIDownloadStandaloneFile(BaseChatCommand):
    user_id: UserId
    file_description_uri: FileDescriptionURI
    crypto_file: CryptoFile
    def format(self) -> str:
        return "/_download " + A.decimal(self.user_id) + A.space + strP_(self.file_description_uri) + cryptoFileP(self.crypto_file)

class APIStandaloneFileInfo(BaseChatCommand):
    file_description_uri: FileDescriptionURI
    def format(self) -> str:
        return "/_download info " + strP(self.file_description_uri)

class QuitChat(BaseChatCommand):
    def format(self) -> str:
        return "/quit"

class ShowVersion(BaseChatCommand):
    def format(self) -> str:
        return "/version"

class DebugLocks(BaseChatCommand):
    def format(self) -> str:
        return "/debug locks"

class DebugEvent(BaseChatCommand):
    chat_event: ChatEvent
    def format(self) -> str:
        return "/debug event " + jsonP(self.chat_event)

class GetAgentSubsTotal(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/get subs total " + A.decimal(self.user_id)

class GetAgentServersSummary(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/get servers summary " + A.decimal(self.user_id)

class ResetAgentServersStats(BaseChatCommand):
    def format(self) -> str:
        return "/reset servers stats"

class GetAgentSubs(BaseChatCommand):
    def format(self) -> str:
        return "/get subs"

class GetAgentSubsDetails(BaseChatCommand):
    def format(self) -> str:
        return "/get subs details"

class GetAgentWorkers(BaseChatCommand):
    def format(self) -> str:
        return "/get workers"

class GetAgentWorkersDetails(BaseChatCommand):
    def format(self) -> str:
        return "/get workers details"

class GetAgentQueuesInfo(BaseChatCommand):
    def format(self) -> str:
        return "/get queues"

class CustomChatCommand(BaseChatCommand):
    data: bytes
    def format(self) -> str:
        return "//" + A.takeByteString(self.data)
