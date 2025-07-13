import json
from typing import Annotated, Literal, Optional, TypeVar, Union, Callable
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

    def __str__(self) -> str:
        # TODO default values?
        socksProxy = "socks=" + ("off" if self.socksProxy is None else self.socksProxy)
        socksMode = " socks-mode=" + self.socksMode
        hostMode = " host-mode=" + self.hostMode
        requiredHostMode = " required-host-mode" if self.requiredHostMode else ""
        smpProxyMode = (" smp-proxy=" + self.smpProxyMode) if self.smpProxyMode is not None else ""
        smpProxyFallback = (" smp-proxy-fallback=" + self.smpProxyFallback) if self.smpProxyFallback is not None else ""
        smpWebPortServers = (" smp-web-port-servers=" + self.smpWebPortServers) if self.smpWebPortServers is not None else ""
        tcpTimeout = (f" timeout={self.tcpTimeout}") if self.tcpTimeout is not None else ""
        logTLSErrors = f" log={to_on_off(self.logTLSErrors)}"

        return socksProxy + socksMode + hostMode + requiredHostMode + smpProxyMode + smpProxyFallback + smpWebPortServers + tcpTimeout + logTLSErrors

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
    time: Optional[str]  # TODO

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
def jsonP(obj: Union[BaseModel, str]) -> str:
    if isinstance(obj, BaseModel): return obj.model_dump_json()
    elif isinstance(obj, str): return json.dumps(obj)
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
        return "/_user " + A.decimal(self.user_id) + optional(self.user_pwd, lambda p: A.space+jsonP(p))

class SetActiveUser(BaseChatCommand):
    user_name: UserName
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/user " + displayNameP(self.user_name) + optional(self.user_pwd, lambda p: A.space+pwdP(p))

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
        return "/_delete user " + \
            A.decimal(self.user_id) + \
            " del_smp=" + onOffP(self.delete_smp_queues) + \
            optional(self.user_pwd, lambda p: A.space + jsonP(p))

class DeleteUser(BaseChatCommand):
    user_name: UserName
    # Always true
    # delete_smp_queues: bool = True
    user_pwd: Optional[UserPwd]
    def format(self) -> str:
        return "/delete user " + \
            displayNameP(self.user_name) + \
            optional(self.user_pwd, lambda p: A.space + pwdP(p))

class StartChat(BaseChatCommand):
    main_app: bool
    enable_snd_files: bool
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
        return f"/_files_encrypt " + onOffP(self.on_or_off)

class SetContactMergeEnabled(BaseChatCommand):
    on_or_off: bool
    def format(self) -> str:
        return f"/contact_merge " + onOffP(self.on_or_off)

#if !defined(dbPostgres)

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

#endif

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
        return f"/_get tags " + A.decimal(self.user_id)

class APIGetChatItemInfo(BaseChatCommand):
    chat_ref: ChatRef
    chat_item_id: ChatItemId
    def format(self) -> str:
        return "/_get item info " + chatRefP(self.chat_ref) + A.space + A.decimal(self.chat_item_id)

class APIDeleteChatTag(BaseChatCommand):
    chat_tag_id: ChatTagId
    def format(self) -> str:
        return "/_delete tag " + A.decimal(self.chat_tag_id)

class APIArchiveReceivedReports(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_archive reports #" + A.decimal(self.group_id)

class APIUserRead(BaseChatCommand):
    user_id: UserId
    def format(self) -> str:
        return "/_read user " + A.decimal(self.user_id)

class UserRead(BaseChatCommand):
    def format(self) -> str:
        return "/read user"

class APIChatRead(BaseChatCommand):
    chat_ref: ChatRef
    def fromat(self) -> str:
        return "/_read chat " + chatRefP(self.chat_ref)

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
        return "/call " + char_("@") + displayNameP(self.contact_name)

class APIRejectCall(BaseChatCommand):
    contact_id: ContactId
    def format(self) -> str:
        return "/_call reject @" + A.decimal(self.contact_id)

class APISendCallOffer(BaseChatCommand):
    contact_id: ContactId
    offer: WebRTCCallOffer
    def format(self) -> str:
        return f"/_call offer @" + A.decimal(self.contact_id) + A.space + jsonP(self.offer)

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

class APISetContactPrefs(BaseChatCommand):
    contact_id: ContactId
    preferences: Preferences
    def format(self) -> str:
        return "/_set prefs @" + A.decimal(self.contact_id) + A.space + jsonP(self.preferences)

class APISetContactAlias(BaseChatCommand):
    contact_id: ContactId
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias @" + A.decimal(self.contact_id) + A.space + textP(self.local_alias)

class APISetGroupAlias(BaseChatCommand):
    group_id: GroupId
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias #" + A.decimal(self.group_id) + A.space + textP(self.local_alias)

class APISetConnectionAlias(BaseChatCommand):
    connection_id: int
    local_alias: LocalAlias
    def format(self) -> str:
        return "/_set alias :" + A.decimal(self.connection_id) + A.space + textP(self.local_alias)

class APISetUserUIThemes(BaseChatCommand):
    user_id: UserId
    themes: Optional[UIThemeEntityOverrides]
    def format(self) -> str:
        return "/_set theme user " + A.decimal(self.user_id) + optional(self.themes, lambda t: A.space + jsonP(t))

class APISetChatUIThemes(BaseChatCommand):
    chat_ref: ChatRef
    themes: Optional[UIThemeEntityOverrides]
    def format(self) -> str:
        return "/_set theme " + chatRefP(self.chat_ref) + optional(self.themes, lambda t: A.space + jsonP(t))

class APIGetNtfToken(BaseChatCommand):
    def format(self) -> str:
        return "/_ntf get"

class APIGetNtfConns(BaseChatCommand):
    nonce: CbNonce
    enc_ntf_info: str
    def format(self) -> str:
        return "/_ntf conns " + strP(self.nonce) + A.space + strP(self.enc_ntf_info)

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

class APILeaveGroup(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_leave #" + A.decimal(self.group_id)

class APIListMembers(BaseChatCommand):
    group_id: GroupId
    def format(self) -> str:
        return "/_members #" + A.decimal(self.group_id)

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

    def __str__(self) -> str:
        return f"/_delete link #{self.group_id}"

class APICreateMemberContact(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId

    def __str__(self) -> str:
        return f"/_create member contact #{self.group_id} {self.member_id}"

class GetUserProtoServers(BaseChatCommand):
    protocol: AProtocolType

    def __str__(self) -> str:
        if self.protocol == "smp":      t = "smp"
        elif self.protocol == "xftp":   t = "xftp"
        else:
            # TODO why no ntf?
            raise ValueError(f"Invalid protocol: {self.protocol}")

        return f"/{t}"

class SetUserProtoServers(BaseChatCommand):
    protocol: AProtocolType
    servers: list[AProtoServerWithAuth]

    def __str__(self) -> str:
        if self.protocol == "smp":      t = "smp"
        elif self.protocol == "xftp":   t = "xftp"
        else:
            # TODO why no ntf?
            raise ValueError(f"Invalid protocol: {self.protocol}")

        return f"/{t} {' '.join(self.servers)}"

class APITestProtoServer(BaseChatCommand):
    user_id: UserId
    server: AProtoServerWithAuth

    def __str__(self) -> str:
        return f"/_server test {self.user_id} {self.server}"

# class TestProtoServer(BaseChatCommand):
#     server: AProtoServerWithAuth

#     def __str__(self) -> str:
#         return ""

class APIGetServerOperators(BaseChatCommand):
    def format(self) -> str:
        return "/_operators"

class APIGetUserServers(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_servers {self.user_id}"

class APIGetUsageConditions(BaseChatCommand):
    def format(self) -> str:
        return "/_conditions"

class APISetConditionsNotified(BaseChatCommand):
    condition_id: int

    def __str__(self) -> str:
        return f"/_conditions_notified {self.condition_id}"

class APISetChatItemTTL(BaseChatCommand):
    user_id: UserId
    new_ttl: int

    def __str__(self) -> str:
        return f"/_ttl {self.user_id} {self.new_ttl}"

ciTTL = Literal["day", "week", "month", "year", "none"]

class SetChatItemTTL(BaseChatCommand):
    new_ttl: ciTTL

    def __str__(self) -> str:
        return f"/ttl {self.new_ttl}"

class APIGetChatItemTTL(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_ttl {self.user_id}"

class GetChatItemTTL(BaseChatCommand):
    def format(self) -> str:
        return "/ttl"

class APISetChatTTL(BaseChatCommand):
    user_id: UserId
    chat_ref: ChatRef
    new_ttl: Optional[int]

    def __str__(self) -> str:
        ttl = "default" if self.new_ttl is None else str(self.new_ttl)
        return f"/_ttl {self.user_id} {self.chat_ref} {ttl}"

class SetChatTTL(BaseChatCommand):
    chat_name: ChatName
    new_ttl: Optional[ciTTL]

    def __str__(self) -> str:
        ttl = self.new_ttl if self.new_ttl is not None else "default"
        return f"/ttl {self.chat_name} {ttl}"

class GetChatTTL(BaseChatCommand):
    chat_name: ChatName

    def __str__(self) -> str:
        return f"/ttl {self.chat_name}"

class APISetNetworkConfig(BaseChatCommand):
    config: NetworkConfig

    def __str__(self) -> str:
        return f"/_network {self.config.model_dump_json()}"

class SetNetworkConfig(BaseChatCommand):
    config: SimpleNetCfg

    def __str__(self) -> str:
        return f"/network {self.config}"

class APIGetNetworkConfig(BaseChatCommand):
    def format(self) -> str:
        return "/network"

class ReconnectAllServers(BaseChatCommand):
    def format(self) -> str:
        return "/reconnect"

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
    def format(self) -> str:
        return "/welcome"

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
    def format(self) -> str:
        return "/contacts"

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
    def format(self) -> str:
        return "/delete_address"

class APIShowMyAddress(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/_show_address {self.user_id}"

class ShowMyAddress(BaseChatCommand):
    def format(self) -> str:
        return "/show_address"

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

class APINewGroup(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    group_profile: GroupProfile

    def __str__(self) -> str:
        return f"/_group {self.user_id} incognito={to_on_off(self.incognito)} {self.group_profile.model_dump_json()}"

class NewGroup(BaseChatCommand):
    incognito: IncognitoEnabled
    group_profile: GroupProfile  # TODO only displayName and fullName are used

    def __str__(self) -> str:
        incognito = " incognito" if self.incognito else ""
        display_name = quote_display_name(self.group_profile.displayName)
        full_name = (" " + self.group_profile.fullName) if self.group_profile.fullName is not None else ""
        profile = display_name + full_name

        return f"/group{incognito} #{profile}"

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
    def format(self) -> str:
        return "/clear *"

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
    def format(self) -> str:
        return "/profile"

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
    def format(self) -> str:
        return "/show profile image"

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
    def format(self) -> str:
        return "/list remote hosts"

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
    def format(self) -> str:
        return "/find remote ctrl"

class ConfirmRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId

    def __str__(self) -> str:
        return f"/confirm remote ctrl {self.remote_ctrl_id}"

class VerifyRemoteCtrlSession(BaseChatCommand):
    session_id: str

    def __str__(self) -> str:
        return f"/verify remote ctrl {self.session_id}"

class ListRemoteCtrls(BaseChatCommand):
    def format(self) -> str:
        return "/list remote ctrls"

class StopRemoteCtrl(BaseChatCommand):
    def format(self) -> str:
        return "/stop remote ctrl"

class DeleteRemoteCtrl(BaseChatCommand):
    remote_ctrl_id: RemoteCtrlId

    def __str__(self) -> str:
        return f"/delete remote ctrl {self.remote_ctrl_id}"

class QuitChat(BaseChatCommand):
    def format(self) -> str:
        return "/quit"

class ShowVersion(BaseChatCommand):
    def format(self) -> str:
        return "/version"

class DebugLocks(BaseChatCommand):
    def format(self) -> str:
        return "/debug locks"

class GetAgentSubsTotal(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/get subs total {self.user_id}"

class GetAgentServersSummary(BaseChatCommand):
    user_id: UserId

    def __str__(self) -> str:
        return f"/get servers summary {self.user_id}"

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
    command: str

    def __str__(self) -> str:
        return "//" + self.command
