import json
from typing import Annotated, Any, Literal, Optional, Sequence, TypeAlias, TypeVar, Union, Callable
from typing_extensions import TypeAliasType
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
NoteFolderId = int
MemberName = str

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


SProtocolType = Literal["smp", "ntf", "xftp"]
AProtocolType = Literal["smp", "ntf", "xftp"]
BasicAuth = str
KeyHash = str
TransportHost = str  # IPv4 / IPv6 / .onion / domain TODO enforce pattern
ServiceName = str
class ProtocolServer(BaseModel):
    scheme: SProtocolType
    host: list[TransportHost]  # NonEmpty
    port: ServiceName
    keyHash: KeyHash
class ProtoServerWithAuth(BaseModel):
    protoServer: ProtocolServer
    serverBasicAuth: Optional[BasicAuth]
class AProtoServerWithAuth(BaseModel):
    protocol: SProtocolType
    server: ProtoServerWithAuth

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
    # TODO only displayName and fullName used?
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

UTCTime = str
class PTLast(BaseModel):
    count: int
class PTAfter(BaseModel):
    after: UTCTime
    count: int
class PTBefore(BaseModel):
    before: UTCTime
    count: int
PaginationByTime = Union[PTLast, PTAfter, PTBefore]

class CLQFilters(BaseModel):
    favorite: bool
    unread: bool
class CLQSearch(BaseModel):
    search: str
ChatListQuery = Union[CLQFilters, CLQSearch]

MsgContentTag = Union[Literal["text", "link", "image", "video", "file", "voice", "report"], str]


class CPLast(BaseModel):
    count: int
class CPAfter(BaseModel):
    after_id: ChatItemId
    count: int
class CPBefore(BaseModel):
    before_id: ChatItemId
    count: int
class CPAround(BaseModel):
    around_id: ChatItemId
    count: int
class CPInitial(BaseModel):
    count: int
ChatPagination = Union[CPLast, CPAfter, CPBefore, CPAround, CPInitial]


class SRDirect(BaseModel):
    contact_id: ContactId
class SRGroup(BaseModel):
    group_id: GroupId
    member_id: Optional[GroupMemberId]
SendRef = Union[SRDirect, SRGroup]

JSON = TypeAliasType(
    'JSON',
    'Union[dict[str, JSON], list[JSON], str, int, float, bool, None]',
)

ReportReason = Union[Literal["spam", "content", "community", "profile", "other"], str]

class LCPage(BaseModel): pass
class LCImage(BaseModel): pass
class LCVideo(BaseModel):
    duration: Optional[int]
class LCUnknown(BaseModel):
    tag: str
    json_: JSON = Field(alias="json")
LinkContent = Union[LCPage, LCImage, LCVideo, LCUnknown]

class LinkPreview(BaseModel):
    uri: str
    title: str
    description: str
    image: ImageData
    content: Optional[LinkContent]

class MCText(BaseModel):
    text: str
class MCLink(BaseModel):
    text: str
    preview: LinkPreview
class MCImage(BaseModel):
    text: str
    image: ImageData
class MCVideo(BaseModel):
    text: str
    image: ImageData
    duration: int
class MCVoice(BaseModel):
    text: str
    duration: int
class MCFile(BaseModel):
    text: str
class MCReport(BaseModel):
    text: str
    reason: ReportReason
class MCUnknown(BaseModel):
    tag: str
    text: str
    json_: JSON = Field(alias="json")
MsgContent = Union[MCText, MCLink, MCImage, MCVideo, MCVoice, MCFile, MCReport, MCUnknown]


class ComposedMessage(BaseModel):
    fileSource: Optional[CryptoFile]
    quotedItemId: Optional[ChatItemId]
    msgContent: MsgContent
    mentions: dict[MemberName, GroupMemberId]

class ChatTagData(BaseModel):
    emoji: Optional[str]
    text: str

class UpdatedMessage(BaseModel):
    msgContent: MsgContent
    mentions: dict[MemberName, GroupMemberId]

CIDeleteMode = Literal["broadcast", "internal", "internalMark"]


MREmojiChar = Annotated[str, StringConstraints(min_length=1, max_length=1)]
class MREmoji(BaseModel):
    emoji: MREmojiChar
class MRUnknown(BaseModel):
    tag: str
    json_: JSON = Field(alias="json")  # J.Object
MsgReaction = Union[MREmoji, MRUnknown]

PushProvider = Literal["apns_dev", "apns_prod", "apns_test", "apns_null"]
class DeviceToken(BaseModel):
    push_provider: PushProvider
    token: bytes

class AutoAccept(BaseModel):
    businessAddress: bool  # possibly, it can be wrapped together with acceptIncognito, or AutoAccept made sum type
    acceptIncognito: IncognitoEnabled
    autoReply: Optional[MsgContent]

AMsgDirection = Literal["snd", "rcv"]

class RCCtrlAddress(BaseModel):
    address: TransportHost  # allows any interface when found exactly
    interface: str

ciTTL_t = Optional[Literal["day", "week", "month", "year", "none"]]

ChatFeature = Literal["timedMessages", "fullDelete", "reactions", "voice", "calls"]
SChatFeature = ChatFeature
AChatFeature = SChatFeature

GroupFeature = Literal["timedMessages", "directMessages", "fullDelete", "reactions", "voice", "files", "simplexLinks", "reports", "history"]
SGroupFeature = GroupFeature
AGroupFeature = SGroupFeature
AGroupFeatureNoRole = SGroupFeature
AGroupFeatureRole = SGroupFeature

NotificationsMode = Literal["PERIODIC", "INSTANT"]

ConnId = bytes
class ConnMsgReq(BaseModel):
    msgConnId: ConnId
    msgDbQueueId: int
    msgTs: Optional[UTCTime]

class CAAccepted(BaseModel):
    acceptedAt: Optional[UTCTime]
    autoAccepted: bool
class CARequired(BaseModel):
    deadline: Optional[UTCTime]
ConditionsAcceptance = Union[CAAccepted, CARequired]
class ServerRoles(BaseModel):
    storage: bool
    proxy: bool
OperatorTag = Literal["simplex", "flux"]
DBEntityId_stored = int
class ServerOperator(BaseModel):
    operatorId: DBEntityId_stored
    operatorTag: Optional[OperatorTag]
    tradeName: str
    legalName: Optional[str]
    serverDomains: list[str]
    conditionsAcceptance: ConditionsAcceptance
    enabled: bool
    smpRoles: ServerRoles
    xftpRoles: ServerRoles

class AUserServer(BaseModel):
    serverId: DBEntityId_stored
    server: ProtoServerWithAuth
    preset: bool
    tested: Optional[bool]
    enabled: bool
    deleted: bool
class UpdatedUserOperatorServers(BaseModel):
    operator: Optional[ServerOperator]
    smpServers: list[AUserServer]  # TODO PSMP
    xftpServers: list[AUserServer]  # TODO PXFTP

RCSignedInvitation = str  # TODO

class TMEEnableSetTTL(BaseModel):
    ttl: int
TimedMessagesEnabled = Union[TMEEnableSetTTL, Literal["enable", "disable"]]

class ServerOperatorRoles(BaseModel):
    operatorId: int
    enabled: bool
    smpRoles: ServerRoles
    xftpRoles: ServerRoles

class RemoteFile(BaseModel):
    userId: int
    fileId: int
    sent: bool
    fileSource: CryptoFile

ServiceScheme = str  # TODO "simplex:" or "https://{server}"
FileClientData = str
ValidFileDescription = str  # TODO
class FileDescriptionURI(BaseModel):
    scheme: ServiceScheme
    description: ValidFileDescription
    clientData: Optional[FileClientData]  # JSON-encoded extensions to pass in a link

class RHNew(BaseModel): pass
class RHId(BaseModel): remoteHostId: RemoteHostId
RHKey = Union[RHNew, RHId]

ChatEvent = Any  # TODO !!!!!!


UserNetworkType = Literal["none", "cellular", "wifi", "ethernet", "other"]
class UserNetworkInfo(BaseModel):
    networkType: UserNetworkType
    online: bool

SMPServer = ProtocolServer

class ChatSettings(BaseModel):
    enableNtfs: MsgFilter
    sendRcpts: Optional[bool]
    favorite: bool

class GroupMemberSettings(BaseModel):
    showMessages: bool

ConnectionRequestUri = str  # TODO
ConnShortLink = str  # TODO
SConnectionMode = Literal["invitation", "contact"]
class CLFull(BaseModel): link: ConnectionRequestUri
class CLShort(BaseModel): link: ConnShortLink
ConnectionLink = Union[CLFull, CLShort]
class CreatedConnLink(BaseModel):
    connFullLink: ConnectionRequestUri
    connShortLink: Optional[ConnShortLink]
class ACreatedConnLink(BaseModel):
    mode: SConnectionMode
    link: CreatedConnLink
class AConnectionLink(BaseModel):
    mode: SConnectionMode
    link: ConnectionLink

# -------------------------------------------------------------

T = TypeVar("T")

class A:
    space = " "
    @staticmethod
    def decimal(n: int) -> str: return str(n)
    @staticmethod
    def char(c: str) -> str:
        if len(c) != 1:
            raise ValueError(f"Not a character: {c}")
        return c
    @staticmethod
    def takeByteString(b: bytes) -> str:
        return b.decode("utf-8")
def AsepBy1(): ...
def Achar(): ...
def AtakeTill(): ...

def char_(c: str) -> str: return A.char(c)  # Can also return ""
def textP(s: str) -> str: return s

strP_t = Union[str, bytes, list[int], set[int], DeviceToken, int, AProtoServerWithAuth, ProtoServerWithAuth, FileDescriptionURI]
def strP(s: strP_t) -> str:  # TODO base64?
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode("utf-8")
    elif isinstance(s, int):
        return str(s)
    elif isinstance(s, list) and s and isinstance(s[0], int):
        return ",".join(str(x) for x in s)
    elif isinstance(s, set) and s and isinstance(next(iter(s)), int):
        return ",".join(str(x) for x in s)
    elif isinstance(s, DeviceToken):
        return s.push_provider + " " + s.token.decode("utf-8")
    elif isinstance(s, AProtoServerWithAuth):
        return strP(s.server)
    elif isinstance(s, ProtoServerWithAuth):
        ser = s.protoServer
        scheme, host, port, keyHash, auth = ser.scheme, ser.host, ser.port, ser.keyHash, s.serverBasicAuth
        return strEncodeServer(scheme, host, port, keyHash, auth)
    elif isinstance(s, FileDescriptionURI):
        raise NotImplementedError("strP(FileDescriptionURI)")
        # strEncode FileDescriptionURI {scheme, description, clientData} = mconcat [strEncode scheme, "/file", "#/?", queryStr]
        # where
        #     queryStr = strEncode $ QSP QEscape qs
        #     qs = ("desc", strEncode description) : maybe [] (\cd -> [("data", encodeUtf8 cd)]) clientData
        # strP = do
        #     scheme <- strP
        #     _ <- "/file" <* optional (A.char '/') <* "#/?"
        #     query <- strP
        #     description <- queryParam "desc" query
        #     let clientData = safeDecodeUtf8 <$> queryParamStr "data" query
        #     pure FileDescriptionURI {scheme, description, clientData}
    else:
        raise TypeError(f"Bad input for strP: {s}")

def strEncodeServer(scheme: str, host: list[TransportHost], port: str, keyHash: str, auth: Optional[BasicAuth]) -> str:
    return scheme + "://" + keyHash + optional(auth, lambda a: ":" + a) + "@" + ",".join(host) + ":" + port
def _strP(s: strP_t) -> str: return A.space + strP(s)
def strP_(s: strP_t) -> str: return strP(s) + A.space
def jsonP(obj: Union[BaseModel, Sequence[BaseModel], JSON]) -> str:
    if isinstance(obj, BaseModel):
        return obj.model_dump_json()
    elif isinstance(obj, list) and obj and isinstance(obj[0], BaseModel):
        obj2: list[BaseModel] = obj  # type: ignore
        return jsonP([item.model_dump() for item in obj2])
    else:
        return json.dumps(obj)
def stringP(s: str) -> str: return s

def optional(maybe: Optional[T], transform: Callable[[T], str]=str):
    return transform(maybe) if maybe is not None else ""

def onOffP(b: bool) -> str: return "on" if b else "off"
def shortP(b: bool) -> str: return A.space + "short" if b else ""
def incognitoP(b: bool) -> str: return A.space + "incognito" if b else ""
def shortOnOffP(b: bool) -> str: return A.space + "short=" + onOffP(b)
def incognitoOnOffP(b: bool) -> str: return A.space + "incognito=" + onOffP(b)
def liveMessageP(b: bool) -> str: return " live=" + onOffP(b)

def sendMessageTTLP(ttl: Optional[int]):
    return (" ttl=" + A.decimal(ttl)) if ttl is not None else "default"
msgTextP = jsonP
def msgContentP(mc: MsgContent) -> str: return "json " + jsonP(mc)
def composedMessagesTextP(): ...
def updatedMessagesTextP(): ...
def quotedMsg(msg: str) -> str:
    if ")" in msg:
        raise ValueError(f"Unquotable quoted message: {msg}")
    return A.char('(') + msg + A.char(')') + A.space

def chatTypeP(ct: ChatType) -> str:
    if ct == "direct": return A.char('@')
    elif ct == "group": return A.char('#')
    elif ct == "local": return A.char('*')
    elif ct == "contactConnection": return A.char(':')
    else: raise ValueError(f"Bad ChatType: {ct}")

def chatNameP(cn: ChatName):
    result = chatTypeP(cn.chatType)
    if cn.chatType == "local":
        result += ""
    else:
        result += displayNameP(cn.chatName)
    return result
def chatNameP_(cn: ChatName) -> str:
    return chatTypeP(cn.chatType) + displayNameP(cn.chatName)

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
def paginationByTimeP(pt: PaginationByTime) -> str:
    if isinstance(pt, PTLast):
        return " count=" + A.decimal(pt.count)
    elif isinstance(pt, PTAfter):
        return "after=" + strP(pt.after) + A.space + "count=" + A.decimal(pt.count)
    elif isinstance(pt, PTBefore):
        return "before=" + strP(pt.before) + A.space + "count=" + A.decimal(pt.count)
    else:
        raise ValueError(f"Invalid pagination by time: {pt}")

def chatRefP(ref: ChatRef) -> str: return ref
def chatPaginationP(p: ChatPagination):
        if isinstance(p, CPLast):
            return "count=" + A.decimal(p.count)
        elif isinstance(p, CPAfter):
            return "after=" + A.decimal(p.after_id) + A.space + "count=" + A.decimal(p.count)
        elif isinstance(p, CPBefore):
            return "before=" + A.decimal(p.before_id) + A.space + "count=" + A.decimal(p.count)
        elif isinstance(p, CPAround):
            return "around=" + A.decimal(p.around_id) + A.space + "count=" + A.decimal(p.count)
        elif isinstance(p, CPInitial):
            return "initial=" + A.decimal(p.count)
        else:
            raise ValueError(f"Invalid pagination: {p}")
def sendRefP(ref: SendRef):
        if isinstance(ref, SRDirect):
            return A.char('@') + A.decimal(ref.contact_id)
        elif isinstance(ref, SRGroup):
            return A.char('#') + A.decimal(ref.group_id) + optional(ref.member_id, lambda m: " @" + A.decimal(m))
        else:
            raise ValueError(f"Invalid send ref: {ref}")
def knownReaction(): ...
def chatDeleteMode(mode: ChatDeleteMode):
    if (mode.mode == "messages") != (mode.notify is not None):
        raise ValueError(f"Invalid delete mode: {mode.mode}_{mode.notify}")
    return " "+mode.mode + optional(mode.notify, lambda n: " notify=" + onOffP(n))

def connMsgP(msg: ConnMsgReq) -> str:
    if msg.msgTs is None:
        raise TypeError(f"Invalid ConnMsgReq ts=None")  # TODO enforce in type?
    return \
        strP(msg.msgConnId) + A.char(':') + \
        strP(msg.msgDbQueueId) + A.char(':') + \
        strP(msg.msgTs)
def connMsgsP(msgs: list[ConnMsgReq]) -> str: return ",".join(connMsgP(m) for m in msgs)
def memberRole(role: GroupMemberRole) -> str: return " " + role
def protocolServersP(servers: list[AProtoServerWithAuth]) -> str:
    return " ".join(strP(server) for server in servers)
def srvRolesP(roles: ServerRoles) -> str:
    if   not roles.storage and not roles.proxy:
        return "off"
    elif not roles.storage and     roles.proxy:
        return "proxy"
    elif     roles.storage and not roles.proxy:
        return "storage"
    elif     roles.storage and     roles.proxy:
        return "on"
    else:
        raise Exception("Unreachable")

def operatorRolesP(roles: ServerOperatorRoles) -> str:
    return \
        A.decimal(roles.operatorId) + \
        A.char(':') + onOffP(roles.enabled) + \
        ":smp=" + srvRolesP(roles.smpRoles) + \
        ":xftp=" + srvRolesP(roles.xftpRoles)

def ciTTLDecimal(ttl: Optional[int]) -> str: return "default" if ttl is None else A.decimal(ttl)
def ciTTL(ttl: ciTTL_t) -> str: return "none" if ttl is None else ttl
def netCfgP(cfg: SimpleNetCfg) -> str:
    return \
        "socks=" + ("off" if cfg.socksProxy is None else "on" + strP(cfg.socksProxy)) + \
        " socks-mode=" + strP(cfg.socksMode) + \
        " host-mode=" + cfg.hostMode + \
        (" required-host-mode" if cfg.requiredHostMode else "") + \
        optional(cfg.smpProxyMode, lambda m: " smp-proxy=" + strP(m)) + \
        optional(cfg.smpProxyFallback, lambda f: " smp-proxy-fallback=" + strP(f)) + \
        " smp-web-port-servers=" + strP(cfg.smpWebPortServers) + \
        optional(cfg.tcpTimeout, lambda t: " timeout=" + A.decimal(t)) + \
        " log=" + onOffP(cfg.logTLSErrors)

def verifyCodeP(code: VerifyCode) -> str:
    if " " in code:
        raise ValueError(f"Verify code can't contain a space: {code}")
    return code
def groupProfile(profile: GroupProfile) -> str:
    return profileNames(profile.displayName, profile.fullName)
def profileNames(displayName: str, fullName: str) -> str:
    return displayNameP(displayName) + fullNameP(fullName)
def fullNameP(fullName: str) -> str:
    return A.space + textP(fullName)

def connLinkP(): ...
def cryptoFileP(file: CryptoFile) -> str:
      return optional(file.cryptoArgs, lambda a: " key=" + strP(a.fileKey) + A.space + " nonce=" + strP(a.fileNonce)) \
        + filePath(file.filePath)
def autoAcceptP(aa: Optional[AutoAccept]) -> str:
    result = ""
    result += onOffP(aa is not None)
    if aa is not None:
        autoReply = lambda: optional(aa.autoReply, lambda ar: A.space + msgContentP(ar))
        if not aa.businessAddress:
            if aa.acceptIncognito: raise ValueError("Business address can't accept incognito")  # TODO enforce in type?
            result += " business" + autoReply()
        else:
            result += " incognito=" + onOffP(aa.acceptIncognito) + autoReply()
    return result
def msgCountP(count: int) -> str: return A.space + A.decimal(count)

def timedTTLP(ttl: int) -> str: return A.decimal(ttl)
def timedTTLOnOffP(ttl: Optional[int]) -> str:
    if ttl is not None:
        return "on" + A.space + timedTTLP(ttl)
    else:
        return "off"
def timedMessagesEnabledP(tme: TimedMessagesEnabled) -> str:
    if isinstance(tme, TMEEnableSetTTL):
        return "yes" + A.space + timedTTLP(tme.ttl)
    elif tme == "enable":
        return "yes"
    elif tme == "disable":
        return "no"
    else:
        raise ValueError(f"Invalild TimedMessagesEnabled: {tme}")

def reactionP(reaction: MsgReaction) -> str:
    if isinstance(reaction, MRUnknown):
        raise TypeError(f"Unsupported MRUnknown: {reaction}")
    return reaction.emoji

def imageP(img: ImageData) -> str: return img

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
    pagination: PaginationByTime = PTLast(count=5000)
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
    enc_ntf_info: bytes
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
    member_ids: set[GroupMemberId]
    with_messages: bool
    def format(self) -> str:
        return "/_remove #" + A.decimal(self.group_id) + _strP(self.member_ids) + " messages=" + onOffP(self.with_messages)

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
    protocol_type: AProtocolType
    servers: list[AProtoServerWithAuth]
    def format(self) -> str:
        if self.protocol_type == "smp":
            return "/smp " + protocolServersP(self.servers)
        elif self.protocol_type == "xftp":
            return "/xftp " + protocolServersP(self.servers)
        else:
            raise ValueError(f"Invalid protocol type: {self.protocol_type}")

class APITestProtoServer(BaseChatCommand):
    user_id: UserId
    server: AProtoServerWithAuth
    def format(self) -> str:
        return "/_server test " + A.decimal(self.user_id) + A.space + strP(self.server)

class TestProtoServer(BaseChatCommand):
    server: AProtoServerWithAuth
    def format(self) -> str:
        if self.server.protocol == "smp":
            return "/smp test " + strP(self.server.server)
        elif self.server.protocol == "xftp":
            return "/xftp test " + strP(self.server.server)
        elif self.server.protocol == "ntf":
            return "/ntf test " + strP(self.server.server)
        else:
            raise ValueError(f"Invalid protocol type: {self.server.protocol}")

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
        return "/operators " + ",".join(operatorRolesP(role) for role in self.roles)

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
    new_ttl: ciTTL_t
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
    new_ttl: Optional[ciTTL_t]
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
        return "/_network info " + jsonP(self.user_network_info)

class ReconnectAllServers(BaseChatCommand):
    def format(self) -> str:
        return "/reconnect"

class ReconnectServer(BaseChatCommand):
    user_id: UserId
    smp_server: SMPServer
    def format(self) -> str:
        return "/reconnect " + A.decimal(self.user_id) + A.space + strP(self.smp_server)

class APISetChatSettings(BaseChatCommand):
    chat_ref: ChatRef
    settings: ChatSettings
    def format(self) -> str:
        return "/_settings " + chatRefP(self.chat_ref) + A.space + jsonP(self.settings)

class APISetMemberSettings(BaseChatCommand):
    group_id: GroupId
    member_id: GroupMemberId
    settings: GroupMemberSettings
    def format(self) -> str:
        return "/_member settings #" + A.decimal(self.group_id) + A.space + A.decimal(self.member_id) + A.space + jsonP(self.settings)

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
    connection_link: AConnectionLink
    def format(self) -> str:
        return "/_connect plan " + A.decimal(self.user_id) + A.space + strP(self.connection_link)

class APIConnect(BaseChatCommand):
    user_id: UserId
    incognito: IncognitoEnabled
    created_conn_link: Optional[ACreatedConnLink]
    def format(self) -> str:
        return "/_connect " + A.decimal(self.user_id) + incognitoOnOffP(self.incognito) + A.space + connLinkP(self.created_conn_link)

class Connect(BaseChatCommand):
    incognito: IncognitoEnabled
    connection_link: Optional[AConnectionLink]
    def format(self) -> str:
        return "/connect" + incognitoP(self.incognito) + A.space + optional(self.connection_link, strP)

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
    msg: str
    def format(self) -> str:
        return chatNameP(self.chat_name) + A.space + msgTextP(self.msg)

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
        def sendMsgQuote() -> str:
            return displayNameP(self.contact_name) + A.space + quotedMsg(self.quoted_msg) + msgTextP(self.message)

        if self.msg_dir == "rcv":
            return ">@" + sendMsgQuote()
        elif self.msg_dir == "snd":
            return ">>@" + sendMsgQuote()
        else:
            raise ValueError(f"Invalid message direction: {self.msg_dir}")


class SendMessageBroadcast(BaseChatCommand):
    msg_content: MsgContent
    def format(self) -> str:
        return "/feed " + msgTextP(self.msg_content)

class DeleteMessage(BaseChatCommand):
    chat_name: ChatName
    message: str
    def format(self) -> str:
        return "\\ " + chatNameP(self.chat_name) + A.space + textP(self.message)

class DeleteMemberMessage(BaseChatCommand):
    group_name: GroupName
    contact_name: ContactName
    deleted_message: str
    def format(self) -> str:
        return "\\\\ #" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + A.space + textP(self.deleted_message)

class EditMessage(BaseChatCommand):
    chat_name: ChatName
    edited_msg: str
    message: str
    def format(self) -> str:
        return "! " + chatNameP(self.chat_name) + A.space + quotedMsg(self.edited_msg) + msgTextP(self.message)

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
    members: set[ContactName]
    with_messages: bool
    def format(self) -> str:
        return "/remove " + char_('#') + displayNameP(self.group_name) + A.space + ','.join(char_('@') + displayNameP(m) for m in self.members) + " messages=" + onOffP(self.with_messages)

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
    contact_name: Optional[ContactName]
    quoted_msg: str
    message: str
    def format(self) -> str:
        if self.contact_name is None:
            return ">#" + displayNameP(self.group_name)                                                          + A.space + quotedMsg(self.quoted_msg) + msgTextP(self.message)
        else:
            return ">#" + displayNameP(self.group_name) + A.space + char_('@') + displayNameP(self.contact_name) + A.space + quotedMsg(self.quoted_msg) + msgTextP(self.message)

class ClearNoteFolder(BaseChatCommand):
    def format(self) -> str:
        return "/clear *"

class LastChats(BaseChatCommand):
    count: Optional[int] = 20
    def format(self) -> str:
        return "/chats" + (" all" if self.count is None else (A.space + A.decimal(self.count)))

class LastMessages(BaseChatCommand):
    chat_name: Optional[ChatName]
    count: int = 10
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
            optional(self.store_encrypted, lambda e: " encrypt=" + onOffP(e)) + \
            optional(self.file_inline, lambda i: " inline=" + onOffP(i)) + \
            optional(self.file_path, lambda p: A.space + filePath(p))

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
    feature: AChatFeature
    feature_allowed: FeatureAllowed
    def format(self) -> str:
        if self.feature == "voice":
            return "/set voice " + strP(self.feature_allowed)
        elif self.feature == "calls":
            return "/set calls " + strP(self.feature_allowed)
        elif self.feature == "fullDelete":
            return "/set delete " + strP(self.feature_allowed)
        else:
            raise ValueError(f"Illegal feature: {self.feature}")  # TODO

class SetContactFeature(BaseChatCommand):
    feature: AChatFeature
    contact_name: ContactName
    feature_allowed: Optional[FeatureAllowed]
    def format(self) -> str:
        if self.feature == "voice":
            return "/set voice @" + displayNameP(self.contact_name) + optional(self.feature_allowed, lambda a: A.space + strP(a))
        elif self.feature == "calls":
            return "/set calls @" + displayNameP(self.contact_name) + optional(self.feature_allowed, lambda a: A.space + strP(a))
        elif self.feature == "fullDelete":
            return "/set delete @" + displayNameP(self.contact_name) + optional(self.feature_allowed, lambda a: A.space + strP(a))
        else:
            raise ValueError(f"Invalid feature: {self.feature}")

class SetGroupFeature(BaseChatCommand):
    feature: AGroupFeatureNoRole
    group_name: GroupName
    enabled: GroupFeatureEnabled
    def format(self) -> str:
        if self.feature == "history":
            return "/set history #" + displayNameP(self.group_name) + A.space + strP(self.enabled)
        elif self.feature == "reactions":
            return "/set reactions #" + displayNameP(self.group_name) + A.space + strP(self.enabled)
        elif self.feature == "reports":
            return "/set reports #" + displayNameP(self.group_name) + _strP(self.enabled)
        else:
            raise ValueError(f"Invalid feature: {self.feature}")

class SetGroupFeatureRole(BaseChatCommand):
    feature: AGroupFeatureRole
    group_name: GroupName
    enabled: GroupFeatureEnabled
    role: Optional[GroupMemberRole]
    def format(self) -> str:
        # Fighting the type checker:
        role: GroupMemberRole = self.role  # type: ignore
        if self.feature == "voice":
            return "/set voice #" + displayNameP(self.group_name) + _strP(self.enabled) + optional(self.role, lambda _: memberRole(role))
        elif self.feature == "files":
            return "/set files #" + displayNameP(self.group_name) + _strP(self.enabled) + optional(self.role, lambda _: memberRole(role))
        elif self.feature == "fullDelete":
            return "/set delete #" + displayNameP(self.group_name) + _strP(self.enabled) + optional(self.role, lambda _: memberRole(role))
        elif self.feature == "directMessages":
            return "/set direct #" + displayNameP(self.group_name) + _strP(self.enabled) + optional(self.role, lambda _: memberRole(role))
        elif self.feature == "simplexLinks":
            return "/set links #" + displayNameP(self.group_name) + _strP(self.enabled) + optional(self.role, lambda _: memberRole(role))
        else:
            raise ValueError(f"Invalid feature: {self.feature}")

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
    remote_host_id: Optional[RemoteHostId]
    multicast: Optional[bool]  # TODO None iff remote_host_id is None
    rc_ctrl_address: Optional[RCCtrlAddress]
    port: Optional[int]
    def format(self) -> str:
        assert (self.remote_host_id is None) == (self.multicast is None)
        return "/start remote host " + ("new" if (self.remote_host_id is None or self.multicast is None) else (A.decimal(self.remote_host_id) + (" multicast=" + onOffP(self.multicast)))) + optional (A.space + rcCtrlAddressP(self.rc_ctrl_address)) + optional(self.port, lambda p: " port=" + A.decimal(p))

class SwitchRemoteHost(BaseChatCommand):
    remote_host_id: Optional[RemoteHostId]
    def format(self) -> str:
        return "/switch remote host " + ("local" if self.remote_host_id is None else A.decimal(self.remote_host_id))

class StopRemoteHost(BaseChatCommand):
    rh_key: RHKey
    def format(self) -> str:
        if isinstance(self.rh_key, RHNew):
            key_part = "new"
        elif isinstance(self.rh_key, RHId):
            key_part = A.decimal(self.rh_key.remoteHostId)
        else:
            raise TypeError(f"Invalid RHKey: {self.rh_key}")
        return "/stop remote host " + key_part

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
