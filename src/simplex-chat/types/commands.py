from typing import Union
from abc import ABC, abstractmethod


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


class BaseChatCommand(ABC):
    @abstractmethod
    def __str__(self) -> str: ...


class ShowActiveUser(BaseChatCommand):
    def __str__(self) -> str: return "/user"

class ListUsers(BaseChatCommand):
    def __str__(self) -> str: return "/users"

class MuteUser(BaseChatCommand):
    def __str__(self) -> str: return "/mute user"

class UnmuteUser(BaseChatCommand):
    def __str__(self) -> str: return "/unmute user"

class CheckChatRunning(BaseChatCommand):
    def __str__(self) -> str: return "/_check running"

class APIStopChat(BaseChatCommand):
    def __str__(self) -> str: return "/_stop"

class ResubscribeAllConnections(BaseChatCommand):
    def __str__(self) -> str: return "/_resubscribe all"

class ExportArchive(BaseChatCommand):
    def __str__(self) -> str: return "/db export"

class APIDeleteStorage(BaseChatCommand):
    def __str__(self) -> str: return "/_db delete"

class SlowSQLQueries(BaseChatCommand):
    def __str__(self) -> str: return "/sql slow"

class UserRead(BaseChatCommand):
    def __str__(self) -> str: return "/read user"

class APIGetCallInvitations(BaseChatCommand):
    def __str__(self) -> str: return "/_call get"

class APIGetNetworkStatuses(BaseChatCommand):
    def __str__(self) -> str: return "/_network_statuses"

class APIGetNtfToken(BaseChatCommand):
    def __str__(self) -> str: return "/_ntf get"

class APIGetServerOperators(BaseChatCommand):
    def __str__(self) -> str: return "/_operators"

class APIGetUsageConditions(BaseChatCommand):
    def __str__(self) -> str: return "/_conditions"

class GetChatItemTTL(BaseChatCommand):
    def __str__(self) -> str: return "/ttl"

class APIGetNetworkConfig(BaseChatCommand):
    def __str__(self) -> str: return "/network"

class ReconnectAllServers(BaseChatCommand):
    def __str__(self) -> str: return "/reconnect"

class Welcome(BaseChatCommand):
    def __str__(self) -> str: return "/welcome"

class ListContacts(BaseChatCommand):
    def __str__(self) -> str: return "/contacts"

class DeleteMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/delete_address"

class ShowMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/show_address"

class ClearNoteFolder(BaseChatCommand):
    def __str__(self) -> str: return "/clear *"

class ShowProfile(BaseChatCommand):
    def __str__(self) -> str: return "/profile"

class ShowProfileImage(BaseChatCommand):
    def __str__(self) -> str: return "/show profile image"

class ListRemoteHosts(BaseChatCommand):
    def __str__(self) -> str: return "/list remote hosts"

class FindKnownRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/find remote ctrl"

class ListRemoteCtrls(BaseChatCommand):
    def __str__(self) -> str: return "/list remote ctrls"

class StopRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/stop remote ctrl"

class QuitChat(BaseChatCommand):
    def __str__(self) -> str: return "/quit"

class ShowVersion(BaseChatCommand):
    def __str__(self) -> str: return "/version"

class DebugLocks(BaseChatCommand):
    def __str__(self) -> str: return "/debug locks"

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

# TODO "/delete profile image"
