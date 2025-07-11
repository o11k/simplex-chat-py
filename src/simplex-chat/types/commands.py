import json
from typing import Annotated, Literal, Optional, Union
from abc import ABC, abstractmethod
import sys

from pydantic import BaseModel, StringConstraints

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
ImageData = str
RemoteHostId = int
RemoteCtrlId = int
CbNonce = str
# Doesn't exist in Haskell
VerifyCode = Annotated[str, StringConstraints(pattern=r"^[^\d ]$")]

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

class SetAllContactReceipts(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/set receipts all {to_on_off(self.on_or_off)}"

class SetActiveUser(BaseChatCommand):
    user_name: UserName
    user_pwd: Optional[UserPwd]

    def __str__(self) -> str:
        cmd = f"/user {quote_display_name(self.user_name)}"
        if self.user_pwd is not None:
            cmd += " " + json.dumps(self.user_pwd)
        return cmd

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

class APISetEncryptLocalFiles(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/_files_encrypt {to_on_off(self.on_or_off)}"

class SetContactMergeEnabled(BaseChatCommand):
    on_or_off: bool

    def __str__(self) -> str:
        return f"/contact_merge {to_on_off(self.on_or_off)}"

class ExportArchive(BaseChatCommand):
    def __str__(self) -> str: return "/db export"

class APIDeleteStorage(BaseChatCommand):
    def __str__(self) -> str: return "/_db delete"

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

class APIRejectCall(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_call reject @{self.contact_id}"

class APIEndCall(BaseChatCommand):
    contact_id: ContactId

    def __str__(self) -> str:
        return f"/_call end @{self.contact_id}"

class APIGetCallInvitations(BaseChatCommand):
    def __str__(self) -> str: return "/_call get"

class APIGetNetworkStatuses(BaseChatCommand):
    def __str__(self) -> str: return "/_network_statuses"

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

# APIAddContact UserId CreateShortLink IncognitoEnabled
# AddContact CreateShortLink IncognitoEnabled
# APISetConnectionIncognito Int64 IncognitoEnabled
# APIChangeConnectionUser Int64 UserId
# APIConnectContactViaAddress UserId IncognitoEnabled ContactId
# ConnectSimplex IncognitoEnabled
# ClearContact ContactName
# APIListContacts UserId

class ListContacts(BaseChatCommand):
    def __str__(self) -> str: return "/contacts"

# APICreateMyAddress UserId CreateShortLink
# CreateMyAddress CreateShortLink
# APIDeleteMyAddress UserId

class DeleteMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/delete_address"

# APIShowMyAddress UserId

class ShowMyAddress(BaseChatCommand):
    def __str__(self) -> str: return "/show_address"

# APISetProfileAddress UserId Bool
# SetProfileAddress Bool
# AcceptContact IncognitoEnabled ContactName
# SendMemberContactMessage GroupName ContactName Text
# DeleteMemberMessage GroupName ContactName Text
# AddMember GroupName ContactName GroupMemberRole
# MemberRole GroupName ContactName GroupMemberRole
# BlockForAll GroupName ContactName Bool

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

# APIListGroups UserId (Maybe ContactId) (Maybe String)
# ListGroups (Maybe ContactName) (Maybe String)
# ShowGroupProfile GroupName
# UpdateGroupDescription GroupName (Maybe Text)
# ShowGroupDescription GroupName
# CreateGroupLink GroupName GroupMemberRole CreateShortLink
# GroupLinkMemberRole GroupName GroupMemberRole
# DeleteGroupLink GroupName
# ShowGroupLink GroupName
# SendGroupMessageQuote {groupName :: GroupName, contactName_ :: Maybe ContactName, quotedMsg :: Text, message :: Text}

class ClearNoteFolder(BaseChatCommand):
    def __str__(self) -> str: return "/clear *"

# LastChats (Maybe Int)
# ShowChatItem (Maybe ChatItemId)
# ShowLiveItems Bool
# ReceiveFile {fileId :: FileTransferId, userApprovedRelays :: Bool, storeEncrypted :: Maybe Bool, fileInline :: Maybe Bool, filePath :: Maybe FilePath}
# SetFileToReceive {fileId :: FileTransferId, userApprovedRelays :: Bool, storeEncrypted :: Maybe Bool}
# CancelFile FileTransferId
# FileStatus FileTransferId

class ShowProfile(BaseChatCommand):
    def __str__(self) -> str: return "/profile"

# UpdateProfile ContactName Text
# UpdateProfileImage (Maybe ImageData)

class ShowProfileImage(BaseChatCommand):
    def __str__(self) -> str: return "/show profile image"

# SetUserTimedMessages Bool
# SetGroupTimedMessages GroupName (Maybe Int)
# SetLocalDeviceName Text

class ListRemoteHosts(BaseChatCommand):
    def __str__(self) -> str: return "/list remote hosts"

# SwitchRemoteHost (Maybe RemoteHostId)
# DeleteRemoteHost RemoteHostId
# StoreRemoteFile {remoteHostId :: RemoteHostId, storeEncrypted :: Maybe Bool, localPath :: FilePath}

class FindKnownRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/find remote ctrl"

# ConfirmRemoteCtrl RemoteCtrlId
# VerifyRemoteCtrlSession Text

class ListRemoteCtrls(BaseChatCommand):
    def __str__(self) -> str: return "/list remote ctrls"

class StopRemoteCtrl(BaseChatCommand):
    def __str__(self) -> str: return "/stop remote ctrl"

# DeleteRemoteCtrl RemoteCtrlId

class QuitChat(BaseChatCommand):
    def __str__(self) -> str: return "/quit"

class ShowVersion(BaseChatCommand):
    def __str__(self) -> str: return "/version"

class DebugLocks(BaseChatCommand):
    def __str__(self) -> str: return "/debug locks"

# GetAgentSubsTotal UserId
# GetAgentServersSummary UserId

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

# CustomChatCommand ByteString
