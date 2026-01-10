#  Auto-generated code from types_generator.py using ll_mtproto/resources/tl/system.tl

# noinspection All

import typing
import dataclasses
from ll_mtproto.tl.structure import BaseStructure, TypedStructure, TypedStructureObjectType
from ll_mtproto.tl.tl import Value, TlBodyData

_int128 = bytes
_string = str
_int256 = bytes
_ulong = int
_long = int
_PaddedObject = BaseStructure
_PlainObject = BaseStructure
_encrypted = bytes
_rawobject = bytes | Value
_sha1 = bytes
_uint = int
_true = bool | None
_double = float
_Bool = bool
_bytes = bytes
_int = int

__all__ = (
	"AuthorizationInnerData",
	"BadMsgNotification",
	"BadServerSalt",
	"BindAuthKeyInner",
	"ClientDHInnerData",
	"DestroyAuthKey",
	"DestroyAuthKeyFail",
	"DestroyAuthKeyNone",
	"DestroyAuthKeyOk",
	"DestroySession",
	"DestroySessionNone",
	"DestroySessionOk",
	"DhGenFail",
	"DhGenOk",
	"DhGenRetry",
	"EncryptedMessage",
	"FutureSalt",
	"FutureSalts",
	"GetFutureSalts",
	"HttpWait",
	"InitConnection",
	"InputClientProxy",
	"InvokeWithLayer",
	"InvokeWithoutUpdates",
	"JsonArray",
	"JsonBool",
	"JsonNull",
	"JsonNumber",
	"JsonObject",
	"JsonObjectValue",
	"JsonString",
	"MessageFromClient",
	"MessageFromServer",
	"MessageInnerData",
	"MessageInnerDataFromServer",
	"MsgContainer",
	"MsgDetailedInfo",
	"MsgNewDetailedInfo",
	"MsgResendReq",
	"MsgsAck",
	"MsgsAllInfo",
	"MsgsStateInfo",
	"MsgsStateReq",
	"NewSessionCreated",
	"PQInnerData",
	"PQInnerDataDc",
	"PQInnerDataTemp",
	"PQInnerDataTempDc",
	"Ping",
	"PingDelayDisconnect",
	"Pong",
	"ReqDHParams",
	"ReqPq",
	"ReqPqMulti",
	"ResPQ",
	"RpcAnswerDropped",
	"RpcAnswerDroppedRunning",
	"RpcAnswerUnknown",
	"RpcDropAnswer",
	"RpcError",
	"RpcResult",
	"ServerDHInnerData",
	"ServerDHParamsFail",
	"ServerDHParamsOk",
	"SetClientDHParams",
	"UnencryptedMessage",
)

_BadMsgNotification = typing.Union[
	"BadMsgNotification",
	"BadServerSalt",
]
_BindAuthKeyInner = typing.Union[
	"BindAuthKeyInner",
]
_ClientDHInnerData = typing.Union[
	"ClientDHInnerData",
]
_DataToDecrypt = typing.Union[
	"MessageInnerDataFromServer",
]
_DataToEncrypt = typing.Union[
	"AuthorizationInnerData",
	"MessageInnerData",
]
_DataToSend = typing.Union[
	"EncryptedMessage",
	"UnencryptedMessage",
]
_DestroyAuthKeyRes = typing.Union[
	"DestroyAuthKeyFail",
	"DestroyAuthKeyNone",
	"DestroyAuthKeyOk",
]
_DestroySessionRes = typing.Union[
	"DestroySessionNone",
	"DestroySessionOk",
]
_FutureSalt = typing.Union[
	"FutureSalt",
]
_FutureSalts = typing.Union[
	"FutureSalts",
]
_HttpWait = typing.Union[
	"HttpWait",
]
_InputClientProxy = typing.Union[
	"InputClientProxy",
]
_JSONObjectValue = typing.Union[
	"JsonObjectValue",
]
_JSONValue = typing.Union[
	"JsonArray",
	"JsonBool",
	"JsonNull",
	"JsonNumber",
	"JsonObject",
	"JsonString",
]
_MessageContainer = typing.Union[
	"MsgContainer",
]
_MessageFromClient = typing.Union[
	"MessageFromClient",
]
_MessageFromServer = typing.Union[
	"MessageFromServer",
]
_MsgDetailedInfo = typing.Union[
	"MsgDetailedInfo",
	"MsgNewDetailedInfo",
]
_MsgResendReq = typing.Union[
	"MsgResendReq",
]
_MsgsAck = typing.Union[
	"MsgsAck",
]
_MsgsAllInfo = typing.Union[
	"MsgsAllInfo",
]
_MsgsStateInfo = typing.Union[
	"MsgsStateInfo",
]
_MsgsStateReq = typing.Union[
	"MsgsStateReq",
]
_NewSession = typing.Union[
	"NewSessionCreated",
]
_PQInnerData = typing.Union[
	"PQInnerData",
	"PQInnerDataDc",
	"PQInnerDataTemp",
	"PQInnerDataTempDc",
]
_Pong = typing.Union[
	"Pong",
]
_ResPQ = typing.Union[
	"ResPQ",
]
_RpcDropAnswer = typing.Union[
	"RpcAnswerDropped",
	"RpcAnswerDroppedRunning",
	"RpcAnswerUnknown",
]
_RpcError = typing.Union[
	"RpcError",
]
_RpcResult = typing.Union[
	"RpcResult",
]
_ServerDHParams = typing.Union[
	"ServerDHParamsFail",
	"ServerDHParamsOk",
]
_ServerDHInnerData = typing.Union[
	"ServerDHInnerData",
]
_SetClientDHParamsAnswer = typing.Union[
	"DhGenFail",
	"DhGenOk",
	"DhGenRetry",
]


@typing.final
@dataclasses.dataclass(eq=False)
class AuthorizationInnerData(TypedStructure[_DataToEncrypt]):
	CONS: typing.ClassVar[str] = "authorization_inner_data"
	data_hash: _sha1
	data: _string


@typing.final
@dataclasses.dataclass(eq=False)
class BadMsgNotification(TypedStructure[_BadMsgNotification]):
	CONS: typing.ClassVar[str] = "bad_msg_notification"
	bad_msg_id: _long
	bad_msg_seqno: _int
	error_code: _int


@typing.final
@dataclasses.dataclass(eq=False)
class BadServerSalt(TypedStructure[_BadMsgNotification]):
	CONS: typing.ClassVar[str] = "bad_server_salt"
	bad_msg_id: _long
	bad_msg_seqno: _int
	error_code: _int
	new_server_salt: _long


@typing.final
@dataclasses.dataclass(eq=False)
class BindAuthKeyInner(TypedStructure[_BindAuthKeyInner]):
	CONS: typing.ClassVar[str] = "bind_auth_key_inner"
	nonce: _long
	temp_auth_key_id: _long
	perm_auth_key_id: _long
	temp_session_id: _ulong
	expires_at: _int


@typing.final
@dataclasses.dataclass(eq=False)
class ClientDHInnerData(TypedStructure[_ClientDHInnerData]):
	CONS: typing.ClassVar[str] = "client_DH_inner_data"
	nonce: _int128
	server_nonce: _int128
	retry_id: _long
	g_b: _bytes


@typing.final
@dataclasses.dataclass(eq=False)
class DestroyAuthKey(TypedStructure[_DestroyAuthKeyRes]):
	CONS: typing.ClassVar[str] = "destroy_auth_key"


@typing.final
@dataclasses.dataclass(eq=False)
class DestroyAuthKeyFail(TypedStructure[_DestroyAuthKeyRes]):
	CONS: typing.ClassVar[str] = "destroy_auth_key_fail"


@typing.final
@dataclasses.dataclass(eq=False)
class DestroyAuthKeyNone(TypedStructure[_DestroyAuthKeyRes]):
	CONS: typing.ClassVar[str] = "destroy_auth_key_none"


@typing.final
@dataclasses.dataclass(eq=False)
class DestroyAuthKeyOk(TypedStructure[_DestroyAuthKeyRes]):
	CONS: typing.ClassVar[str] = "destroy_auth_key_ok"


@typing.final
@dataclasses.dataclass(eq=False)
class DestroySession(TypedStructure[_DestroySessionRes]):
	CONS: typing.ClassVar[str] = "destroy_session"
	session_id: _ulong


@typing.final
@dataclasses.dataclass(eq=False)
class DestroySessionNone(TypedStructure[_DestroySessionRes]):
	CONS: typing.ClassVar[str] = "destroy_session_none"
	session_id: _ulong


@typing.final
@dataclasses.dataclass(eq=False)
class DestroySessionOk(TypedStructure[_DestroySessionRes]):
	CONS: typing.ClassVar[str] = "destroy_session_ok"
	session_id: _ulong


@typing.final
@dataclasses.dataclass(eq=False)
class DhGenFail(TypedStructure[_SetClientDHParamsAnswer]):
	CONS: typing.ClassVar[str] = "dh_gen_fail"
	nonce: _int128
	server_nonce: _int128
	new_nonce_hash3: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class DhGenOk(TypedStructure[_SetClientDHParamsAnswer]):
	CONS: typing.ClassVar[str] = "dh_gen_ok"
	nonce: _int128
	server_nonce: _int128
	new_nonce_hash1: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class DhGenRetry(TypedStructure[_SetClientDHParamsAnswer]):
	CONS: typing.ClassVar[str] = "dh_gen_retry"
	nonce: _int128
	server_nonce: _int128
	new_nonce_hash2: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class EncryptedMessage(TypedStructure[_DataToSend]):
	CONS: typing.ClassVar[str] = "encrypted_message"
	auth_key_id: _long
	msg_key: _int128
	encrypted_data: _rawobject


@typing.final
@dataclasses.dataclass(eq=False)
class FutureSalt(TypedStructure[_FutureSalt]):
	CONS: typing.ClassVar[str] = "future_salt"
	valid_since: _int
	valid_until: _int
	salt: _long


@typing.final
@dataclasses.dataclass(eq=False)
class FutureSalts(TypedStructure[_FutureSalts]):
	CONS: typing.ClassVar[str] = "future_salts"
	req_msg_id: _long
	now: _int
	salts: typing.List[_FutureSalt]


@typing.final
@dataclasses.dataclass(eq=False)
class GetFutureSalts(TypedStructure[_FutureSalts]):
	CONS: typing.ClassVar[str] = "get_future_salts"
	num: _int


@typing.final
@dataclasses.dataclass(eq=False)
class HttpWait(TypedStructure[_HttpWait]):
	CONS: typing.ClassVar[str] = "http_wait"
	max_delay: _int
	wait_after: _int
	max_wait: _int


@typing.final
@dataclasses.dataclass(eq=False)
class InitConnection[TypedStructureObjectType](TypedStructure[TypedStructureObjectType]):
	CONS: typing.ClassVar[str] = "initConnection"
	api_id: _int
	device_model: _string
	system_version: _string
	app_version: _string
	system_lang_code: _string
	lang_pack: _string
	lang_code: _string
	_wrapped: TypedStructure[TypedStructureObjectType] | TlBodyData | Value
	proxy: _InputClientProxy | None = dataclasses.field(default=None)
	params: _JSONValue | None = dataclasses.field(default=None)


@typing.final
@dataclasses.dataclass(eq=False)
class InputClientProxy(TypedStructure[_InputClientProxy]):
	CONS: typing.ClassVar[str] = "inputClientProxy"
	address: _string
	port: _int


@typing.final
@dataclasses.dataclass(eq=False)
class InvokeWithLayer[TypedStructureObjectType](TypedStructure[TypedStructureObjectType]):
	CONS: typing.ClassVar[str] = "invokeWithLayer"
	layer: _int
	_wrapped: TypedStructure[TypedStructureObjectType] | TlBodyData | Value


@typing.final
@dataclasses.dataclass(eq=False)
class InvokeWithoutUpdates[TypedStructureObjectType](TypedStructure[TypedStructureObjectType]):
	CONS: typing.ClassVar[str] = "invokeWithoutUpdates"
	_wrapped: TypedStructure[TypedStructureObjectType] | TlBodyData | Value


@typing.final
@dataclasses.dataclass(eq=False)
class JsonArray(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonArray"
	value: typing.List[_JSONValue]


@typing.final
@dataclasses.dataclass(eq=False)
class JsonBool(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonBool"
	value: _Bool


@typing.final
@dataclasses.dataclass(eq=False)
class JsonNull(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonNull"


@typing.final
@dataclasses.dataclass(eq=False)
class JsonNumber(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonNumber"
	value: _double


@typing.final
@dataclasses.dataclass(eq=False)
class JsonObject(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonObject"
	value: typing.List[_JSONObjectValue]


@typing.final
@dataclasses.dataclass(eq=False)
class JsonObjectValue(TypedStructure[_JSONObjectValue]):
	CONS: typing.ClassVar[str] = "jsonObjectValue"
	key: _string
	value: _JSONValue


@typing.final
@dataclasses.dataclass(eq=False)
class JsonString(TypedStructure[_JSONValue]):
	CONS: typing.ClassVar[str] = "jsonString"
	value: _string


@typing.final
@dataclasses.dataclass(eq=False)
class MessageFromClient(TypedStructure[_MessageFromClient]):
	CONS: typing.ClassVar[str] = "message_from_client"
	msg_id: _ulong
	seqno: _uint
	body: _PlainObject


@typing.final
@dataclasses.dataclass(eq=False)
class MessageFromServer(TypedStructure[_MessageFromServer]):
	CONS: typing.ClassVar[str] = "message_from_server"
	msg_id: _ulong
	seqno: _uint


@typing.final
@dataclasses.dataclass(eq=False)
class MessageInnerData(TypedStructure[_DataToEncrypt]):
	CONS: typing.ClassVar[str] = "message_inner_data"
	salt: _long
	session_id: _ulong
	message: _MessageFromClient


@typing.final
@dataclasses.dataclass(eq=False)
class MessageInnerDataFromServer(TypedStructure[_DataToDecrypt]):
	CONS: typing.ClassVar[str] = "message_inner_data_from_server"
	salt: _long
	session_id: _ulong
	message: _MessageFromServer


@typing.final
@dataclasses.dataclass(eq=False)
class MsgContainer(TypedStructure[_MessageContainer]):
	CONS: typing.ClassVar[str] = "msg_container"
	messages: typing.List[_MessageFromClient]


@typing.final
@dataclasses.dataclass(eq=False)
class MsgDetailedInfo(TypedStructure[_MsgDetailedInfo]):
	CONS: typing.ClassVar[str] = "msg_detailed_info"
	msg_id: _long
	answer_msg_id: _long
	bytes: _int
	status: _int


@typing.final
@dataclasses.dataclass(eq=False)
class MsgNewDetailedInfo(TypedStructure[_MsgDetailedInfo]):
	CONS: typing.ClassVar[str] = "msg_new_detailed_info"
	answer_msg_id: _long
	bytes: _int
	status: _int


@typing.final
@dataclasses.dataclass(eq=False)
class MsgResendReq(TypedStructure[_MsgResendReq]):
	CONS: typing.ClassVar[str] = "msg_resend_req"
	msg_ids: typing.List[_long]


@typing.final
@dataclasses.dataclass(eq=False)
class MsgsAck(TypedStructure[_MsgsAck]):
	CONS: typing.ClassVar[str] = "msgs_ack"
	msg_ids: typing.List[_long]


@typing.final
@dataclasses.dataclass(eq=False)
class MsgsAllInfo(TypedStructure[_MsgsAllInfo]):
	CONS: typing.ClassVar[str] = "msgs_all_info"
	msg_ids: typing.List[_long]
	info: _string


@typing.final
@dataclasses.dataclass(eq=False)
class MsgsStateInfo(TypedStructure[_MsgsStateInfo]):
	CONS: typing.ClassVar[str] = "msgs_state_info"
	req_msg_id: _long
	info: _string


@typing.final
@dataclasses.dataclass(eq=False)
class MsgsStateReq(TypedStructure[_MsgsStateReq]):
	CONS: typing.ClassVar[str] = "msgs_state_req"
	msg_ids: typing.List[_long]


@typing.final
@dataclasses.dataclass(eq=False)
class NewSessionCreated(TypedStructure[_NewSession]):
	CONS: typing.ClassVar[str] = "new_session_created"
	first_msg_id: _long
	unique_id: _long
	server_salt: _long


@typing.final
@dataclasses.dataclass(eq=False)
class PQInnerData(TypedStructure[_PQInnerData]):
	CONS: typing.ClassVar[str] = "p_q_inner_data"
	pq: _string
	p: _string
	q: _string
	nonce: _int128
	server_nonce: _int128
	new_nonce: _int256


@typing.final
@dataclasses.dataclass(eq=False)
class PQInnerDataDc(TypedStructure[_PQInnerData]):
	CONS: typing.ClassVar[str] = "p_q_inner_data_dc"
	pq: _string
	p: _string
	q: _string
	nonce: _int128
	server_nonce: _int128
	new_nonce: _int256
	dc: _int


@typing.final
@dataclasses.dataclass(eq=False)
class PQInnerDataTemp(TypedStructure[_PQInnerData]):
	CONS: typing.ClassVar[str] = "p_q_inner_data_temp"
	pq: _string
	p: _string
	q: _string
	nonce: _int128
	server_nonce: _int128
	new_nonce: _int256
	expires_in: _int


@typing.final
@dataclasses.dataclass(eq=False)
class PQInnerDataTempDc(TypedStructure[_PQInnerData]):
	CONS: typing.ClassVar[str] = "p_q_inner_data_temp_dc"
	pq: _string
	p: _string
	q: _string
	nonce: _int128
	server_nonce: _int128
	new_nonce: _int256
	dc: _int
	expires_in: _int


@typing.final
@dataclasses.dataclass(eq=False)
class Ping(TypedStructure[_Pong]):
	CONS: typing.ClassVar[str] = "ping"
	ping_id: _long


@typing.final
@dataclasses.dataclass(eq=False)
class PingDelayDisconnect(TypedStructure[_Pong]):
	CONS: typing.ClassVar[str] = "ping_delay_disconnect"
	ping_id: _long
	disconnect_delay: _int


@typing.final
@dataclasses.dataclass(eq=False)
class Pong(TypedStructure[_Pong]):
	CONS: typing.ClassVar[str] = "pong"
	msg_id: _long
	ping_id: _long


@typing.final
@dataclasses.dataclass(eq=False)
class ReqDHParams(TypedStructure[_ServerDHParams]):
	CONS: typing.ClassVar[str] = "req_DH_params"
	nonce: _int128
	server_nonce: _int128
	p: _string
	q: _string
	public_key_fingerprint: _long
	encrypted_data: _string


@typing.final
@dataclasses.dataclass(eq=False)
class ReqPq(TypedStructure[_ResPQ]):
	CONS: typing.ClassVar[str] = "req_pq"
	nonce: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class ReqPqMulti(TypedStructure[_ResPQ]):
	CONS: typing.ClassVar[str] = "req_pq_multi"
	nonce: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class ResPQ(TypedStructure[_ResPQ]):
	CONS: typing.ClassVar[str] = "resPQ"
	nonce: _int128
	server_nonce: _int128
	pq: _bytes
	server_public_key_fingerprints: typing.List[_long]


@typing.final
@dataclasses.dataclass(eq=False)
class RpcAnswerDropped(TypedStructure[_RpcDropAnswer]):
	CONS: typing.ClassVar[str] = "rpc_answer_dropped"
	msg_id: _long
	seq_no: _int
	bytes: _int


@typing.final
@dataclasses.dataclass(eq=False)
class RpcAnswerDroppedRunning(TypedStructure[_RpcDropAnswer]):
	CONS: typing.ClassVar[str] = "rpc_answer_dropped_running"


@typing.final
@dataclasses.dataclass(eq=False)
class RpcAnswerUnknown(TypedStructure[_RpcDropAnswer]):
	CONS: typing.ClassVar[str] = "rpc_answer_unknown"


@typing.final
@dataclasses.dataclass(eq=False)
class RpcDropAnswer(TypedStructure[_RpcDropAnswer]):
	CONS: typing.ClassVar[str] = "rpc_drop_answer"
	req_msg_id: _long


@typing.final
@dataclasses.dataclass(eq=False)
class RpcError(TypedStructure[_RpcError]):
	CONS: typing.ClassVar[str] = "rpc_error"
	error_code: _int
	error_message: _string


@typing.final
@dataclasses.dataclass(eq=False)
class RpcResult(TypedStructure[_RpcResult]):
	CONS: typing.ClassVar[str] = "rpc_result"
	req_msg_id: _long
	result: _rawobject


@typing.final
@dataclasses.dataclass(eq=False)
class ServerDHInnerData(TypedStructure[_ServerDHInnerData]):
	CONS: typing.ClassVar[str] = "server_DH_inner_data"
	nonce: _int128
	server_nonce: _int128
	g: _int
	dh_prime: _bytes
	g_a: _bytes
	server_time: _int


@typing.final
@dataclasses.dataclass(eq=False)
class ServerDHParamsFail(TypedStructure[_ServerDHParams]):
	CONS: typing.ClassVar[str] = "server_DH_params_fail"
	nonce: _int128
	server_nonce: _int128
	new_nonce_hash: _int128


@typing.final
@dataclasses.dataclass(eq=False)
class ServerDHParamsOk(TypedStructure[_ServerDHParams]):
	CONS: typing.ClassVar[str] = "server_DH_params_ok"
	nonce: _int128
	server_nonce: _int128
	encrypted_answer: _bytes


@typing.final
@dataclasses.dataclass(eq=False)
class SetClientDHParams(TypedStructure[_SetClientDHParamsAnswer]):
	CONS: typing.ClassVar[str] = "set_client_DH_params"
	nonce: _int128
	server_nonce: _int128
	encrypted_data: _string


@typing.final
@dataclasses.dataclass(eq=False)
class UnencryptedMessage(TypedStructure[_DataToSend]):
	CONS: typing.ClassVar[str] = "unencrypted_message"
	auth_key_id: _long
	msg_id: _ulong
	body: _PaddedObject
