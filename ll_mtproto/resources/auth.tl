// Core types (no need to gen)

//vector#1cb5c415 {t:Type} # [ t ] = Vector t;

///////////////////////////////
/////////////////// Layer cons
///////////////////////////////

//invokeAfterMsg#cb9f372d msg_id:long query:!X = X;
//invokeAfterMsgs#3dc4b4f0 msg_ids:Vector<long> query:!X = X;
//invokeWithLayer1#53835315 query:!X = X;
//invokeWithLayer2#289dd1f6 query:!X = X;
//invokeWithLayer3#b7475268 query:!X = X;
//invokeWithLayer4#dea0d430 query:!X = X;
//invokeWithLayer5#417a57ae query:!X = X;
//invokeWithLayer6#3a64d54d query:!X = X;
//invokeWithLayer7#a5be56d3 query:!X = X;
//invokeWithLayer8#e9abd9fd query:!X = X;
//invokeWithLayer9#76715a63 query:!X = X;
//invokeWithLayer10#39620c41 query:!X = X;
//invokeWithLayer11#a6b88fdf query:!X = X;
//invokeWithLayer12#dda60d3c query:!X = X;
//invokeWithLayer13#427c8ea2 query:!X = X;
//invokeWithLayer14#2b9b08fa query:!X = X;
//invokeWithLayer15#b4418b64 query:!X = X;
//invokeWithLayer16#cf5f0987 query:!X = X;
//invokeWithLayer17#50858a19 query:!X = X;
//invokeWithLayer18#1c900537 query:!X = X;
//invokeWithLayer#da9b0d0d layer:int query:!X = X; // after 18 layer

///////////////////////////////
/// Authorization key creation
///////////////////////////////

resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;

p_q_inner_data#83c95aec pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;
p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;
bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:ulong perm_auth_key_id:ulong temp_session_id:ulong expires_at:int = BindAuthKeyInner;

p_q_inner_data_dc#a9f55f95 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int = P_Q_inner_data;
p_q_inner_data_temp_dc#56fddf88 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int expires_in:int = P_Q_inner_data;

server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params;

server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data;

client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data;

dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;

destroy_auth_key_ok#f660e1d4 = DestroyAuthKeyRes;
destroy_auth_key_none#0a9f2259 = DestroyAuthKeyRes;
destroy_auth_key_fail#ea109b13 = DestroyAuthKeyRes;

---functions---

req_pq#60469778 nonce:int128 = ResPQ;
req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;

req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;

set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;

destroy_auth_key#d1435160 = DestroyAuthKeyRes;

///////////////////////////////
////////////// System messages
///////////////////////////////

---types---

msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;

bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;

msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq;
msgs_state_info#04deb57d req_msg_id:long info:string = MsgsStateInfo;
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:string = MsgsAllInfo;

msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;

msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq;

//rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult; // parsed manually

rpc_error#2144ca19 error_code:int error_message:string = RpcError;

rpc_answer_unknown#5e2ad36e = RpcDropAnswer;
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer;
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer;

future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts;

pong#347773c5 msg_id:long ping_id:long = Pong;

destroy_session_ok#e22045fc session_id:ulong = DestroySessionRes;
destroy_session_none#62d350c9 session_id:ulong = DestroySessionRes;

new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;

//message msg_id:long seqno:int bytes:int body:Object = Message; // parsed manually
//msg_container#73f1f8dc messages:vector<message> = MessageContainer; // parsed manually
//msg_copy#e06046b2 orig_message:Message = MessageCopy; // parsed manually, not used - use msg_container
//gzip_packed#3072cfa1 packed_data:string = Object; // parsed manually

http_wait#9299359f max_delay:int wait_after:int max_wait:int = HttpWait;

---functions---

rpc_drop_answer#58e4a740 req_msg_id:long = RpcDropAnswer;

get_future_salts#b921bd04 num:int = FutureSalts;

ping#7abe77ec ping_id:long = Pong;
ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;

destroy_session#e7512126 session_id:ulong = DestroySessionRes;

contest.saveDeveloperInfo#9a5f6e95 vk_id:int name:string phone_number:string age:int city:string = Bool;
