msg_container#73f1f8dc messages:vector<message_from_client> = MessageContainer;

message_from_client msg_id:ulong seqno:uint body:object = Message;
message_from_server msg_id:ulong seqno:uint = Message;

unencrypted_message auth_key_id:ulong msg_id:ulong body:padded_object = DataToSend;
encrypted_message auth_key_id:ulong msg_key:int128 encrypted_data:encrypted = DataToSend;

message_inner_data salt:long session_id:ulong message:message_from_client = DataToEncrypt;
message_inner_data_from_server salt:long session_id:ulong message:message_from_server = DataToDecrypt;

authorization_inner_data data_hash:sha1 data:string = DataToEncrypt;

rpc_result#f35c6d01 req_msg_id:long result:rawobject = RpcResult;
gzip_packed#3072cfa1 data:gzip = Object;
