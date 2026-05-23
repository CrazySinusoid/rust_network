pub mod codec;
pub mod frame;
pub mod handshake;
pub mod packet_type;
pub mod replay;
pub mod secure;
pub mod session;

pub use codec::{decode_frame, encode_frame, encode_header};
pub use frame::{Frame, FrameHeader, HEADER_LEN, MAGIC, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, VERSION};
pub use handshake::{
    decode_auth_confirm, decode_client_hello, decode_server_hello, encode_auth_confirm,
    encode_client_hello, encode_server_hello, AuthConfirm, ClientHello, ServerHello,
    AUTH_METHOD_PSK,
};
pub use packet_type::{DisconnectReason, ErrorCode, PacketType};
pub use replay::{ReplayDecision, ReplayWindow, REPLAY_WINDOW_SIZE};
pub use secure::{
    decode_error_frame, decrypt_auth_confirm_frame, decrypt_data_frame, decrypt_disconnect_frame,
    decrypt_keepalive_frame, encrypt_auth_confirm_frame, encrypt_data_frame,
    encrypt_disconnect_frame, encrypt_keepalive_frame,
};
