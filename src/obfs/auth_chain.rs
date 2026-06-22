use crate::error::Result;
use super::obfs::{Protocol, ServerInfo};

macro_rules! make_auth_chain {
    ($name:ident, $label:expr) => {
        pub struct $name {
            server_info: ServerInfo,
        }

        impl $name {
            pub fn new() -> Self {
                $name { server_info: ServerInfo::default() }
            }
        }

        impl Protocol for $name {
            fn name(&self) -> &str { $label }
            fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
            fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
            fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
            fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
            fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
            fn get_server_info(&self) -> &ServerInfo { &self.server_info }
            fn dispose(&mut self) {}
        }
    };
}

make_auth_chain!(AuthChainA, "auth_chain_a");
make_auth_chain!(AuthChainB, "auth_chain_b");
make_auth_chain!(AuthChainC, "auth_chain_c");
make_auth_chain!(AuthChainD, "auth_chain_d");
make_auth_chain!(AuthChainE, "auth_chain_e");
make_auth_chain!(AuthChainF, "auth_chain_f");
