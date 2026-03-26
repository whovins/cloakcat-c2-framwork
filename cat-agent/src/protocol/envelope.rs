//! Envelope message wrapper for typed protocol framing.

use cloakcat_protocol::{Command, RegisterReq, RegisterResp, ResultReq};
use serde::{Deserialize, Serialize};

/// Top-level protocol envelope — wraps every message exchanged between
/// agent and server so both sides can match on a single tagged enum
/// instead of relying on URL path + content-type conventions.
#[derive(Debug, Serialize, Deserialize)]
pub enum Envelope {
    V1Register(RegisterReq),
    V1RegisterResp(RegisterResp),
    V1Poll { agent_id: String, hold: u64 },
    V1PollResp(Option<Command>),
    V1Result(ResultReq),
    V1Ack,
}
