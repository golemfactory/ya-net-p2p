use crate::{Address, Error};
use actix::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct GetStatus {}

#[derive(Deserialize, Serialize)]
pub struct StatusInfo {
    pub connections: ConnectionInfo,
}

#[derive(Deserialize, Serialize)]
pub struct ConnectionInfo {
    pub pending: Vec<Address>,
    pub active: Vec<Address>,
}

impl Message for GetStatus {
    type Result = Result<StatusInfo, Error>;
}
