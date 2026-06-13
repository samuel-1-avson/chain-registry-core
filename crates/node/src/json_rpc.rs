use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::SharedState;

const JSONRPC_VERSION: &str = "2.0";

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[serde(default)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    id: Option<Value>,
}

pub async fn handle(State(state): State<SharedState>, body: Bytes) -> Response {
    let request = match serde_json::from_slice::<RpcRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return rpc_error_response(
                StatusCode::OK,
                None,
                -32700,
                "Parse error",
                Some(json!(error.to_string())),
            );
        }
    };

    if request.jsonrpc.as_deref().unwrap_or(JSONRPC_VERSION) != JSONRPC_VERSION {
        return rpc_error_response(
            StatusCode::OK,
            request.id,
            -32600,
            "Invalid Request",
            Some(json!("jsonrpc must be \"2.0\"")),
        );
    }

    execute(state, request).await.into_response()
}

async fn execute(state: SharedState, request: RpcRequest) -> Json<Value> {
    let id = request.id;
    let result = match request.method.as_str() {
        "creg_chainId" => creg_chain_id(&state).await.map(Value::String),
        "creg_blockNumber" => creg_block_number(&state).await.map(Value::String),
        "creg_getBlockByNumber" => creg_get_block_by_number(&state, request.params).await,
        "creg_health" => creg_health(&state).await,
        _ => return rpc_error_json(id, -32601, "Method not found", Some(json!(request.method))),
    };

    match result {
        Ok(result) => rpc_success_json(id, result),
        Err(error) => rpc_error_json(id, error.code, error.message, error.data),
    }
}

async fn creg_chain_id(state: &SharedState) -> Result<String, RpcError> {
    let state = state.read().await;
    Ok(node_chain_id(&state.config))
}

async fn creg_block_number(state: &SharedState) -> Result<String, RpcError> {
    let state = state.read().await;
    let height = state.chain.tip_height().map_err(internal_error)?;
    Ok(hex_quantity(height))
}

async fn creg_health(state: &SharedState) -> Result<Value, RpcError> {
    let state = state.read().await;
    let height = state.chain.tip_height().map_err(internal_error)?;
    Ok(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "chain_id": node_chain_id(&state.config),
        "block_number": hex_quantity(height),
        "validator_set_sync": state.validator_set_sync,
    }))
}

async fn creg_get_block_by_number(
    state: &SharedState,
    params: Option<Value>,
) -> Result<Value, RpcError> {
    let height = parse_block_number(params)?;
    let state = state.read().await;
    let resolved_height = match height {
        BlockNumberParam::Latest => state.chain.tip_height().map_err(internal_error)?,
        BlockNumberParam::Number(height) => height,
    };

    match state
        .chain
        .get_block_by_height(resolved_height)
        .map_err(internal_error)?
    {
        Some(block) => Ok(block_to_json(&block)),
        None => Ok(Value::Null),
    }
}

#[derive(Debug, Clone, Copy)]
enum BlockNumberParam {
    Latest,
    Number(u64),
}

fn parse_block_number(params: Option<Value>) -> Result<BlockNumberParam, RpcError> {
    let Some(Value::Array(params)) = params else {
        return Err(invalid_params(
            "creg_getBlockByNumber expects params array: [height | \"latest\"]",
        ));
    };
    let Some(first) = params.first() else {
        return Err(invalid_params(
            "creg_getBlockByNumber requires a block number parameter",
        ));
    };

    match first {
        Value::String(value) if value.eq_ignore_ascii_case("latest") => {
            Ok(BlockNumberParam::Latest)
        }
        Value::String(value) if value.starts_with("0x") => u64::from_str_radix(&value[2..], 16)
            .map(BlockNumberParam::Number)
            .map_err(|_| invalid_params("block number hex quantity is invalid")),
        Value::Number(value) => value
            .as_u64()
            .map(BlockNumberParam::Number)
            .ok_or_else(|| invalid_params("block number must be a non-negative integer")),
        _ => Err(invalid_params(
            "block number must be a non-negative integer, hex quantity, or \"latest\"",
        )),
    }
}

fn block_to_json(block: &common::Block) -> Value {
    let mut value = serde_json::to_value(block).unwrap_or(Value::Null);
    if let Value::Object(ref mut map) = value {
        map.insert("hash".into(), Value::String(block.hash()));
        map.insert("finalized".into(), Value::Bool(true));
    }
    value
}

fn node_chain_id(config: &crate::config::NodeConfig) -> String {
    if !config.chain_id.trim().is_empty() {
        config.chain_id.clone()
    } else if config.is_testnet {
        "creg-testnet-1".to_string()
    } else {
        "creg-mainnet-1".to_string()
    }
}

fn hex_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

#[derive(Debug)]
struct RpcError {
    code: i64,
    message: &'static str,
    data: Option<Value>,
}

fn invalid_params(message: impl Into<String>) -> RpcError {
    RpcError {
        code: -32602,
        message: "Invalid params",
        data: Some(json!(message.into())),
    }
}

fn internal_error(error: impl std::fmt::Display) -> RpcError {
    RpcError {
        code: -32603,
        message: "Internal error",
        data: Some(json!(error.to_string())),
    }
}

fn rpc_success_json(id: Option<Value>, result: Value) -> Json<Value> {
    Json(json!({
        "jsonrpc": JSONRPC_VERSION,
        "result": result,
        "id": id.unwrap_or(Value::Null),
    }))
}

fn rpc_error_json(
    id: Option<Value>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
) -> Json<Value> {
    Json(rpc_error_value(id, code, message, data))
}

fn rpc_error_response(
    status: StatusCode,
    id: Option<Value>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
) -> Response {
    (status, Json(rpc_error_value(id, code, message, data))).into_response()
}

fn rpc_error_value(
    id: Option<Value>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
) -> Value {
    let mut error = serde_json::Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message));
    if let Some(data) = data {
        error.insert("data".into(), data);
    }

    json!({
        "jsonrpc": JSONRPC_VERSION,
        "error": Value::Object(error),
        "id": id.unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_store::ChainStore,
        config::NodeConfig,
        pending_pool::PendingPool,
        publisher_index::PublisherIndex,
        state::{
            BridgeStatus, NodeState, P2PStatus, ValidatorRegistrationStatus, ValidatorSetSyncStatus,
        },
    };
    use std::{collections::HashMap, sync::Arc};
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    async fn test_state() -> anyhow::Result<(SharedState, TempDir)> {
        let tempdir = tempfile::tempdir()?;
        let chain = ChainStore::open(tempdir.path())?;
        let state = Arc::new(RwLock::new(NodeState {
            chain,
            pending_pool: PendingPool::new(),
            publisher_index: PublisherIndex::new(),
            validator_set_bootstrap: common::ValidatorSet::default(),
            validator_set: common::ValidatorSet::default(),
            package_rounds: HashMap::new(),
            config: NodeConfig {
                chain_id: "creg-testnet-1".into(),
                data_dir: tempdir.path().to_path_buf(),
                is_testnet: true,
                ..Default::default()
            },
            p2p_status: P2PStatus::default(),
            bridge_status: BridgeStatus::default(),
            vrf_proofs: HashMap::new(),
            decryption_shares: HashMap::new(),
            validator_registrations: HashMap::<String, ValidatorRegistrationStatus>::new(),
            validator_set_sync: ValidatorSetSyncStatus::default(),
            view_change_certs: HashMap::new(),
            reorgs: Vec::new(),
            pbft_engine: crate::state::PbftEngine::new(),
        }));

        Ok((state, tempdir))
    }

    async fn call(state: SharedState, body: Value) -> Value {
        let response = execute(state, serde_json::from_value(body).unwrap()).await;
        response.0
    }

    #[tokio::test]
    async fn creg_block_number_returns_tip_as_hex_quantity() -> anyhow::Result<()> {
        let (state, _tempdir) = test_state().await?;
        let response = call(
            state,
            json!({
                "jsonrpc": "2.0",
                "method": "creg_blockNumber",
                "params": [],
                "id": 1,
            }),
        )
        .await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["result"], "0x0");
        assert_eq!(response["id"], 1);
        Ok(())
    }

    #[tokio::test]
    async fn creg_get_block_by_number_returns_genesis_block() -> anyhow::Result<()> {
        let (state, _tempdir) = test_state().await?;
        let response = call(
            state,
            json!({
                "jsonrpc": "2.0",
                "method": "creg_getBlockByNumber",
                "params": ["0x0"],
                "id": "block-0",
            }),
        )
        .await;

        assert_eq!(response["result"]["header"]["height"], 0);
        assert_eq!(response["result"]["finalized"], true);
        assert!(response["result"]["hash"].as_str().is_some());
        assert_eq!(response["id"], "block-0");
        Ok(())
    }

    #[tokio::test]
    async fn unknown_method_returns_json_rpc_error() -> anyhow::Result<()> {
        let (state, _tempdir) = test_state().await?;
        let response = call(
            state,
            json!({
                "jsonrpc": "2.0",
                "method": "creg_missingMethod",
                "id": 99,
            }),
        )
        .await;

        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(response["id"], 99);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_block_params_return_invalid_params() -> anyhow::Result<()> {
        let (state, _tempdir) = test_state().await?;
        let response = call(
            state,
            json!({
                "jsonrpc": "2.0",
                "method": "creg_getBlockByNumber",
                "params": ["nope"],
                "id": 7,
            }),
        )
        .await;

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["id"], 7);
        Ok(())
    }
}
