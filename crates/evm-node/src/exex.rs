// Copyright 2025 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pool-state ExEx.
//!
//! On every committed (or reorged-to) chain, this execution extension:
//!
//! 1. Filters block logs by the configured topic0s (V3/PancakeV3 `Swap`,
//!    `Mint`, `Burn`, V4 `Swap`, `ModifyLiquidity`).
//! 2. Selects one tick per pool: the last `Swap` tick outranks liquidity
//!    events; otherwise the last `Mint`/`Burn`/`ModifyLiquidity` `tickLower`.
//!    V3 pool addresses are left-padded into the `bytes32` pool id space.
//! 3. Batches all selected pools into a single `getMultiTicksRange` `eth_call`
//!    pinned to the new chain tip (via the node's loopback RPC).
//! 4. Publishes the decoded response as a [`PoolStateSnapshot`] on a
//!    [`watch`] channel served by the `poolState` RPC namespace.

use crate::rpc::pool_state::{
    default_topics, PoolStateEntry, PoolStateSnapshot, PoolStateWatch, TickRangeEntry,
    IPoolState, TOPIC_UNISWAP_V3_SWAP, TOPIC_V3_BURN, TOPIC_V3_MINT, TOPIC_V4_MODIFY_LIQUIDITY,
    TOPIC_V4_SWAP,
};
use alloy_consensus::{BlockHeader as _, TxReceipt as _};
use alloy_primitives::{hex, Address, B256, Log, Signed};
use alloy_sol_types::{SolCall, SolEvent};
use futures::TryStreamExt;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_primitives_traits::NodePrimitives;
use reth_provider::Chain;
use std::collections::BTreeMap;

/// V3-family event bindings (UniswapV3 / PancakeV3 share signatures).
mod v3_events {
    alloy_sol_types::sol! {
        #[derive(Debug)]
        event Swap(
            address indexed sender,
            address indexed recipient,
            int256 amount0,
            int256 amount1,
            uint160 sqrtPriceX96,
            uint128 liquidity,
            int24 tick
        );

        #[derive(Debug)]
        event Mint(
            address sender,
            address indexed owner,
            int24 indexed tickLower,
            int24 indexed tickUpper,
            uint128 amount,
            uint256 amount0,
            uint256 amount1
        );

        #[derive(Debug)]
        event Burn(
            address indexed owner,
            int24 indexed tickLower,
            int24 indexed tickUpper,
            uint128 amount,
            uint256 amount0,
            uint256 amount1
        );
    }
}

/// V4 event bindings.
mod v4_events {
    alloy_sol_types::sol! {
        #[derive(Debug)]
        event Swap(
            bytes32 indexed id,
            address indexed sender,
            int128 amount0,
            int128 amount1,
            uint160 sqrtPriceX96,
            uint128 liquidity,
            int24 tick,
            uint24 fee
        );

        #[derive(Debug)]
        event ModifyLiquidity(
            bytes32 indexed id,
            address indexed sender,
            int24 tickLower,
            int24 tickUpper,
            int256 liquidityDelta
        );
    }
}

/// Pool-state ExEx configuration.
#[derive(Debug, Clone)]
pub struct PoolStateConfig {
    /// Contract exposing `getMultiTicksRange`.
    pub contract: Address,
    /// Topic0 filter; defaults to [`default_topics`].
    pub topics: Vec<B256>,
    /// Loopback RPC URL used for the `eth_call`s.
    pub http_url: String,
}

impl PoolStateConfig {
    /// Builds a config, falling back to the default topic set.
    pub fn new(contract: Address, topics: Option<Vec<B256>>, http_url: String) -> Self {
        Self {
            contract,
            topics: topics.unwrap_or_else(default_topics),
            http_url,
        }
    }
}

/// Selected tick for a pool during a block scan.
#[derive(Debug, Clone, Copy)]
struct Selection {
    tick: i32,
    is_swap: bool,
}

/// Pool-state ExEx entry point.
pub async fn pool_state_exex<N>(
    mut ctx: ExExContext<N>,
    cfg: PoolStateConfig,
    watch: PoolStateWatch,
) -> eyre::Result<()>
where
    N: FullNodeComponents,
    <N::Types as NodeTypes>::Primitives:
        NodePrimitives<Receipt: alloy_consensus::TxReceipt<Log = Log>>,
{
    let http = reqwest::Client::new();
    let exex_id = "pool-state";

    tracing::info!(
        target: "arc::exex::pool_state",
        contract = %cfg.contract,
        topics = cfg.topics.len(),
        http_url = %cfg.http_url,
        "pool-state ExEx started"
    );

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                process_chain(new, &cfg, &http, &watch).await;
            }
            ExExNotification::ChainReorged { new, .. } => {
                // Recompute the snapshot from the new chain.
                process_chain(new, &cfg, &http, &watch).await;
            }
            ExExNotification::ChainReverted { .. } => {
                // State will be refreshed by the next committed chain.
            }
        }

        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events
                .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }
    }

    tracing::info!(target: "arc::exex::pool_state", id = exex_id, "notification stream closed");
    Ok(())
}

/// Scans a committed chain for matching events, batches one
/// `getMultiTicksRange` call at the chain tip and publishes the snapshot.
async fn process_chain<N>(
    chain: &Chain<N>,
    cfg: &PoolStateConfig,
    http: &reqwest::Client,
    watch: &PoolStateWatch,
) where
    N: NodePrimitives<Receipt: alloy_consensus::TxReceipt<Log = Log>>,
{
    let mut selections: BTreeMap<B256, Selection> = BTreeMap::new();
    for block in chain.blocks_iter() {
        let Some(receipts) = chain.receipts_by_block_hash(block.hash()) else {
            continue;
        };
        for receipt in receipts {
            for log in receipt.logs() {
                process_log(log, &cfg.topics, &mut selections);
            }
        }
    }

    if selections.is_empty() {
        return;
    }

    let tip = chain.tip();
    let args: Vec<IPoolState::ITicksRangeArgs> = selections
        .iter()
        .map(|(pool_id, sel)| IPoolState::ITicksRangeArgs {
            poolId: *pool_id,
            tick: Signed::<24, 1>::try_from(sel.tick).unwrap_or_default(),
        })
        .collect();

    let returns = match call_get_multi_ticks_range(http, cfg, &args, tip.hash()).await {
        Ok(returns) => returns,
        Err(err) => {
            tracing::warn!(
                target: "arc::exex::pool_state",
                block_number = tip.number(),
                error = %err,
                "getMultiTicksRange call failed; keeping previous snapshot"
            );
            return;
        }
    };

    let entries: Vec<PoolStateEntry> = selections
        .iter()
        .zip(returns.into_iter())
        .map(|((pool_id, sel), info)| PoolStateEntry {
            pool_id: format!("{pool_id:#x}"),
            tick: sel.tick,
            lp_fee: u32::try_from(info.lpFee).unwrap_or_default(),
            range: info
                .range
                .iter()
                .map(|tick| TickRangeEntry {
                    tick_index: i32::try_from(tick.tickIndex).unwrap_or_default(),
                    liquidity_net: tick.liquidityNet.to_string(),
                })
                .collect(),
        })
        .collect();

    let snapshot = PoolStateSnapshot {
        block_number: tip.number(),
        block_hash: format!("{:#x}", tip.hash()),
        entries,
    };

    tracing::debug!(
        target: "arc::exex::pool_state",
        block_number = snapshot.block_number,
        pools = snapshot.entries.len(),
        "published pool-state snapshot"
    );
    watch.send_replace(snapshot);
}

/// Applies one log to the per-pool selection map.
fn process_log(log: &Log, topics: &[B256], selections: &mut BTreeMap<B256, Selection>) {
    let Some(&topic0) = log.topics().first() else { return };
    if !topics.contains(&topic0) {
        return;
    }

    let insert_swap = |selections: &mut BTreeMap<B256, Selection>, pool_id: B256, tick: i32| {
        selections.insert(pool_id, Selection { tick, is_swap: true });
    };
    let insert_liquidity =
        |selections: &mut BTreeMap<B256, Selection>, pool_id: B256, tick: i32| {
            match selections.get(&pool_id) {
                // A swap always outranks liquidity events for the same pool.
                Some(sel) if sel.is_swap => {}
                _ => {
                    selections.insert(pool_id, Selection { tick, is_swap: false });
                }
            }
        };

    let pool_word = log.address.into_word();
    let to_i32 = |v: Signed<24, 1>| i32::try_from(v).unwrap_or_default();
    match topic0 {
        t if t == TOPIC_UNISWAP_V3_SWAP => match v3_events::Swap::decode_log(log) {
            Ok(event) => insert_swap(selections, pool_word, to_i32(event.tick)),
            Err(err) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Swap log"),
        },
        t if t == TOPIC_V3_MINT => match v3_events::Mint::decode_log(log) {
            Ok(event) => insert_liquidity(selections, pool_word, to_i32(event.tickLower)),
            Err(err) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Mint log"),
        },
        t if t == TOPIC_V3_BURN => match v3_events::Burn::decode_log(log) {
            Ok(event) => insert_liquidity(selections, pool_word, to_i32(event.tickLower)),
            Err(err) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Burn log"),
        },
        t if t == TOPIC_V4_SWAP => match v4_events::Swap::decode_log(log) {
            Ok(event) => insert_swap(selections, event.id, to_i32(event.tick)),
            Err(err) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v4 Swap log"),
        },
        t if t == TOPIC_V4_MODIFY_LIQUIDITY => {
            match v4_events::ModifyLiquidity::decode_log(log) {
                Ok(event) => insert_liquidity(selections, event.id, to_i32(event.tickLower)),
                Err(err) => tracing::debug!(
                    target: "arc::exex::pool_state",
                    error = %err,
                    "failed to decode v4 ModifyLiquidity log"
                ),
            }
        }
        _ => {}
    }
}

/// Executes `getMultiTicksRange` at the given block hash via the loopback RPC.
async fn call_get_multi_ticks_range(
    http: &reqwest::Client,
    cfg: &PoolStateConfig,
    args: &[IPoolState::ITicksRangeArgs],
    at: B256,
) -> eyre::Result<Vec<IPoolState::IRangeTickInfoLpFee>> {
    let call = IPoolState::getMultiTicksRangeCall { args: args.to_vec() };
    let calldata = call.abi_encode();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": cfg.contract.to_checksum(None),
                "data": hex::encode_prefixed(calldata),
            },
            { "blockHash": hex::encode_prefixed(at) }
        ]
    });

    let response: serde_json::Value =
        http.post(&cfg.http_url).json(&body).send().await?.error_for_status()?.json().await?;
    if let Some(error) = response.get("error") {
        eyre::bail!("eth_call error response: {error}");
    }
    let result = response["result"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("eth_call response missing result"))?;
    let output = hex::decode(result.trim_start_matches("0x"))?;
    Ok(IPoolState::getMultiTicksRangeCall::abi_decode_returns(&output)?)
}
