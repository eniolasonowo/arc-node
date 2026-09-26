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

//! Pool state RPC namespace.
//!
//! Exposes the latest per-block pool tick ranges gathered by the pool-state
//! ExEx (see `crate::exex`): the ExEx watches swap/liquidity events, batches
//! the affected pools into a single `getMultiTicksRange` call per block and
//! publishes the decoded response on a [`watch`] channel; this module serves
//! it as `poolState_latest` and `poolState_subscribe`.

use alloy_primitives::{b256, B256, I256, U160};
use alloy_sol_types::sol;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, PendingSubscriptionSink, SubscriptionMessage};
use tokio::sync::watch;

/// UniswapV3 `Swap(address,address,int256,int256,uint160,uint128,int24)`.
pub const TOPIC_UNISWAP_V3_SWAP: B256 =
    b256!("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67");

/// PancakeV3 `Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick,uint128 protocolFeesToken0,uint128 protocolFeesToken1)`.
pub const TOPIC_PANCAKE_V3_SWAP: B256 =
    b256!("0x19b47279256b2a23a1665c810c8d55a1758940ee09377d4f8d26497a3577dc83");

/// V3 `Mint(address,address indexed owner,int24 indexed tickLower,int24 indexed tickUpper,uint128,uint256,uint256)`.
pub const TOPIC_V3_MINT: B256 =
    b256!("0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde");

/// V3 `Burn(address indexed owner,int24 indexed tickLower,int24 indexed tickUpper,uint128,uint256,uint256)`.
pub const TOPIC_V3_BURN: B256 =
    b256!("0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c");

/// UniswapV4 `ModifyLiquidity(bytes32 indexed id,address indexed sender,int24 tickLower,int24 tickUpper,int256 liquidityDelta)`.
pub const TOPIC_V4_MODIFY_LIQUIDITY: B256 =
    b256!("0xf208f4912782fd25c7f114ca3723a2d5dd6f3bcc3ac8db5af63baa85f711d5ec");

/// UniswapV4 `Swap(bytes32 indexed id,address indexed sender,int128 amount0,int128 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick,uint24 fee)`.
pub const TOPIC_V4_SWAP: B256 =
    b256!("0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f");

/// Default topic0 filter used when `--exex.pool-state.topics` is not set.
pub fn default_topics() -> Vec<B256> {
    vec![
        TOPIC_UNISWAP_V3_SWAP,
        TOPIC_PANCAKE_V3_SWAP,
        TOPIC_V3_MINT,
        TOPIC_V3_BURN,
        TOPIC_V4_MODIFY_LIQUIDITY,
        TOPIC_V4_SWAP,
    ]
}

// V3-family tick-range contract: pools are identified by address.
sol! {
    #[derive(Debug)]
    interface IV3PoolState {
        struct ITicksRangeArgs {
            address pool;
            int24 tick;
        }
        struct IRangeTickInfo {
            int24 tickIndex;
            int128 liquidityNet;
        }
        struct IRangeTickInfoLpFee {
            uint24 lpFee;
            IRangeTickInfo[] range;
        }
        function getMultiTicksRange(ITicksRangeArgs[] memory args)
            external
            view
            returns (IRangeTickInfoLpFee[] memory multiPoolInfo);
    }
}

// V4-family tick-range contract: pools are identified by bytes32 id.
sol! {
    #[derive(Debug)]
    interface IV4PoolState {
        struct ITicksRangeArgs {
            bytes32 poolId;
            int24 tick;
        }
        struct IRangeTickInfo {
            int24 tickIndex;
            int128 liquidityNet;
        }
        struct IRangeTickInfoLpFee {
            uint24 lpFee;
            IRangeTickInfo[] range;
        }
        function getMultiTicksRange(ITicksRangeArgs[] memory args)
            external
            view
            returns (IRangeTickInfoLpFee[] memory multiPoolInfo);
    }
}

// V4-family rates contract: pools are identified by bytes32 id.
sol! {
    #[derive(Debug)]
    interface IV4Rates {
        struct Rates {
            bytes32 poolId;
            uint256 rate0In;
            uint256 delta0;
            uint256 rate1In;
            uint256 delta1;
            uint256[] rates0Out;
            uint256[] rates1Out;
        }
        function getMultiRatesArc(bytes32[] memory poolIds)
            public
            returns (Rates[] memory rates);
    }
}

/// One tick entry of a pool's range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TickRangeEntry {
    /// Tick index.
    pub tick_index: i32,
    /// Net liquidity at the tick, decimal string (int128).
    pub liquidity_net: String,
}

/// Per-pool tick-range state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolStateEntry {
    /// Pool id: V4 raw `bytes32` id, or a left-padded V2/V3 pool address.
    pub pool_id: String,
    /// Tick that triggered the refresh.
    pub tick: i32,
    /// Pool fee in hundredths of a bip.
    pub lp_fee: u32,

    /// SqrtPriceX96
    pub sqrtprice_x96: U160,
    /// liquidity
    pub liquidity: u128,
    pub amount0: I256,
    pub amount1: I256,
    /// Tick range around the trigger tick.
    pub range: Vec<TickRangeEntry>,
}

/// Per-pool rates from `getMultiRatesArc`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolRatesEntry {
    /// V4 raw `bytes32` pool id.
    pub pool_id: String,
    /// Input rate for token0, decimal string (uint256).
    pub rate0_in: String,
    /// Delta for token0, decimal string (uint256).
    pub delta0: String,
    /// Input rate for token1, decimal string (uint256).
    pub rate1_in: String,
    /// Delta for token1, decimal string (uint256).
    pub delta1: String,
    /// Output rates for token0, decimal strings (uint256).
    pub rates0_out: Vec<String>,
    /// Output rates for token1, decimal strings (uint256).
    pub rates1_out: Vec<String>,
}

/// Latest pool-state snapshot published by the ExEx for one block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PoolStateSnapshot {
    /// Block the snapshot was computed at (0 until the first block).
    pub block_number: u64,
    /// Hash of the block the snapshot was computed at.
    pub block_hash: String,

    /// Wall-clock nanoseconds since the Unix epoch, captured when the ExEx
    /// began processing the notification that produced this snapshot.
    pub timestamp: u128,
    /// Base fee of the block the snapshot was computed at (0 if pre-London).
    pub base_fee: u64,

    /// One entry per pool that had a matching event in the block.
    pub entries: Vec<PoolStateEntry>,
    /// One entry per V4 pool with a configured rates contract; empty if the
    /// rates contract is not configured or the call failed.
    pub rates: Vec<PoolRatesEntry>,
}

/// Watch channel used to publish snapshots from the ExEx to the RPC layer.
pub type PoolStateWatch = watch::Sender<PoolStateSnapshot>;

/// `poolState` namespace: latest snapshot + WS subscription.
#[rpc(server, namespace = "poolState")]
pub trait PoolStateApi {
    /// Returns the latest pool-state snapshot, if any block has been processed yet.
    #[method(name = "latest")]
    fn latest(&self) -> RpcResult<Option<PoolStateSnapshot>>;

    /// Subscribes to pool-state snapshots; one update per block that produced
    /// at least one matching event.
    #[subscription(name = "subscribe", unsubscribe = "unsubscribe", item = PoolStateSnapshot)]
    fn subscribe(&self);
}

pub struct PoolStateRpc {
    /// Latest published snapshot.
    rx: watch::Receiver<PoolStateSnapshot>,
}

impl PoolStateApiServer for PoolStateRpc {
    fn latest(&self) -> RpcResult<Option<PoolStateSnapshot>> {
        if self.rx.borrow().block_number == 0 {
            return Ok(None);
        }
        Ok(Some(self.rx.borrow().clone()))
    }

    fn subscribe(&self, pending: PendingSubscriptionSink) {
        let mut rx = self.rx.clone();
        tokio::spawn(async move {
            let sink = match pending.accept().await {
                Ok(sink) => sink,
                Err(e) => {
                    tracing::debug!(target: "rpc::pool_state", error = %e, "subscription closed before accept");
                    return;
                }
            };
            // Skip the initial value: subscribers only get new snapshots.
            let _ = rx.changed().await;
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                let snapshot = rx.borrow_and_update().clone();
                let raw = serde_json::value::to_raw_value(&snapshot).expect("snapshot serializes");
                let msg = SubscriptionMessage::from(raw);
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Builds the `poolState` RPC module backed by the given watch receiver.
pub fn build_pool_state_rpc_module(
    rx: watch::Receiver<PoolStateSnapshot>,
) -> jsonrpsee::RpcModule<PoolStateRpc> {
    PoolStateRpc { rx }.into_rpc()
}
