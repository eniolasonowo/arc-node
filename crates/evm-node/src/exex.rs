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
    IV3PoolState, IV4PoolState, TOPIC_PANCAKE_V3_SWAP, TOPIC_UNISWAP_V3_SWAP, TOPIC_V3_BURN,
    TOPIC_V3_MINT, TOPIC_V4_MODIFY_LIQUIDITY, TOPIC_V4_SWAP,
};
use alloy_consensus::{BlockHeader as _, TxEip1559, TxReceipt as _};
use alloy_primitives::{Address, Bytes, B256, Log, Signed, TxKind};
use alloy_sol_types::{SolCall, SolEvent};
use futures::TryStreamExt;
use arc_evm::ArcEvmConfig;
use reth_evm::{ConfigureEvm, Evm as _};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_ethereum_primitives::EthPrimitives;
use reth_primitives_traits::Recovered;
use reth_provider::{Chain, StateProviderFactory};
use reth_revm::{database::StateProviderDatabase, db::State};
use revm::context_interface::result::ResultAndState;
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

/// PancakeV3 event bindings (signature extends UniswapV3's Swap with two
/// trailing protocol-fee fields, hence a different topic0).
mod pancake_events {
    alloy_sol_types::sol! {
        #[derive(Debug)]
        event Swap(
            address indexed sender,
            address indexed recipient,
            int256 amount0,
            int256 amount1,
            uint160 sqrtPriceX96,
            uint128 liquidity,
            int24 tick,
            uint128 protocolFeesToken0,
            uint128 protocolFeesToken1
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
            int256 liquidityDelta,
            bytes32 extra
        );
    }
}

/// Pool-state ExEx configuration.
#[derive(Debug, Clone)]
pub struct PoolStateConfig {
    /// V3-family contract exposing `getMultiTicksRange` (address-keyed pools).
    pub contract_v3: Option<Address>,
    /// V4-family contract exposing `getMultiTicksRange` (bytes32-keyed pools).
    pub contract_v4: Option<Address>,
    /// Topic0 filter; defaults to [`default_topics`].
    pub topics: Vec<B256>,
}

impl PoolStateConfig {
    /// Builds a config, falling back to the default topic set. Families
    /// without a configured contract are not tracked.
    pub fn new(
        contract_v3: Option<Address>,
        contract_v4: Option<Address>,
        topics: Option<Vec<B256>>,
    ) -> Self {
        Self {
            contract_v3,
            contract_v4,
            topics: topics.unwrap_or_else(default_topics),
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
    N: FullNodeComponents<
        Evm = ArcEvmConfig,
        Provider: StateProviderFactory + Clone + Unpin + 'static,
        Types: NodeTypes<Primitives = EthPrimitives>,
    >,
{
    let exex_id = "pool-state";

    tracing::info!(
        target: "arc::exex::pool_state",
        contract_v3 = ?cfg.contract_v3,
        contract_v4 = ?cfg.contract_v4,
        topics = cfg.topics.len(),
        "pool-state ExEx started"
    );

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                process_chain::<N>(
                    new,
                    &cfg,
                    ctx.components.evm_config(),
                    ctx.components.provider(),
                    &watch,
                );
            }
            ExExNotification::ChainReorged { new, .. } => {
                // Recompute the snapshot from the new chain.
                process_chain::<N>(
                    new,
                    &cfg,
                    ctx.components.evm_config(),
                    ctx.components.provider(),
                    &watch,
                );
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
fn process_chain<N>(
    chain: &Chain<<N::Types as NodeTypes>::Primitives>,
    cfg: &PoolStateConfig,
    evm_config: &N::Evm,
    provider: &N::Provider,
    watch: &PoolStateWatch,
) where
    N: FullNodeComponents<Evm = ArcEvmConfig, Types: NodeTypes<Primitives = EthPrimitives>>,
{
    // Per-family pool selections; a family without a configured contract is
    // not tracked at all.
    let mut selections_v3: BTreeMap<Address, Selection> = BTreeMap::new();
    let mut selections_v4: BTreeMap<B256, Selection> = BTreeMap::new();
    for block in chain.blocks_iter() {
        let Some(receipts) = chain.receipts_by_block_hash(block.hash()) else {
            continue;
        };
        for receipt in receipts {
            for log in receipt.logs() {
                process_log(log, cfg, &mut selections_v3, &mut selections_v4);
            }
        }
    }

    if selections_v3.is_empty() && selections_v4.is_empty() {
        return;
    }

    let tip = chain.tip();
    let mut entries: Vec<PoolStateEntry> = Vec::new();

    if let (Some(contract), false) = (cfg.contract_v3, selections_v3.is_empty()) {
        let args: Vec<IV3PoolState::ITicksRangeArgs> = selections_v3
            .iter()
            .map(|(pool, sel)| IV3PoolState::ITicksRangeArgs {
                pool: *pool,
                tick: Signed::<24, 1>::try_from(sel.tick).unwrap_or_default(),
            })
            .collect();

        match execute_eth_call(
            evm_config,
            provider,
            contract,
            IV3PoolState::getMultiTicksRangeCall { args }.abi_encode().into(),
            tip.header(),
            tip.hash(),
        ) {
            Ok(output) => match IV3PoolState::getMultiTicksRangeCall::abi_decode_returns(&output)
            {
                Ok(returns) => {
                    entries.extend(selections_v3.iter().zip(returns).map(|((pool, sel), info)| {
                        PoolStateEntry {
                            pool_id: format!("{pool:#x}"),
                            tick: sel.tick,
                            lp_fee: u32::try_from(info.lpFee).unwrap_or_default(),
                            range: info
                                .range
                                .iter()
                                .map(|tick| TickRangeEntry {
                                    tick_index: i32::try_from(tick.tickIndex)
                                        .unwrap_or_default(),
                                    liquidity_net: tick.liquidityNet.to_string(),
                                })
                                .collect(),
                        }
                    }));
                }
                Err(err) => tracing::warn!(
                    target: "arc::exex::pool_state",
                    block_number = tip.number(),
                    error = %err,
                    "failed to decode v3 getMultiTicksRange output"
                ),
            },
            Err(err) => tracing::warn!(
                target: "arc::exex::pool_state",
                block_number = tip.number(),
                error = %err,
                "v3 getMultiTicksRange call failed; keeping previous snapshot"
            ),
        }
    }

    if let (Some(contract), false) = (cfg.contract_v4, selections_v4.is_empty()) {
        let args: Vec<IV4PoolState::ITicksRangeArgs> = selections_v4
            .iter()
            .map(|(pool_id, sel)| IV4PoolState::ITicksRangeArgs {
                poolId: *pool_id,
                tick: Signed::<24, 1>::try_from(sel.tick).unwrap_or_default(),
            })
            .collect();

        match execute_eth_call(
            evm_config,
            provider,
            contract,
            IV4PoolState::getMultiTicksRangeCall { args }.abi_encode().into(),
            tip.header(),
            tip.hash(),
        ) {
            Ok(output) => match IV4PoolState::getMultiTicksRangeCall::abi_decode_returns(&output)
            {
                Ok(returns) => {
                    entries.extend(selections_v4.iter().zip(returns).map(
                        |((pool_id, sel), info)| PoolStateEntry {
                            pool_id: format!("{pool_id:#x}"),
                            tick: sel.tick,
                            lp_fee: u32::try_from(info.lpFee).unwrap_or_default(),
                            range: info
                                .range
                                .iter()
                                .map(|tick| TickRangeEntry {
                                    tick_index: i32::try_from(tick.tickIndex)
                                        .unwrap_or_default(),
                                    liquidity_net: tick.liquidityNet.to_string(),
                                })
                                .collect(),
                        },
                    ));
                }
                Err(err) => tracing::warn!(
                    target: "arc::exex::pool_state",
                    block_number = tip.number(),
                    error = %err,
                    "failed to decode v4 getMultiTicksRange output"
                ),
            },
            Err(err) => tracing::warn!(
                target: "arc::exex::pool_state",
                block_number = tip.number(),
                error = %err,
                "v4 getMultiTicksRange call failed; keeping previous snapshot"
            ),
        }
    }

    if entries.is_empty() {
        return;
    }

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

/// Applies one log to the per-family selection maps. V3-family pools are
/// keyed by address, V4-family pools by bytes32 id; families without a
/// configured contract are skipped.
fn process_log(
    log: &Log,
    cfg: &PoolStateConfig,
    selections_v3: &mut BTreeMap<Address, Selection>,
    selections_v4: &mut BTreeMap<B256, Selection>,
) {
    let Some(&topic0) = log.topics().first() else { return };
    if !cfg.topics.contains(&topic0) {
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
    let insert_v3_swap =
        |selections: &mut BTreeMap<Address, Selection>, pool: Address, tick: i32| {
            selections.insert(pool, Selection { tick, is_swap: true });
        };
    let insert_v3_liquidity =
        |selections: &mut BTreeMap<Address, Selection>, pool: Address, tick: i32| {
            match selections.get(&pool) {
                // A swap always outranks liquidity events for the same pool.
                Some(sel) if sel.is_swap => {}
                _ => {
                    selections.insert(pool, Selection { tick, is_swap: false });
                }
            }
        };

    let to_i32 = |v: Signed<24, 1>| i32::try_from(v).unwrap_or_default();
    match topic0 {
        t if t == TOPIC_UNISWAP_V3_SWAP => match (cfg.contract_v3, v3_events::Swap::decode_log(log)) {
            (Some(_), Ok(event)) => insert_v3_swap(selections_v3, log.address, to_i32(event.tick)),
            (Some(_), Err(err)) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Swap log"),
            (None, _) => {}
        },
        t if t == TOPIC_PANCAKE_V3_SWAP => {
            match (cfg.contract_v3, pancake_events::Swap::decode_log(log)) {
                (Some(_), Ok(event)) => {
                    insert_v3_swap(selections_v3, log.address, to_i32(event.tick))
                }
                (Some(_), Err(err)) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode pancake v3 Swap log"),
                (None, _) => {}
            }
        }
        t if t == TOPIC_V3_MINT => match (cfg.contract_v3, v3_events::Mint::decode_log(log)) {
            (Some(_), Ok(event)) => {
                insert_v3_liquidity(selections_v3, log.address, to_i32(event.tickLower))
            }
            (Some(_), Err(err)) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Mint log"),
            (None, _) => {}
        },
        t if t == TOPIC_V3_BURN => match (cfg.contract_v3, v3_events::Burn::decode_log(log)) {
            (Some(_), Ok(event)) => {
                insert_v3_liquidity(selections_v3, log.address, to_i32(event.tickLower))
            }
            (Some(_), Err(err)) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Burn log"),
            (None, _) => {}
        },
        t if t == TOPIC_V4_SWAP => match (cfg.contract_v4, v4_events::Swap::decode_log(log)) {
            (Some(_), Ok(event)) => insert_swap(selections_v4, event.id, to_i32(event.tick)),
            (Some(_), Err(err)) => tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v4 Swap log"),
            (None, _) => {}
        },
        t if t == TOPIC_V4_MODIFY_LIQUIDITY => {
            match (cfg.contract_v4, v4_events::ModifyLiquidity::decode_log(log)) {
                (Some(_), Ok(event)) => {
                    insert_liquidity(selections_v4, event.id, to_i32(event.tickLower))
                }
                (Some(_), Err(err)) => tracing::debug!(
                    target: "arc::exex::pool_state",
                    error = %err,
                    "failed to decode v4 ModifyLiquidity log"
                ),
                (None, _) => {}
            }
        }
        _ => {}
    }
}

/// Executes an arbitrary call against the state at the given block,
/// in-process, mirroring reth's `eth_call` handling (see
/// `prepare_call_env` in `rpc-eth-api/src/helpers/call.rs`): sender `0x0`,
/// zero gas price, and the same cfg relaxations. Returns the raw output.
fn execute_eth_call(
    evm_config: &ArcEvmConfig,
    provider: &(impl StateProviderFactory + Clone + Unpin + 'static),
    contract: Address,
    calldata: Bytes,
    header: &alloy_consensus::Header,
    at: B256,
) -> eyre::Result<Bytes> {
    let state = provider.history_by_block_hash(at)?;

    let mut evm_env = evm_config.evm_env(header)?;

    // Same relaxations `prepare_call_env` applies for `eth_call`.
    evm_env.cfg_env.disable_nonce_check = true;
    evm_env.cfg_env.disable_base_fee = true;
    evm_env.cfg_env.disable_eip3607 = true;
    evm_env.cfg_env.disable_block_gas_limit = true;
    evm_env.cfg_env.disable_fee_charge = true;
    evm_env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);

    let tx = TxEip1559 {
        gas_limit: u64::MAX,
        to: TxKind::Call(contract),
        input: calldata,
        // zero fees: no balance needed for the zeroed caller
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        ..Default::default()
    };

    let tx_env = evm_config.tx_env(Recovered::new_unchecked(tx, Address::ZERO));

    let db = State::builder().with_database(StateProviderDatabase::new(state)).build();
    let mut evm = evm_config.evm_with_env(db, evm_env);
    let ResultAndState { result, .. } = evm.transact_raw(tx_env)?;
    result
        .into_output()
        .ok_or_else(|| eyre::eyre!("call returned no output"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::pool_state::{
        TOPIC_PANCAKE_V3_SWAP, TOPIC_UNISWAP_V3_SWAP, TOPIC_V3_BURN, TOPIC_V3_MINT,
        TOPIC_V4_MODIFY_LIQUIDITY, TOPIC_V4_SWAP,
    };
    use alloy_sol_types::SolEvent;

    /// Each topic0 filter constant must equal the signature hash of the event
    /// binding used to decode it; otherwise logs would silently stop matching.
    #[test]
    fn topic_constants_match_event_bindings() {
        assert_eq!(
            TOPIC_UNISWAP_V3_SWAP,
            v3_events::Swap::SIGNATURE_HASH,
            "uniswap v3 swap topic drifted from its binding"
        );
        assert_ne!(
            TOPIC_PANCAKE_V3_SWAP, TOPIC_UNISWAP_V3_SWAP,
            "pancake v3 swap topic must differ from uniswap v3's"
        );
        assert_eq!(
            TOPIC_PANCAKE_V3_SWAP,
            pancake_events::Swap::SIGNATURE_HASH,
            "pancake v3 swap topic drifted from its binding"
        );
        assert_eq!(TOPIC_V3_MINT, v3_events::Mint::SIGNATURE_HASH);
        assert_eq!(TOPIC_V3_BURN, v3_events::Burn::SIGNATURE_HASH);
        assert_eq!(TOPIC_V4_SWAP, v4_events::Swap::SIGNATURE_HASH);
        assert_eq!(
            TOPIC_V4_MODIFY_LIQUIDITY,
            v4_events::ModifyLiquidity::SIGNATURE_HASH
        );
    }

    /// The default topic filter must contain every supported topic exactly once.
    #[test]
    fn default_topics_cover_all_supported() {
        let mut topics = default_topics();
        topics.sort();
        topics.dedup();
        assert_eq!(
            topics.len(),
            default_topics().len(),
            "default topic list contains duplicates"
        );
        for expected in [
            TOPIC_UNISWAP_V3_SWAP,
            TOPIC_PANCAKE_V3_SWAP,
            TOPIC_V3_MINT,
            TOPIC_V3_BURN,
            TOPIC_V4_MODIFY_LIQUIDITY,
            TOPIC_V4_SWAP,
        ] {
            assert!(
                default_topics().contains(&expected),
                "default topic list missing {expected}"
            );
        }
    }
}


#[allow(dead_code)]
fn probe_tx_env_conversion(evm_config: &ArcEvmConfig) {
    let tx = TxEip1559::default();
    let _unused = evm_config.tx_env(Recovered::new_unchecked(tx, Address::ZERO));
}

