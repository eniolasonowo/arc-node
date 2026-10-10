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
//!    pinned to the new chain tip, and — when a V4 rates contract is
//!    configured — a second `getMultiRatesArc` `eth_call` for the V4 pools.
//! 4. Publishes the decoded responses as a [`PoolStateSnapshot`] on a
//!    [`watch`] channel served by the `poolState` RPC namespace.

use crate::rpc::lending::{
    ILendingBlockUpdate, TOPIC_LENDING_BORROW, TOPIC_LENDING_REPAY, TOPIC_LENDING_SUPPLY,
    TOPIC_LENDING_SUPPLY_COLLATERAL, TOPIC_LENDING_WITHDRAW, TOPIC_LENDING_WITHDRAW_COLLATERAL,
};
use crate::rpc::pool_state::{
    default_topics, IV3PoolState, IV4PoolState, IV4Rates, LendingBlockUpdateData, MarketDetailEntry,
    PoolRatesEntry, PoolStateEntry, PoolStateSnapshot, PoolStateWatch, RatesPoolRegistry,
    TickRangeEntry, UserPositionEntry, TOPIC_PANCAKE_V3_SWAP, TOPIC_UNISWAP_V3_SWAP, TOPIC_V3_BURN,
    TOPIC_V3_MINT, TOPIC_V4_MODIFY_LIQUIDITY, TOPIC_V4_SWAP,
};
use alloy_consensus::{BlockHeader as _, TxEip1559, TxReceipt as _};
use alloy_primitives::{Address, Bytes, Log, Signed, TxKind, B256, I256, U160};
use alloy_sol_types::{SolCall, SolEvent};
use arc_evm::ArcEvmConfig;
use futures::TryStreamExt;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::{ConfigureEvm, Evm as _, EvmFor};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_primitives_traits::Recovered;
use reth_provider::{Chain, StateProviderBox, StateProviderFactory};
use reth_revm::{database::StateProviderDatabase, db::State};
use revm::context_interface::result::ResultAndState;
use std::collections::{BTreeMap, BTreeSet};

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

/// Lending (Morpho-family) event bindings.
pub(crate) mod lending_events {
    alloy_sol_types::sol! {
        #[derive(Debug)]
        event Supply(
            bytes32 indexed id,
            address indexed caller,
            address indexed onBehalf,
            uint256 assets,
            uint256 shares
        );

        #[derive(Debug)]
        event Withdraw(
            bytes32 indexed id,
            address caller,
            address indexed onBehalf,
            address indexed receiver,
            uint256 assets,
            uint256 shares
        );

        #[derive(Debug)]
        event Borrow(
            bytes32 indexed id,
            address caller,
            address indexed onBehalf,
            address indexed receiver,
            uint256 assets,
            uint256 shares
        );

        #[derive(Debug)]
        event Repay(
            bytes32 indexed id,
            address indexed caller,
            address indexed onBehalf,
            uint256 assets,
            uint256 shares
        );

        #[derive(Debug)]
        event SupplyCollateral(
            bytes32 indexed id,
            address indexed caller,
            address indexed onBehalf,
            uint256 assets
        );

        #[derive(Debug)]
        event WithdrawCollateral(
            bytes32 indexed id,
            address caller,
            address indexed onBehalf,
            address indexed receiver,
            uint256 assets
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
    /// V4-family contract exposing `getMultiRatesArc` (bytes32-keyed pools).
    pub contract_v4_rates: Option<Address>,
    /// Lending contract exposing `blockUpdate` (bytes32-keyed markets).
    pub contract_lending: Option<Address>,
    /// Topic0 filter; defaults to [`default_topics`].
    pub topics: Vec<B256>,
}

impl PoolStateConfig {
    /// Builds a config, falling back to the default topic set. Families
    /// without a configured contract are not tracked.
    pub fn new(
        contract_v3: Option<Address>,
        contract_v4: Option<Address>,
        contract_v4_rates: Option<Address>,
        contract_lending: Option<Address>,
        topics: Option<Vec<B256>>,
    ) -> Self {
        Self {
            contract_v3,
            contract_v4,
            contract_v4_rates,
            contract_lending,
            topics: topics.unwrap_or_else(default_topics),
        }
    }
}

/// Selected tick for a pool during a block scan.
#[derive(Debug, Clone, Copy)]
struct Selection {
    tick: i32,
    is_swap: bool,
    /// Swap market data (zero for liquidity-only pools).
    sqrt_price_x96: U160,
    liquidity: u128,
    amount0: I256,
    amount1: I256,
}

impl Selection {
    fn swap(
        tick: i32,
        sqrt_price_x96: U160,
        liquidity: u128,
        amount0: I256,
        amount1: I256,
    ) -> Self {
        Self {
            tick,
            is_swap: true,
            sqrt_price_x96,
            liquidity,
            amount0,
            amount1,
        }
    }

    fn liquidity_event(tick: i32) -> Self {
        Self {
            tick,
            is_swap: false,
            sqrt_price_x96: U160::ZERO,
            liquidity: 0,
            amount0: I256::ZERO,
            amount1: I256::ZERO,
        }
    }
}

/// Pool-state ExEx entry point.
pub async fn pool_state_exex<N>(
    mut ctx: ExExContext<N>,
    cfg: PoolStateConfig,
    watch: PoolStateWatch,
    rates_pools: RatesPoolRegistry,
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
        contract_lending = ?cfg.contract_lending,
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
                    &rates_pools,
                );
            }
            ExExNotification::ChainReorged { .. } => {
                // Arc chain has not reorg
                // Recompute the snapshot from the new chain.
                // process_chain::<N>(
                //     new,
                //     &cfg,
                //     ctx.components.evm_config(),
                //     ctx.components.provider(),
                //     &watch,
                // );
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
    rates_pools: &RatesPoolRegistry,
) where
    N: FullNodeComponents<Evm = ArcEvmConfig, Types: NodeTypes<Primitives = EthPrimitives>>,
{
    // Per-family pool selections; a family without a configured contract is
    // not tracked at all.
    let mut selections_v3: BTreeMap<Address, Selection> = BTreeMap::new();
    let mut selections_v4: BTreeMap<B256, Selection> = BTreeMap::new();
    // Lending-family selections: unique market ids and unique `onBehalf`
    // users; not tracked without a configured lending contract.
    let mut lending_ids: BTreeSet<B256> = BTreeSet::new();
    let mut lending_users: BTreeSet<Address> = BTreeSet::new();
    for block in chain.blocks_iter() {
        let Some(receipts) = chain.receipts_by_block_hash(block.hash()) else {
            continue;
        };
        for receipt in receipts {
            for log in receipt.logs() {
                process_log(log, cfg, &mut selections_v3, &mut selections_v4);
                process_lending_log(log, cfg, &mut lending_ids, &mut lending_users);
            }
        }
    }

    // Lending block-update call: independent of the pool ticks/rates calls.
    // Runs on every committed block — the contract returns market details
    // even when no lending events matched (empty ids/users); the ids/users
    // gathered from the block's events enrich the call with the positions
    // actually touched by that block.
    let lending_data = if cfg.contract_lending.is_some() {
        process_lending_block_update::<N>(
            chain,
            cfg,
            evm_config,
            provider,
            &lending_ids,
            &lending_users,
        )
    } else {
        LendingBlockUpdateData::default()
    };

    if selections_v3.is_empty() && selections_v4.is_empty() {
        if lending_data.market_details.is_empty() && lending_data.positions.is_empty() {
            return;
        }
        // Lending-only block: publish the snapshot with empty pool entries.
        let tip = chain.tip();
        let snapshot = PoolStateSnapshot {
            block_number: tip.number(),
            block_hash: format!("{:#x}", tip.hash()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
            base_fee: tip.header().base_fee_per_gas().unwrap_or_default(),
            entries: Vec::new(),
            rates: Vec::new(),
            lending: lending_data,
        };
        tracing::debug!(
            target: "arc::exex::pool_state",
            block_number = snapshot.block_number,
            markets = snapshot.lending.market_details.len(),
            "published lending-only pool-state snapshot"
        );
        watch.send_replace(snapshot);
        return;
    }

    let tip = chain.tip();
    let mut entries: Vec<PoolStateEntry> = Vec::new();

    let (mut call_evm, chain_id, base_fee) =
        match build_call_evm(evm_config, provider, tip.header(), tip.hash()) {
            Ok((evm, chain_id, base_fee)) => (evm, chain_id, base_fee),
            Err(err) => {
                tracing::warn!(
                    target: "arc::exex::pool_state",
                    block_number = tip.number(),
                    error = %err,
                    "failed to build call evm; keeping previous snapshot"
                );
                return;
            }
        };
    let started_at_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();

    if let (Some(contract), false) = (cfg.contract_v3, selections_v3.is_empty()) {
        let args: Vec<IV3PoolState::ITicksRangeArgs> = selections_v3
            .iter()
            .map(|(pool, sel)| IV3PoolState::ITicksRangeArgs {
                pool: *pool,
                tick: Signed::<24, 1>::try_from(sel.tick).unwrap_or_default(),
            })
            .collect();

        let call_started = std::time::Instant::now();
        match call_contract(
            &mut call_evm,
            evm_config,
            contract,
            IV3PoolState::getMultiTicksRangeCall { args }
                .abi_encode()
                .into(),
            chain_id,
        ) {
            Ok(output) => {
                tracing::info!(
                    target: "arc::exex::pool_state",
                    family = "v3",
                    block_number = tip.number(),
                    pools = selections_v3.len(),
                    elapsed_ms = call_started.elapsed().as_millis() as u64,
                    "getMultiTicksRange call completed"
                );
                match IV3PoolState::getMultiTicksRangeCall::abi_decode_returns(&output) {
                    Ok(returns) => {
                        entries.extend(selections_v3.iter().zip(returns).map(
                            |((pool, sel), info)| {
                                PoolStateEntry {
                                    pool_id: format!("{pool:#x}"),
                                    tick: sel.tick,
                                    lp_fee: u32::try_from(info.lpFee).unwrap_or_default(),
                                    sqrtprice_x96: sel.sqrt_price_x96,
                                    liquidity: sel.liquidity,
                                    amount0: sel.amount0,
                                    amount1: sel.amount1,
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
                            },
                        ));
                    }
                    Err(err) => tracing::warn!(
                        target: "arc::exex::pool_state",
                        block_number = tip.number(),
                        error = %err,
                        "failed to decode v3 getMultiTicksRange output"
                    ),
                }
            }
            Err(err) => tracing::warn!(
                target: "arc::exex::pool_state",
                family = "v3",
                block_number = tip.number(),
                elapsed_ms = call_started.elapsed().as_millis() as u64,
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

        let call_started = std::time::Instant::now();
        match call_contract(
            &mut call_evm,
            evm_config,
            contract,
            IV4PoolState::getMultiTicksRangeCall { args }
                .abi_encode()
                .into(),
            chain_id,
        ) {
            Ok(output) => {
                tracing::info!(
                    target: "arc::exex::pool_state",
                    family = "v4",
                    block_number = tip.number(),
                    pools = selections_v4.len(),
                    elapsed_ms = call_started.elapsed().as_millis() as u64,
                    "getMultiTicksRange call completed"
                );
                match IV4PoolState::getMultiTicksRangeCall::abi_decode_returns(&output) {
                    Ok(returns) => {
                        entries.extend(selections_v4.iter().zip(returns).map(
                            |((pool_id, sel), info)| {
                                PoolStateEntry {
                                    pool_id: format!("{pool_id:#x}"),
                                    tick: sel.tick,
                                    lp_fee: u32::try_from(info.lpFee).unwrap_or_default(),
                                    sqrtprice_x96: sel.sqrt_price_x96,
                                    liquidity: sel.liquidity,
                                    amount0: sel.amount0,
                                    amount1: sel.amount1,
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
                            },
                        ));
                    }
                    Err(err) => tracing::warn!(
                        target: "arc::exex::pool_state",
                        block_number = tip.number(),
                        error = %err,
                        "failed to decode v4 getMultiTicksRange output"
                    ),
                }
            }
            Err(err) => tracing::warn!(
                target: "arc::exex::pool_state",
                family = "v4",
                block_number = tip.number(),
                elapsed_ms = call_started.elapsed().as_millis() as u64,
                error = %err,
                "v4 getMultiTicksRange call failed; keeping previous snapshot"
            ),
        }
    }

    // Rates call for the V4 pools; independent of the ticks call outcome.
    let mut rates: Vec<PoolRatesEntry> = Vec::new();
    // Only pools both touched by this block's events and tracked via
    // `poolState_addRatesPools` get rates data; an empty registry disables
    // the rates call entirely.
    let rates_pool_ids: Vec<B256> = selections_v4
        .keys()
        .filter(|id| rates_pools.contains_id(id))
        .copied()
        .collect();
    if let (Some(rates_contract), false) =
        (cfg.contract_v4_rates, rates_pool_ids.is_empty())
    {
        let call_pool_ids: Vec<B256> = rates_pool_ids.clone();
        let pool_ids: Vec<B256> = rates_pool_ids;

        let call_started = std::time::Instant::now();
        match call_contract(
            &mut call_evm,
            evm_config,
            rates_contract,
            IV4Rates::getMultiRatesArcCall { poolIds: call_pool_ids }
                .abi_encode()
                .into(),
            chain_id,
        ) {
            Ok(output) => {
                tracing::info!(
                    target: "arc::exex::pool_state",
                    family = "v4",
                    call = "getMultiRatesArc",
                    block_number = tip.number(),
                    pools = pool_ids.len(),
                    elapsed_ms = call_started.elapsed().as_millis() as u64,
                    "getMultiRatesArc call completed"
                );
                match IV4Rates::getMultiRatesArcCall::abi_decode_returns(&output) {
                    Ok(returns) => {
                        rates.extend(returns.iter().map(|r| PoolRatesEntry {
                            pool_id: format!("{:#x}", r.poolId),
                            rate0_in: r.rate0In.to_string(),
                            delta0: r.delta0.to_string(),
                            rate1_in: r.rate1In.to_string(),
                            delta1: r.delta1.to_string(),
                            rates0_out: r.rates0Out.iter().map(|v| v.to_string()).collect(),
                            rates1_out: r.rates1Out.iter().map(|v| v.to_string()).collect(),
                        }));
                    }
                    Err(err) => tracing::warn!(
                        target: "arc::exex::pool_state",
                        family = "v4",
                        block_number = tip.number(),
                        error = %err,
                        "failed to decode v4 getMultiRatesArc output; publishing ticks without rates"
                    ),
                }
            }
            Err(err) => tracing::warn!(
                target: "arc::exex::pool_state",
                family = "v4",
                block_number = tip.number(),
                elapsed_ms = call_started.elapsed().as_millis() as u64,
                error = %err,
                "v4 getMultiRatesArc call failed; publishing ticks without rates"
            ),
        }
    }

    if entries.is_empty() && rates.is_empty() && lending_data.is_empty() {
        return;
    }

    let snapshot = PoolStateSnapshot {
        block_number: tip.number(),
        block_hash: format!("{:#x}", tip.hash()),
        timestamp: started_at_ns,
        base_fee,
        entries,
        rates,
        lending: lending_data,
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
    let Some(&topic0) = log.topics().first() else {
        return;
    };
    if !cfg.topics.contains(&topic0) {
        return;
    }

    let insert_swap =
        |selections: &mut BTreeMap<B256, Selection>, pool_id: B256, sel: Selection| {
            selections.insert(pool_id, sel);
        };
    let insert_liquidity =
        |selections: &mut BTreeMap<B256, Selection>, pool_id: B256, tick: i32| {
            match selections.get(&pool_id) {
                // A swap always outranks liquidity events for the same pool.
                Some(sel) if sel.is_swap => {}
                _ => {
                    selections.insert(pool_id, Selection::liquidity_event(tick));
                }
            }
        };
    let insert_v3_swap =
        |selections: &mut BTreeMap<Address, Selection>, pool: Address, sel: Selection| {
            selections.insert(pool, sel);
        };
    let insert_v3_liquidity =
        |selections: &mut BTreeMap<Address, Selection>, pool: Address, tick: i32| {
            match selections.get(&pool) {
                // A swap always outranks liquidity events for the same pool.
                Some(sel) if sel.is_swap => {}
                _ => {
                    selections.insert(pool, Selection::liquidity_event(tick));
                }
            }
        };

    let to_i32 = |v: Signed<24, 1>| i32::try_from(v).unwrap_or_default();
    match topic0 {
        t if t == TOPIC_UNISWAP_V3_SWAP => {
            match (cfg.contract_v3, v3_events::Swap::decode_log(log)) {
                (Some(_), Ok(event)) => insert_v3_swap(
                    selections_v3,
                    log.address,
                    Selection::swap(
                        to_i32(event.tick),
                        event.sqrtPriceX96,
                        event.liquidity,
                        event.amount0,
                        event.amount1,
                    ),
                ),
                (Some(_), Err(err)) => {
                    tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Swap log")
                }
                (None, _) => {}
            }
        }
        t if t == TOPIC_PANCAKE_V3_SWAP => {
            match (cfg.contract_v3, pancake_events::Swap::decode_log(log)) {
                (Some(_), Ok(event)) => insert_v3_swap(
                    selections_v3,
                    log.address,
                    Selection::swap(
                        to_i32(event.tick),
                        event.sqrtPriceX96,
                        event.liquidity,
                        event.amount0,
                        event.amount1,
                    ),
                ),
                (Some(_), Err(err)) => {
                    tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode pancake v3 Swap log")
                }
                (None, _) => {}
            }
        }
        t if t == TOPIC_V3_MINT => match (cfg.contract_v3, v3_events::Mint::decode_log(log)) {
            (Some(_), Ok(event)) => {
                insert_v3_liquidity(selections_v3, log.address, to_i32(event.tickLower))
            }
            (Some(_), Err(err)) => {
                tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Mint log")
            }
            (None, _) => {}
        },
        t if t == TOPIC_V3_BURN => match (cfg.contract_v3, v3_events::Burn::decode_log(log)) {
            (Some(_), Ok(event)) => {
                insert_v3_liquidity(selections_v3, log.address, to_i32(event.tickLower))
            }
            (Some(_), Err(err)) => {
                tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v3 Burn log")
            }
            (None, _) => {}
        },
        t if t == TOPIC_V4_SWAP => match (cfg.contract_v4, v4_events::Swap::decode_log(log)) {
            (Some(_), Ok(event)) => insert_swap(
                selections_v4,
                event.id,
                Selection::swap(
                    to_i32(event.tick),
                    event.sqrtPriceX96,
                    event.liquidity,
                    I256::try_from(event.amount0).unwrap_or_default(),
                    I256::try_from(event.amount1).unwrap_or_default(),
                ),
            ),
            (Some(_), Err(err)) => {
                tracing::debug!(target: "arc::exex::pool_state", error = %err, "failed to decode v4 Swap log")
            }
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

/// Applies one log to the lending id/user sets. Market ids are keyed by the
/// events' indexed `id`; users by the indexed `onBehalf` (independent lists
/// for the `blockUpdate` call). No-op without a configured lending contract.
fn process_lending_log(
    log: &Log,
    cfg: &PoolStateConfig,
    lending_ids: &mut BTreeSet<B256>,
    lending_users: &mut BTreeSet<Address>,
) {
    let Some(&topic0) = log.topics().first() else {
        return;
    };
    if cfg.contract_lending.is_none() {
        return;
    }

    let mut record = |id: B256, on_behalf: Address| {
        lending_ids.insert(id);
        lending_users.insert(on_behalf);
    };

    match topic0 {
        t if t == TOPIC_LENDING_SUPPLY => {
            if let Ok(event) = lending_events::Supply::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        t if t == TOPIC_LENDING_WITHDRAW => {
            if let Ok(event) = lending_events::Withdraw::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        t if t == TOPIC_LENDING_BORROW => {
            if let Ok(event) = lending_events::Borrow::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        t if t == TOPIC_LENDING_REPAY => {
            if let Ok(event) = lending_events::Repay::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        t if t == TOPIC_LENDING_SUPPLY_COLLATERAL => {
            if let Ok(event) = lending_events::SupplyCollateral::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        t if t == TOPIC_LENDING_WITHDRAW_COLLATERAL => {
            if let Ok(event) = lending_events::WithdrawCollateral::decode_log(log) {
                record(event.id, event.onBehalf);
            }
        }
        _ => {}
    }
}

/// Batches the selected ids/users into a single `blockUpdate` call pinned to
/// the new chain tip; returns the decoded data, or default on failure.
///
/// Called on every committed block when the lending contract is configured:
/// the contract returns market details even for empty ids/users, so the
/// snapshot stays fresh block-to-block regardless of lending activity.
#[allow(clippy::too_many_arguments)]
fn process_lending_block_update<N>(
    chain: &Chain<<N::Types as NodeTypes>::Primitives>,
    cfg: &PoolStateConfig,
    evm_config: &N::Evm,
    provider: &N::Provider,
    lending_ids: &BTreeSet<B256>,
    lending_users: &BTreeSet<Address>,
) -> LendingBlockUpdateData
where
    N: FullNodeComponents<Evm = ArcEvmConfig, Types: NodeTypes<Primitives = EthPrimitives>>,
{
    let Some(contract) = cfg.contract_lending else {
        return LendingBlockUpdateData::default();
    };
    let tip = chain.tip();

    let (mut call_evm, chain_id, _base_fee) =
        match build_call_evm(evm_config, provider, tip.header(), tip.hash()) {
            Ok(built) => built,
            Err(err) => {
                tracing::warn!(
                    target: "arc::exex::pool_state",
                    block_number = tip.number(),
                    error = %err,
                    "failed to build call evm; skipping lending block update"
                );
                return LendingBlockUpdateData::default();
            }
        };

    let ids: Vec<B256> = lending_ids.iter().copied().collect();
    let users: Vec<Address> = lending_users.iter().copied().collect();
    let call_started = std::time::Instant::now();
    match call_contract(
        &mut call_evm,
        evm_config,
        contract,
        ILendingBlockUpdate::blockUpdateCall { ids, users }
            .abi_encode()
            .into(),
        chain_id,
    ) {
        Ok(output) => {
            tracing::info!(
                target: "arc::exex::pool_state",
                family = "lending",
                call = "blockUpdate",
                block_number = tip.number(),
                ids = lending_ids.len(),
                users = lending_users.len(),
                elapsed_ms = call_started.elapsed().as_millis() as u64,
                "blockUpdate call completed"
            );
            match ILendingBlockUpdate::blockUpdateCall::abi_decode_returns(&output) {
                Ok(update) => LendingBlockUpdateData {
                    market_details: update
                        .marketDetails
                        .iter()
                        .map(|m| MarketDetailEntry {
                            id: format!("{:#x}", m.id),
                            total_supply_assets: m.totalSupplyAssets.to_string(),
                            total_supply_shares: m.totalSupplyShares.to_string(),
                            total_borrow_assets: m.totalBorrowAssets.to_string(),
                            total_borrow_shares: m.totalBorrowShares.to_string(),
                            last_update: m.lastUpdate.to_string(),
                            fee: m.fee.to_string(),
                            loan_token: format!("{:#x}", m.loanToken),
                            collateral_token: format!("{:#x}", m.collateralToken),
                            oracle: format!("{:#x}", m.oracle),
                            irm: format!("{:#x}", m.irm),
                            lltv: m.lltv.to_string(),
                            borrow_rate: m.borrowRate.to_string(),
                            price: m.price.to_string(),
                        })
                        .collect(),
                    positions: update
                        .positions
                        .iter()
                        .map(|p| UserPositionEntry {
                            id: format!("{:#x}", p.id),
                            user: format!("{:#x}", p.user),
                            supply_shares: p.supplyShares.to_string(),
                            borrow_shares: p.borrowShares.to_string(),
                            collateral: p.collateral.to_string(),
                        })
                        .collect(),
                },
                Err(err) => {
                    tracing::warn!(
                        target: "arc::exex::pool_state",
                        block_number = tip.number(),
                        error = %err,
                        "failed to decode blockUpdate output; publishing pools without lending data"
                    );
                    LendingBlockUpdateData::default()
                }
            }
        }
        Err(err) => {
            tracing::warn!(
                target: "arc::exex::pool_state",
                family = "lending",
                block_number = tip.number(),
                elapsed_ms = call_started.elapsed().as_millis() as u64,
                error = %err,
                "blockUpdate call failed; publishing pools without lending data"
            );
            LendingBlockUpdateData::default()
        }
    }
}

/// The shared EVM instance used for the per-chain `getMultiTicksRange`
/// calls: revm `State` over the tip's historical state provider.
type CallEvm = EvmFor<ArcEvmConfig, State<StateProviderDatabase<StateProviderBox>>>;

/// Builds the EVM instance shared by all of a chain's `getMultiTicksRange`
/// calls, pinned to the state at the given block.
///
/// Mirrors reth's `eth_call` handling (see `prepare_call_env` in
/// `rpc-eth-api/src/helpers/call.rs`): same cfg relaxations.
fn build_call_evm(
    evm_config: &ArcEvmConfig,
    provider: &(impl StateProviderFactory + Clone + Unpin + 'static),
    header: &alloy_consensus::Header,
    at: B256,
) -> eyre::Result<(CallEvm, u64 /* chain_id */, u64 /* base_fee */)> {
    let state = provider.history_by_block_hash(at)?;

    let mut evm_env = evm_config.evm_env(header)?;

    let chain_id = evm_env.cfg_env.chain_id;
    // Captured before `disable_base_fee` relaxes the env below.
    let base_fee = evm_env.block_env.basefee;

    // Same relaxations `prepare_call_env` applies for `eth_call`.
    evm_env.cfg_env.disable_nonce_check = true;
    evm_env.cfg_env.disable_base_fee = true;
    evm_env.cfg_env.disable_eip3607 = true;
    evm_env.cfg_env.disable_block_gas_limit = true;
    evm_env.cfg_env.disable_fee_charge = true;
    evm_env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);

    let db = State::builder()
        .with_database(StateProviderDatabase::new(state))
        .build();
    Ok((evm_config.evm_with_env(db, evm_env), chain_id, base_fee))
}

/// Executes an arbitrary call on the shared EVM: sender `0x0`, zero gas
/// price, unlimited gas. The call may leave (no-op) state changes in the
/// `State` overlay, which is fine for view contracts. Returns the raw output.
fn call_contract(
    evm: &mut CallEvm,
    evm_config: &ArcEvmConfig,
    contract: Address,
    calldata: Bytes,
    chain_id: u64,
) -> eyre::Result<Bytes> {
    let tx = TxEip1559 {
        gas_limit: u64::MAX,
        to: TxKind::Call(contract),
        input: calldata,
        // zero fees: no balance needed for the zeroed caller
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        chain_id,
        ..Default::default()
    };

    let tx_env = evm_config.tx_env(Recovered::new_unchecked(tx, Address::ZERO));
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

    /// Swap selections carry market data; liquidity-only selections default
    /// to zeros; and a liquidity event never clobbers an earlier swap's data.
    #[test]
    fn selection_market_data_semantics() {
        let sqrt = U160::from(1_234_567_890u64);
        let amt0 = I256::try_from(-100_000_000i64).unwrap();
        let amt1 = I256::try_from(500_000_000i64).unwrap();

        let swap = Selection::swap(-887220, sqrt, 987_654u128, amt0, amt1);
        assert!(swap.is_swap);
        assert_eq!(swap.tick, -887220);
        assert_eq!(swap.sqrt_price_x96, sqrt);
        assert_eq!(swap.liquidity, 987_654);
        assert_eq!(swap.amount0, amt0);
        assert_eq!(swap.amount1, amt1);

        let liq = Selection::liquidity_event(42);
        assert!(!liq.is_swap);
        assert_eq!(liq.sqrt_price_x96, U160::ZERO);
        assert_eq!(liq.liquidity, 0);
        assert_eq!(liq.amount0, I256::ZERO);
        assert_eq!(liq.amount1, I256::ZERO);

        // Same precedence rule as `insert_v3_liquidity`/`insert_liquidity`:
        // a liquidity event must not overwrite an existing swap selection.
        let mut pools: std::collections::BTreeMap<Address, Selection> =
            std::collections::BTreeMap::new();
        let pool = Address::repeat_byte(0xaa);
        pools.insert(pool, swap);
        match pools.get(&pool) {
            Some(sel) if sel.is_swap => {}
            _ => {
                pools.insert(pool, liq);
            }
        }
        let kept = &pools[&pool];
        assert_eq!(kept.sqrt_price_x96, sqrt);
        assert_eq!(kept.amount0, amt0);
        assert_eq!(kept.amount1, amt1);
    }
}

#[allow(dead_code)]
fn probe_tx_env_conversion(evm_config: &ArcEvmConfig) {
    let tx = TxEip1559::default();
    let _unused = evm_config.tx_env(Recovered::new_unchecked(tx, Address::ZERO));
}
