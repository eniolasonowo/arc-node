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

//! Lending block-update bindings used by the pool-state ExEx (see
//! `crate::exex`): topic0 constants for the Morpho-family market events and
//! the `blockUpdate` call interface. The decoded data is published as the
//! `lending` field of [`crate::rpc::pool_state::PoolStateSnapshot`].

use alloy_primitives::{b256, B256};
use alloy_sol_types::sol;

/// Morpho `Supply(bytes32 indexed id, address indexed caller, address indexed onBehalf, uint256 assets, uint256 shares)`.
pub const TOPIC_LENDING_SUPPLY: B256 =
    b256!("0xedf8870433c83823eb071d3df1caa8d008f12f6440918c20d75a3602cda30fe0");

/// Morpho `Withdraw(bytes32 indexed id, address caller, address indexed onBehalf, address indexed receiver, uint256 assets, uint256 shares)`.
pub const TOPIC_LENDING_WITHDRAW: B256 =
    b256!("0xa56fc0ad5702ec05ce63666221f796fb62437c32db1aa1aa075fc6484cf58fbf");

/// Morpho `Borrow(bytes32 indexed id, address caller, address indexed onBehalf, address indexed receiver, uint256 assets, uint256 shares)`.
pub const TOPIC_LENDING_BORROW: B256 =
    b256!("0x570954540bed6b1304a87dfe815a5eda4a648f7097a16240dcd85c9b5fd42a43");

/// Morpho `Repay(bytes32 indexed id, address indexed caller, address indexed onBehalf, uint256 assets, uint256 shares)`.
pub const TOPIC_LENDING_REPAY: B256 =
    b256!("0x52acb05cebbd3cd39715469f22afbf5a17496295ef3bc9bb5944056c63ccaa09");

/// Morpho `SupplyCollateral(bytes32 indexed id, address indexed caller, address indexed onBehalf, uint256 assets)`.
pub const TOPIC_LENDING_SUPPLY_COLLATERAL: B256 =
    b256!("0xa3b9472a1399e17e123f3c2e6586c23e504184d504de59cdaa2b375e880c6184");

/// Morpho `WithdrawCollateral(bytes32 indexed id, address caller, address indexed onBehalf, address indexed receiver, uint256 assets)`.
pub const TOPIC_LENDING_WITHDRAW_COLLATERAL: B256 =
    b256!("0xe80ebd7cc9223d7382aab2e0d1d6155c65651f83d53c8b9b06901d167e321142");

// Lending block-update contract: markets are identified by bytes32 id.
sol! {
    #[derive(Debug)]
    interface ILendingBlockUpdate {
        struct UserPosition {
            bytes32 id;
            address user;
            uint256 supplyShares;
            uint128 borrowShares;
            uint128 collateral;
        }

        struct MarketDetail {
            bytes32 id;
            // market
            uint128 totalSupplyAssets;
            uint128 totalSupplyShares;
            uint128 totalBorrowAssets;
            uint128 totalBorrowShares;
            uint128 lastUpdate;
            uint128 fee;
            // market params
            address loanToken;
            address collateralToken;
            address oracle;
            address irm;
            uint256 lltv;
            // irm borrow rate
            uint256 borrowRate;
            // oracle price
            uint256 price;
        }

        struct BlockUpdate {
            MarketDetail[] marketDetails;
            UserPosition[] positions;
        }

        function blockUpdate(bytes32[] memory ids, address[] memory users)
            external
            returns (BlockUpdate memory update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exex::lending_events;
    use alloy_sol_types::SolEvent;

    /// Each topic0 filter constant must equal the signature hash of the
    /// event binding used to decode it; otherwise logs would silently stop
    /// matching.
    #[test]
    fn topic_constants_match_event_bindings() {
        assert_eq!(
            TOPIC_LENDING_SUPPLY,
            lending_events::Supply::SIGNATURE_HASH,
            "lending Supply topic drifted from its binding"
        );
        assert_eq!(
            TOPIC_LENDING_WITHDRAW,
            lending_events::Withdraw::SIGNATURE_HASH,
            "lending Withdraw topic drifted from its binding"
        );
        assert_eq!(
            TOPIC_LENDING_BORROW,
            lending_events::Borrow::SIGNATURE_HASH,
            "lending Borrow topic drifted from its binding"
        );
        assert_eq!(
            TOPIC_LENDING_REPAY,
            lending_events::Repay::SIGNATURE_HASH,
            "lending Repay topic drifted from its binding"
        );
        assert_eq!(
            TOPIC_LENDING_SUPPLY_COLLATERAL,
            lending_events::SupplyCollateral::SIGNATURE_HASH,
            "lending SupplyCollateral topic drifted from its binding"
        );
        assert_eq!(
            TOPIC_LENDING_WITHDRAW_COLLATERAL,
            lending_events::WithdrawCollateral::SIGNATURE_HASH,
            "lending WithdrawCollateral topic drifted from its binding"
        );
    }
}
