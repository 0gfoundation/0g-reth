use crate::spec::DepositContract;
use alloy_eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS;
use alloy_primitives::b256;

/// The chain ID for the 0G Chain devnet.
pub const ZG_DEVNET_CHAIN_ID: u64 = 16_601;

/// The chain ID for the 0G Chain testnet.
pub const ZG_TESTNET_CHAIN_ID: u64 = 16_602;

/// The chain ID for the 0G Chain mainnet.
pub const ZG_MAINNET_CHAIN_ID: u64 = 16_661;

/// Staking activation timestamp for 0G mainnet (2026-01-28 0:00:00 UTC).
pub const STAKING_ACTIVATION_TIME_MAINNET: u64 = 1_769_558_400;

/// Staking activation timestamp for 0G testnet/devnet (2026-01-08 0:00:00 UTC).
pub const STAKING_ACTIVATION_TIME_TESTNET: u64 = 1_767_830_400;

/// Returns the staking activation timestamp for the given chain ID.
///
/// Unknown chains return `0` (staking inactive).
#[inline]
pub const fn staking_activation_time(chain_id: u64) -> u64 {
    match chain_id {
        ZG_MAINNET_CHAIN_ID => STAKING_ACTIVATION_TIME_MAINNET,
        ZG_TESTNET_CHAIN_ID | ZG_DEVNET_CHAIN_ID => STAKING_ACTIVATION_TIME_TESTNET,
        _ => 0,
    }
}

/// Gas per transaction not creating a contract.
pub const MIN_TRANSACTION_GAS: u64 = 21_000u64;

/// Mainnet prune delete limit.
pub const MAINNET_PRUNE_DELETE_LIMIT: usize = 20000;

/// Deposit contract address: `0x00000000219ab540356cbb839cbe05303d7705fa`
pub(crate) const MAINNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    MAINNET_DEPOSIT_CONTRACT_ADDRESS,
    11052984,
    b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staking_activation_time_by_chain_id() {
        assert_eq!(
            staking_activation_time(ZG_MAINNET_CHAIN_ID),
            STAKING_ACTIVATION_TIME_MAINNET
        );
        assert_eq!(
            staking_activation_time(ZG_TESTNET_CHAIN_ID),
            STAKING_ACTIVATION_TIME_TESTNET
        );
        assert_eq!(
            staking_activation_time(ZG_DEVNET_CHAIN_ID),
            STAKING_ACTIVATION_TIME_TESTNET
        );
        assert_eq!(staking_activation_time(1), 0);
    }
}
