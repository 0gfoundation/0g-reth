use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use reth_primitives_traits::constants::GAS_LIMIT_BOUND_DIVISOR;

/// Settings for the Ethereum builder.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EthereumBuilderConfig {
    /// Desired gas limit.
    pub desired_gas_limit: u64,
    /// Waits for the first payload to be built if there is no payload built when the payload is
    /// being resolved.
    pub await_payload_on_missing: bool,
    /// If non-zero, on blocks where `target_block % perpdex_modulus != 0` the payload builder
    /// packs PerpDEX-targeted transactions first and only uses remaining gas to fill the block
    /// with non-PerpDEX transactions. `0` disables the behavior entirely.
    pub perpdex_modulus: u64,
}

impl Default for EthereumBuilderConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EthereumBuilderConfig {
    /// Create new payload builder config.
    pub const fn new() -> Self {
        Self {
            desired_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M,
            await_payload_on_missing: true,
            perpdex_modulus: 0,
        }
    }

    /// Set desired gas limit.
    pub const fn with_gas_limit(mut self, desired_gas_limit: u64) -> Self {
        self.desired_gas_limit = desired_gas_limit;
        self
    }

    /// Configures whether the initial payload should be awaited when the payload job is being
    /// resolved and no payload has been built yet.
    pub const fn with_await_payload_on_missing(mut self, await_payload_on_missing: bool) -> Self {
        self.await_payload_on_missing = await_payload_on_missing;
        self
    }

    /// Enables PerpDEX-priority packing with the given modulus. `0` disables the behavior
    /// (see [`EthereumBuilderConfig::perpdex_modulus`]).
    pub const fn with_perpdex_modulus(mut self, perpdex_modulus: u64) -> Self {
        self.perpdex_modulus = perpdex_modulus;
        self
    }

    /// Returns `true` if `target_block` should pack transactions with the current unrestricted
    /// behavior (either the feature is disabled or this block is a scheduled "open" block).
    /// When `false`, non-PerpDEX transactions must be deferred to the fill pass.
    pub const fn is_open_block(&self, target_block: u64) -> bool {
        self.perpdex_modulus == 0 || target_block.is_multiple_of(self.perpdex_modulus)
    }
}

impl EthereumBuilderConfig {
    /// Returns the gas limit for the next block based
    /// on parent and desired gas limits.
    pub fn gas_limit(&self, parent_gas_limit: u64) -> u64 {
        calculate_block_gas_limit(parent_gas_limit, self.desired_gas_limit)
    }
}

/// Calculate the gas limit for the next block based on parent and desired gas limits.
/// Ref: <https://github.com/ethereum/go-ethereum/blob/88cbfab332c96edfbe99d161d9df6a40721bd786/core/block_validator.go#L166>
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - delta;
    let max_gas_limit = parent_gas_limit + delta;
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_modulus(modulus: u64) -> EthereumBuilderConfig {
        EthereumBuilderConfig::new().with_perpdex_modulus(modulus)
    }

    #[test]
    fn modulus_zero_treats_every_block_as_open() {
        let cfg = config_with_modulus(0);
        for target in [0u64, 1, 7, 10, 99, u64::MAX] {
            assert!(
                cfg.is_open_block(target),
                "modulus=0 target={target} must be open (feature disabled)"
            );
        }
    }

    #[test]
    fn modulus_one_treats_every_block_as_open() {
        // modulus == 1 degenerates to "every block is open" since N % 1 == 0 for all N.
        let cfg = config_with_modulus(1);
        for target in [0u64, 1, 2, 99, u64::MAX] {
            assert!(cfg.is_open_block(target), "modulus=1 target={target} must be open");
        }
    }

    #[test]
    fn modulus_ten_opens_only_multiples() {
        let cfg = config_with_modulus(10);
        // closed on non-multiples
        for target in [1u64, 2, 5, 9, 11, 19, 21, 99] {
            assert!(!cfg.is_open_block(target), "modulus=10 target={target} must be closed");
        }
        // open on multiples (including 0: the genesis-successor case)
        for target in [0u64, 10, 20, 100, 10_000] {
            assert!(cfg.is_open_block(target), "modulus=10 target={target} must be open");
        }
    }

    #[test]
    fn default_config_has_feature_disabled() {
        // Sanity: `new()` and `Default::default()` both leave the feature off so the
        // unmodified builder path is byte-for-byte identical to upstream.
        assert_eq!(EthereumBuilderConfig::new().perpdex_modulus, 0);
        assert_eq!(EthereumBuilderConfig::default().perpdex_modulus, 0);
        assert!(EthereumBuilderConfig::default().is_open_block(1));
        assert!(EthereumBuilderConfig::default().is_open_block(7));
    }
}
