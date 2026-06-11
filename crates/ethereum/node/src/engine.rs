//! Validates execution payload wrt Ethereum Execution Engine API version.

use alloy_primitives::{Address, TxHash};
use alloy_rpc_types_engine::ExecutionData;
pub use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes,
};
use rayon::prelude::*;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_ethereum_primitives::Block;
use reth_node_api::PayloadTypes;
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_primitives_traits::{RecoveredBlock, SignerRecoverable};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

// Spike: bound the persistent sender cache so a long bench doesn't grow it without limit.
// When exceeded the cache is cleared. Briefly drops hit rate to 0% for the next few blocks.
const SIGNER_CACHE_CAP: usize = 1_000_000;

type SignerCache = Arc<RwLock<HashMap<TxHash, Address>>>;

/// Validator for the ethereum engine API.
#[derive(Debug, Clone)]
pub struct EthereumEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
    signer_cache: SignerCache,
}

impl<ChainSpec> EthereumEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
            signer_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = self.inner.ensure_well_formed_payload(payload)?;

        let txs: &[_] = sealed_block.body().transactions.as_slice();
        let n = txs.len();
        if n == 0 {
            return sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()));
        }

        // Two-pass: snapshot lookups under one read-lock, then ECDSA in parallel for misses.
        let lookup: Vec<Option<Address>> = {
            let cache = self.signer_cache.read().unwrap();
            txs.iter().map(|tx| cache.get(tx.tx_hash()).copied()).collect()
        };
        let hits = lookup.iter().filter(|s| s.is_some()).count();
        let misses = n - hits;
        tracing::info!(
            target: "engine::signer_cache",
            hits,
            misses,
            total = n,
            "newPayload sender cache"
        );

        let senders: Vec<Address> = if misses == 0 {
            lookup.into_iter().map(Option::unwrap).collect()
        } else {
            let recovered: Result<Vec<(usize, Address)>, _> = txs
                .par_iter()
                .enumerate()
                .filter(|(i, _)| lookup[*i].is_none())
                .map(|(i, tx)| tx.recover_signer().map(|a| (i, a)))
                .collect();
            let recovered = recovered.map_err(NewPayloadError::other)?;
            let mut out: Vec<Address> = vec![Address::ZERO; n];
            for (i, addr) in lookup.iter().enumerate() {
                if let Some(a) = addr {
                    out[i] = *a;
                }
            }
            for (i, addr) in recovered {
                out[i] = addr;
            }
            // Write back so subsequent blocks can hit on these txs.
            let mut cache = self.signer_cache.write().unwrap();
            if cache.len().saturating_add(misses) > SIGNER_CACHE_CAP {
                tracing::warn!(
                    target: "engine::signer_cache",
                    size = cache.len(),
                    cap = SIGNER_CACHE_CAP,
                    "signer cache cap reached — clearing"
                );
                cache.clear();
            }
            for (tx, addr) in txs.iter().zip(out.iter()) {
                cache.insert(*tx.tx_hash(), *addr);
            }
            out
        };

        Ok(sealed_block.with_senders(senders))
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Types::ExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}
