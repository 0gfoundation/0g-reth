use super::{build_test_eth_api, estimation_env, sender, BLOCK_GAS_CAP};
use alloy_evm::overrides::apply_state_overrides;
use alloy_primitives::U256;
use alloy_rpc_types_eth::{state::StateOverride, TransactionRequest};
use reth_evm::TransactionEnv;
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_revm::database::StateProviderDatabase;
use reth_rpc_eth_api::helpers::{
    estimate::{EstimateCall, MaxUsedGasInspector},
    Call,
};
use revm::{
    context_interface::result::ExecutionResult, database::CacheDB, primitives::hardfork::SpecId,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Matrix {
    block_gas_cap: u64,
    chain_id: u64,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    fork: String,
    transaction: Value,
    #[serde(rename = "stateOverrides")]
    state_overrides: Value,
    gas_caps: Vec<Option<u64>>,
    expected_success: Vec<bool>,
}

/// Executes once and also returns the estimator's pre-settlement gas for the run,
/// so the matrix can compare it with geth's `MaxUsedGas`.
fn execute(
    api: &super::FakeEthApi,
    provider: &MockEthProvider,
    env: reth_evm::EvmEnv,
    request: TransactionRequest,
    overrides: StateOverride,
    limit: u64,
) -> Result<(ExecutionResult, Option<u64>), String> {
    let mut db = CacheDB::new(StateProviderDatabase::new(provider.clone()));
    apply_state_overrides(overrides, &mut db).map_err(|err| err.to_string())?;
    let mut tx = api.create_txn_env(&env, request, &mut db).map_err(|err| err.to_string())?;
    tx.set_gas_limit(limit);
    let mut inspector = MaxUsedGasInspector::default();
    let result = api
        .transact_with_inspector(db, env, tx, &mut inspector)
        .map(|out| out.result)
        .map_err(|err| err.to_string())?;
    Ok((result, inspector.max_used_gas()))
}

#[tokio::test]
async fn gas_alignment_matrix() {
    let matrix: Matrix =
        serde_json::from_str(include_str!("../../../../testdata/gas_alignment.json"))
            .expect("canonical gas alignment fixture");
    assert_eq!(matrix.block_gas_cap, BLOCK_GAS_CAP);
    assert_eq!(matrix.chain_id, 16661);
    assert!(matrix.cases.len() >= 16);
    assert!(matrix.cases.iter().map(|case| case.gas_caps.len()).sum::<usize>() >= 60);

    for case in &matrix.cases {
        assert_eq!(case.gas_caps.len(), case.expected_success.len(), "{}", case.name);
        let provider = MockEthProvider::default();
        provider.add_account(
            sender(),
            ExtendedAccount::new(0, U256::from(1_000_000_000_000_000_000u64)),
        );
        let api = build_test_eth_api(provider.clone());
        let mut env = estimation_env(&provider, matrix.block_gas_cap);
        env.cfg_env.chain_id = matrix.chain_id;
        // Match geth's matrix header time. The deployed revm charges the 80% floor
        // unconditionally; geth skips it before Prague, so Cancun rows differ on purpose.
        env.block_env.timestamp = U256::from(1);
        env.cfg_env.spec = match case.fork.as_str() {
            "Prague" => SpecId::PRAGUE,
            "Cancun" => SpecId::CANCUN,
            other => panic!("unsupported fixture fork {other}"),
        };
        let overrides: StateOverride = serde_json::from_value(case.state_overrides.clone())
            .unwrap_or_else(|err| panic!("{} overrides: {err}", case.name));

        for (&cap, &expected_success) in case.gas_caps.iter().zip(&case.expected_success) {
            let mut request: TransactionRequest = serde_json::from_value(case.transaction.clone())
                .unwrap_or_else(|err| panic!("{} transaction: {err}", case.name));
            request.gas = cap;
            let probe_limit = cap.unwrap_or(matrix.block_gas_cap).min(matrix.block_gas_cap);
            let probe = execute(
                &api,
                &provider,
                env.clone(),
                request.clone(),
                overrides.clone(),
                probe_limit,
            );
            let (charged_gas, max_used_gas, probe_success, probe_error) = match probe {
                Ok((result, max_used_gas)) => (
                    Some(result.gas_used()),
                    max_used_gas,
                    result.is_success(),
                    if result.is_success() { None } else { Some(format!("{result:?}")) },
                ),
                Err(err) => (None, None, false, Some(err)),
            };
            let estimate_result = EstimateCall::estimate_gas_with(
                &api,
                env.clone(),
                request.clone(),
                provider.clone(),
                Some(overrides.clone()),
            );
            let (estimate, error) = match estimate_result {
                Ok(gas) => (Some(gas.saturating_to::<u64>()), None),
                Err(err) => (None, Some(err.to_string())),
            };
            let (replay_success, replay_error) = if let Some(limit) = estimate {
                match execute(&api, &provider, env.clone(), request, overrides.clone(), limit) {
                    Ok((result, _)) => (
                        Some(result.is_success()),
                        if result.is_success() { None } else { Some(format!("{result:?}")) },
                    ),
                    Err(err) => (Some(false), Some(err)),
                }
            } else {
                (None, None)
            };
            println!(
                "GAS_ALIGNMENT {}",
                json!({
                    "source": "reth", "case": case.name, "fork": case.fork, "cap": cap,
                    "probe_limit": probe_limit, "charged_gas": charged_gas,
                    "max_used_gas": max_used_gas, "probe_success": probe_success,
                    "probe_error": probe_error, "estimate": estimate, "error": error,
                    "replay_success": replay_success, "replay_error": replay_error,
                })
            );
            assert_eq!(
                estimate.is_some(),
                expected_success,
                "{} cap {cap:?}: {error:?}",
                case.name
            );
            if expected_success {
                assert_eq!(
                    replay_success,
                    Some(true),
                    "{} cap {cap:?}: {replay_error:?}",
                    case.name
                );
            }
        }
    }
}
