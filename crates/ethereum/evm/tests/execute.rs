//! Execution tests.

use alloy_consensus::{constants::ETH_TO_WEI, Header, TxLegacy};
use alloy_eips::{
    eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE},
    eip4788::{BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE, SYSTEM_ADDRESS},
    eip4895::Withdrawal,
    eip7002::{WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_CODE},
    eip7685::EMPTY_REQUESTS_HASH,
};
use alloy_evm::block::BlockValidationError;
use alloy_primitives::{b256, fixed_bytes, keccak256, Bytes, TxKind, B256, U256};
use reth_chainspec::{ChainSpecBuilder, EthereumHardfork, ForkCondition, MAINNET};
use reth_ethereum_primitives::{Block, BlockBody, Transaction};
use reth_evm::{
    execute::{BasicBlockExecutor, Executor},
    ConfigureEvm,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{
    crypto::secp256k1::public_key_to_address, Block as _, RecoveredBlock,
};
use reth_testing_utils::generators::{self, sign_tx_with_key_pair};
use revm::{
    database::{CacheDB, EmptyDB, TransitionState},
    primitives::address,
    state::{AccountInfo, Bytecode, EvmState},
    Database,
};
use std::sync::{mpsc, Arc};

fn create_database_with_beacon_root_contract() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(Default::default());

    let beacon_root_contract_account = AccountInfo {
        balance: U256::ZERO,
        code_hash: keccak256(BEACON_ROOTS_CODE.clone()),
        nonce: 1,
        code: Some(Bytecode::new_raw(BEACON_ROOTS_CODE.clone())),
    };

    db.insert_account_info(BEACON_ROOTS_ADDRESS, beacon_root_contract_account);

    db
}

fn create_database_with_withdrawal_requests_contract() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(Default::default());

    let withdrawal_requests_contract_account = AccountInfo {
        nonce: 1,
        balance: U256::ZERO,
        code_hash: keccak256(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone()),
        code: Some(Bytecode::new_raw(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone())),
    };

    db.insert_account_info(
        WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        withdrawal_requests_contract_account,
    );

    db
}

#[test]
fn eip_4788_non_genesis_call() {
    let mut header =
        Header { timestamp: 1, number: 1, excess_blob_gas: Some(0), ..Header::default() };

    let db = create_database_with_beacon_root_contract();

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);

    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute a block without parent beacon block root, expect err
    let err = executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block {
                header: header.clone(),
                body: BlockBody { transactions: vec![], ommers: vec![], withdrawals: None },
            },
            vec![],
        ))
        .expect_err("Executing cancun block without parent beacon block root field should fail");

    assert!(matches!(
        err.as_validation().unwrap(),
        BlockValidationError::MissingParentBeaconBlockRoot
    ));

    // fix header, set a gas limit
    header.parent_beacon_block_root = Some(B256::with_last_byte(0x69));

    // Now execute a block with the fixed header, ensure that it does not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block {
                header: header.clone(),
                body: BlockBody { transactions: vec![], ommers: vec![], withdrawals: None },
            },
            vec![],
        ))
        .unwrap();

    // check the actual storage of the contract - it should be:
    // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH should be
    // header.timestamp
    // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH //
    //   should be parent_beacon_block_root
    let history_buffer_length = 8191u64;
    let timestamp_index = header.timestamp % history_buffer_length;
    let parent_beacon_block_root_index =
        timestamp_index % history_buffer_length + history_buffer_length;

    let timestamp_storage = executor.with_state_mut(|state| {
        state.storage(BEACON_ROOTS_ADDRESS, U256::from(timestamp_index)).unwrap()
    });
    assert_eq!(timestamp_storage, U256::from(header.timestamp));

    // get parent beacon block root storage and compare
    let parent_beacon_block_root_storage = executor.with_state_mut(|state| {
        state
            .storage(BEACON_ROOTS_ADDRESS, U256::from(parent_beacon_block_root_index))
            .expect("storage value should exist")
    });
    assert_eq!(parent_beacon_block_root_storage, U256::from(0x69));
}

#[test]
fn eip_4788_no_code_cancun() {
    // This test ensures that we "silently fail" when cancun is active and there is no code at
    // // BEACON_ROOTS_ADDRESS
    let header = Header {
        timestamp: 1,
        number: 1,
        parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
        excess_blob_gas: Some(0),
        ..Header::default()
    };

    let db = CacheDB::new(EmptyDB::default());

    // DON'T deploy the contract at genesis
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);

    // attempt to execute an empty block with parent beacon block root, this should not fail
    provider
        .batch_executor(db)
        .execute_one(&RecoveredBlock::new_unhashed(
            Block {
                header,
                body: BlockBody { transactions: vec![], ommers: vec![], withdrawals: None },
            },
            vec![],
        ))
        .expect("Executing a block with no transactions while cancun is active should not fail");
}

#[test]
fn eip_4788_empty_account_call() {
    // This test ensures that we do not increment the nonce of an empty SYSTEM_ADDRESS account
    // // during the pre-block call

    let mut db = create_database_with_beacon_root_contract();

    // insert an empty SYSTEM_ADDRESS
    db.insert_account_info(SYSTEM_ADDRESS, Default::default());

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);

    // construct the header for block one
    let header = Header {
        timestamp: 1,
        number: 1,
        parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
        excess_blob_gas: Some(0),
        ..Header::default()
    };

    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute an empty block with parent beacon block root, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block {
                header,
                body: BlockBody { transactions: vec![], ommers: vec![], withdrawals: None },
            },
            vec![],
        ))
        .expect("Executing a block with no transactions while cancun is active should not fail");

    // ensure that the nonce of the system address account has not changed
    let nonce =
        executor.with_state_mut(|state| state.basic(SYSTEM_ADDRESS).unwrap().unwrap().nonce);
    assert_eq!(nonce, 0);
}

#[test]
fn eip_4788_genesis_call() {
    let db = create_database_with_beacon_root_contract();

    // activate cancun at genesis
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(0))
            .build(),
    );

    let mut header = chain_spec.genesis_header().clone();
    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute the genesis block with non-zero parent beacon block root, expect err
    header.parent_beacon_block_root = Some(B256::with_last_byte(0x69));
    let _err = executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header: header.clone(), body: Default::default() },
            vec![],
        ))
        .expect_err(
            "Executing genesis cancun block with non-zero parent beacon block root field
    should fail",
        );

    // fix header
    header.parent_beacon_block_root = Some(B256::ZERO);

    // now try to process the genesis block again, this time ensuring that a system contract
    // call does not occur
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .unwrap();

    // there is no system contract call so there should be NO STORAGE CHANGES
    // this means we'll check the transition state
    let transition_state = executor.with_state_mut(|state| {
        state.transition_state.take().expect("the evm should be initialized with bundle updates")
    });

    // assert that it is the default (empty) transition state
    assert_eq!(transition_state, TransitionState::default());
}

#[test]
fn eip_4788_high_base_fee() {
    // This test ensures that if we have a base fee, then we don't return an error when the
    // system contract is called, due to the gas price being less than the base fee.
    let header = Header {
        timestamp: 1,
        number: 1,
        parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
        base_fee_per_gas: Some(u64::MAX),
        excess_blob_gas: Some(0),
        ..Header::default()
    };

    let db = create_database_with_beacon_root_contract();

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);

    // execute header
    let mut executor = BasicBlockExecutor::new(provider, db);

    // Now execute a block with the fixed header, ensure that it does not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header: header.clone(), body: Default::default() },
            vec![],
        ))
        .unwrap();

    // check the actual storage of the contract - it should be:
    // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH should be
    // header.timestamp
    // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH //
    //   should be parent_beacon_block_root
    let history_buffer_length = 8191u64;
    let timestamp_index = header.timestamp % history_buffer_length;
    let parent_beacon_block_root_index =
        timestamp_index % history_buffer_length + history_buffer_length;

    // get timestamp storage and compare
    let timestamp_storage = executor.with_state_mut(|state| {
        state.storage(BEACON_ROOTS_ADDRESS, U256::from(timestamp_index)).unwrap()
    });
    assert_eq!(timestamp_storage, U256::from(header.timestamp));

    // get parent beacon block root storage and compare
    let parent_beacon_block_root_storage = executor.with_state_mut(|state| {
        state.storage(BEACON_ROOTS_ADDRESS, U256::from(parent_beacon_block_root_index)).unwrap()
    });
    assert_eq!(parent_beacon_block_root_storage, U256::from(0x69));
}

/// Create a state provider with blockhashes and the EIP-2935 system contract.
fn create_database_with_block_hashes(latest_block: u64) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(Default::default());
    for block_number in 0..=latest_block {
        db.cache.block_hashes.insert(U256::from(block_number), keccak256(block_number.to_string()));
    }

    let blockhashes_contract_account = AccountInfo {
        balance: U256::ZERO,
        code_hash: keccak256(HISTORY_STORAGE_CODE.clone()),
        code: Some(Bytecode::new_raw(HISTORY_STORAGE_CODE.clone())),
        nonce: 1,
    };

    db.insert_account_info(HISTORY_STORAGE_ADDRESS, blockhashes_contract_account);

    db
}
#[test]
fn eip_2935_pre_fork() {
    let db = create_database_with_block_hashes(1);

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Prague, ForkCondition::Never)
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    // construct the header for block one
    let header = Header { timestamp: 1, number: 1, ..Header::default() };

    // attempt to execute an empty block, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // ensure that the block hash was *not* written to storage, since this is before the fork
    // was activated
    //
    // we load the account first, because revm expects it to be
    // loaded
    executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap());
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap().is_zero()
    }));
}

#[test]
fn eip_2935_fork_activation_genesis() {
    let db = create_database_with_block_hashes(0);

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build(),
    );

    let header = chain_spec.genesis_header().clone();
    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute genesis block, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // ensure that the block hash was *not* written to storage, since there are no blocks
    // preceding genesis
    //
    // we load the account first, because revm expects it to be
    // loaded
    executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap());
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap().is_zero()
    }));
}

#[test]
fn eip_2935_fork_activation_within_window_bounds() {
    let fork_activation_block = (HISTORY_SERVE_WINDOW - 10) as u64;
    let db = create_database_with_block_hashes(fork_activation_block);

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(1))
            .build(),
    );

    let header = Header {
        parent_hash: B256::random(),
        timestamp: 1,
        number: fork_activation_block,
        requests_hash: Some(EMPTY_REQUESTS_HASH),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        ..Header::default()
    };
    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute the fork activation block, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // the hash for the ancestor of the fork activation block should be present
    assert!(
        executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some())
    );
    assert_ne!(
        executor.with_state_mut(|state| state
            .storage(HISTORY_STORAGE_ADDRESS, U256::from(fork_activation_block - 1))
            .unwrap()),
        U256::ZERO
    );

    // the hash of the block itself should not be in storage
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::from(fork_activation_block)).unwrap().is_zero()
    }));
}

// <https://github.com/ethereum/EIPs/pull/9144>
#[test]
fn eip_2935_fork_activation_outside_window_bounds() {
    let fork_activation_block = (HISTORY_SERVE_WINDOW + 256) as u64;
    let db = create_database_with_block_hashes(fork_activation_block);

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(1))
            .build(),
    );

    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    let header = Header {
        parent_hash: B256::random(),
        timestamp: 1,
        number: fork_activation_block,
        requests_hash: Some(EMPTY_REQUESTS_HASH),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        ..Header::default()
    };

    // attempt to execute the fork activation block, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // the hash for the ancestor of the fork activation block should be present
    assert!(
        executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some())
    );
}

#[test]
fn eip_2935_state_transition_inside_fork() {
    let db = create_database_with_block_hashes(2);

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build(),
    );

    let header = chain_spec.genesis_header().clone();
    let header_hash = header.hash_slow();

    let provider = EthEvmConfig::new(chain_spec);
    let mut executor = BasicBlockExecutor::new(provider, db);

    // attempt to execute the genesis block, this should not fail
    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // nothing should be written as the genesis has no ancestors
    //
    // we load the account first, because revm expects it to be
    // loaded
    executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap());
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap().is_zero()
    }));

    // attempt to execute block 1, this should not fail
    let header = Header {
        parent_hash: header_hash,
        timestamp: 1,
        number: 1,
        requests_hash: Some(EMPTY_REQUESTS_HASH),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        ..Header::default()
    };
    let header_hash = header.hash_slow();

    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // the block hash of genesis should now be in storage, but not block 1
    assert!(
        executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some())
    );
    assert_ne!(
        executor
            .with_state_mut(|state| state.storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap()),
        U256::ZERO
    );
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::from(1)).unwrap().is_zero()
    }));

    // attempt to execute block 2, this should not fail
    let header = Header {
        parent_hash: header_hash,
        timestamp: 1,
        number: 2,
        requests_hash: Some(EMPTY_REQUESTS_HASH),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        ..Header::default()
    };

    executor
        .execute_one(&RecoveredBlock::new_unhashed(
            Block { header, body: Default::default() },
            vec![],
        ))
        .expect("Executing a block with no transactions while Prague is active should not fail");

    // the block hash of genesis and block 1 should now be in storage, but not block 2
    assert!(
        executor.with_state_mut(|state| state.basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some())
    );
    assert_ne!(
        executor
            .with_state_mut(|state| state.storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap()),
        U256::ZERO
    );
    assert_ne!(
        executor
            .with_state_mut(|state| state.storage(HISTORY_STORAGE_ADDRESS, U256::from(1)).unwrap()),
        U256::ZERO
    );
    assert!(executor.with_state_mut(|state| {
        state.storage(HISTORY_STORAGE_ADDRESS, U256::from(2)).unwrap().is_zero()
    }));
}

#[test]
fn eip_7002() {
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build(),
    );

    let mut db = create_database_with_withdrawal_requests_contract();

    let sender_key_pair = generators::generate_key(&mut generators::rng());
    let sender_address = public_key_to_address(sender_key_pair.public_key());

    db.insert_account_info(
        sender_address,
        AccountInfo { nonce: 1, balance: U256::from(ETH_TO_WEI), ..Default::default() },
    );

    // https://github.com/lightclient/sys-asm/blob/9282bdb9fd64e024e27f60f507486ffb2183cba2/test/Withdrawal.t.sol.in#L36
    let validator_public_key = fixed_bytes!(
            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        );
    let withdrawal_amount = fixed_bytes!("0203040506070809");
    let input: Bytes = [&validator_public_key[..], &withdrawal_amount[..]].concat().into();
    assert_eq!(input.len(), 56);

    let mut header = chain_spec.genesis_header().clone();
    header.gas_limit = 1_500_000;
    // measured
    header.gas_used = 135_856;
    header.receipts_root =
        b256!("0xb31a3e47b902e9211c4d349af4e4c5604ce388471e79ca008907ae4616bb0ed3");

    let tx = sign_tx_with_key_pair(
        sender_key_pair,
        Transaction::Legacy(TxLegacy {
            chain_id: Some(chain_spec.chain.id()),
            nonce: 1,
            gas_price: header.base_fee_per_gas.unwrap().into(),
            gas_limit: header.gas_used,
            to: TxKind::Call(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS),
            // `MIN_WITHDRAWAL_REQUEST_FEE`
            value: U256::from(2),
            input,
        }),
    );

    let provider = EthEvmConfig::new(chain_spec);

    let mut executor = provider.batch_executor(db);

    let BlockExecutionResult { receipts, requests, .. } = executor
        .execute_one(
            &Block { header, body: BlockBody { transactions: vec![tx], ..Default::default() } }
                .try_into_recovered()
                .unwrap(),
        )
        .unwrap();

    let receipt = receipts.first().unwrap();
    assert!(receipt.success);

    // There should be exactly one entry with withdrawal requests
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0][0], 1);
}

#[test]
fn block_gas_limit_error() {
    // Create a chain specification with fork conditions set for Prague
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
            .build(),
    );

    // Create a state provider with the withdrawal requests contract pre-deployed
    let mut db = create_database_with_withdrawal_requests_contract();

    // Generate a new key pair for the sender
    let sender_key_pair = generators::generate_key(&mut generators::rng());
    // Get the sender's address from the public key
    let sender_address = public_key_to_address(sender_key_pair.public_key());

    // Insert the sender account into the state with a nonce of 1 and a balance of 1 ETH in Wei
    db.insert_account_info(
        sender_address,
        AccountInfo { nonce: 1, balance: U256::from(ETH_TO_WEI), ..Default::default() },
    );

    // Define the validator public key and withdrawal amount as fixed bytes
    let validator_public_key = fixed_bytes!(
            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        );
    let withdrawal_amount = fixed_bytes!("2222222222222222");
    // Concatenate the validator public key and withdrawal amount into a single byte array
    let input: Bytes = [&validator_public_key[..], &withdrawal_amount[..]].concat().into();
    // Ensure the input length is 56 bytes
    assert_eq!(input.len(), 56);

    // Create a genesis block header with a specified gas limit and gas used
    let mut header = chain_spec.genesis_header().clone();
    header.gas_limit = 1_500_000;
    header.gas_used = 134_807;
    header.receipts_root =
        b256!("0xb31a3e47b902e9211c4d349af4e4c5604ce388471e79ca008907ae4616bb0ed3");

    // Create a transaction with a gas limit higher than the block gas limit
    let tx = sign_tx_with_key_pair(
        sender_key_pair,
        Transaction::Legacy(TxLegacy {
            chain_id: Some(chain_spec.chain.id()),
            nonce: 1,
            gas_price: header.base_fee_per_gas.unwrap().into(),
            gas_limit: 2_500_000, // higher than block gas limit
            to: TxKind::Call(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS),
            value: U256::from(1),
            input,
        }),
    );

    // Create an executor from the state provider
    let evm_config = EthEvmConfig::new(chain_spec);
    let mut executor = evm_config.batch_executor(db);

    // Execute the block and capture the result
    let exec_result = executor.execute_one(
        &Block { header, body: BlockBody { transactions: vec![tx], ..Default::default() } }
            .try_into_recovered()
            .unwrap(),
    );

    // Check if the execution result is an error and assert the specific error type
    match exec_result {
        Ok(_) => panic!("Expected block gas limit error"),
        Err(err) => assert!(matches!(
            *err.as_validation().unwrap(),
            BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                transaction_gas_limit: 2_500_000,
                block_available_gas: 1_500_000,
            }
        )),
    }
}

#[test]
fn test_balance_increment_not_duplicated() {
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build(),
    );

    let withdrawal_recipient = address!("0x1000000000000000000000000000000000000000");

    let mut db = CacheDB::new(EmptyDB::default());
    let initial_balance = 100;
    db.insert_account_info(
        withdrawal_recipient,
        AccountInfo { balance: U256::from(initial_balance), nonce: 1, ..Default::default() },
    );

    let withdrawal =
        Withdrawal { index: 0, validator_index: 0, address: withdrawal_recipient, amount: 1 };

    let header = Header {
        timestamp: 1,
        number: 1,
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        ..Header::default()
    };

    let block = &RecoveredBlock::new_unhashed(
        Block {
            header,
            body: BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(vec![withdrawal].into()),
            },
        },
        vec![],
    );

    let provider = EthEvmConfig::new(chain_spec);
    let executor = provider.batch_executor(db);

    let (tx, rx) = mpsc::channel();
    let tx_clone = tx.clone();

    let _output = executor
        .execute_with_state_hook(block, move |_, state: &EvmState| {
            if let Some(account) = state.get(&withdrawal_recipient) {
                let _ = tx_clone.send(account.info.balance);
            }
        })
        .expect("Block execution should succeed");

    drop(tx);
    let balance_changes: Vec<U256> = rx.try_iter().collect();

    if let Some(final_balance) = balance_changes.last() {
        let expected_final_balance = U256::from(initial_balance) + U256::from(1_000_000_000); // initial + 1 Gwei in Wei
        assert_eq!(
            *final_balance, expected_final_balance,
            "Final balance should match expected value after withdrawal"
        );
    }
}

mod bridge_tests {
    //! 0G bridge system call integration tests. Verifies that:
    //!
    //! 1. With a configured `bridge_contract_address`, a `bridge_activation_time` already in the
    //!    past, and a `bridge_request` calldata blob attached to the execution context,
    //!    `EthBlockExecutor::finish` issues a `transact_system_call` to the bridge address.
    //! 2. The system call passes the calldata through verbatim (we observe it via a stub contract
    //!    that copies calldata into storage).
    //! 3. With the bridge fork inactive, the system call is suppressed even when calldata is
    //!    attached.
    //!
    //! Deeper end-to-end coverage (full engine API + payload validation) belongs in
    //! `crates/ethereum/node/tests/it/`; this file stays at the executor boundary.
    use super::*;
    use alloy_consensus::Header;
    use alloy_eips::eip4895::Withdrawals;
    use alloy_evm::eth::EthBlockExecutionCtx;
    use alloy_primitives::{address, Address, Bytes, U256};
    use reth_chainspec::ChainSpec;
    use reth_evm::{
        execute::{BlockExecutor, BlockExecutorFactory},
        ConfigureEvm,
    };
    use revm::{
        database::{CacheDB, EmptyDB, State},
        primitives::HashMap,
        state::{AccountInfo, Bytecode},
    };
    use std::{borrow::Cow, sync::Arc};

    // Must match `reth_chainspec::BRIDGE_PROXY_ADDRESS`: the bridge_contract_address() impl on
    // ChainSpec returns that compile-time constant whenever the bridge fork is active, so the
    // stub bytecode this test plants has to live at the same slot.
    const BRIDGE_ADDR: Address = address!("0x54EbF70B91fe29fdF6F5C6cF726983DDF0DE0750");

    /// Returns the runtime bytecode of a tiny stub contract that, on any call:
    ///   * Copies the first 32 bytes of calldata into storage slot 0
    ///   * Stores `calldatasize()` into storage slot 1
    ///   * Returns nothing
    ///
    /// This lets the test observe whether the system call fired (slot 0 != 0) and that the
    /// calldata pass-through was complete (slot 1 == ABI calldata length).
    ///
    /// Bytecode (hand-assembled, 13 bytes):
    ///   PUSH1 0x00 CALLDATALOAD       // [data0]
    ///   PUSH1 0x00 SSTORE              // store at slot 0
    ///   CALLDATASIZE                   // [size]
    ///   PUSH1 0x01 SSTORE              // store at slot 1
    ///   STOP
    fn stub_bridge_bytecode() -> Bytes {
        Bytes::from_static(&[
            0x60, 0x00, // PUSH1 0
            0x35, // CALLDATALOAD
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (slot 0 <- first 32 bytes of calldata)
            0x36, // CALLDATASIZE
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (slot 1 <- calldatasize)
            0x00, // STOP
        ])
    }

    fn build_chain_spec(bridge_active: bool) -> Arc<ChainSpec> {
        // Start from a Prague-activated mainnet builder, then explicitly set the bridge
        // fields. We can't go through the builder for these (no public setter), so we
        // mutate the resulting spec post-build.
        let inner = ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build();
        // The builder returns a struct we can clone-and-mutate. `bridge_contract_address()`
        // is derived from `bridge_activation_time`: > 0 returns BRIDGE_PROXY_ADDRESS,
        // 0 returns None. So toggling activation alone covers both branches.
        let mut spec = inner;
        spec.bridge_activation_time = if bridge_active { 1 } else { 0 };
        Arc::new(spec)
    }

    fn database_with_bridge_stub() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        let code = Bytecode::new_raw(stub_bridge_bytecode());
        db.insert_account_info(
            BRIDGE_ADDR,
            AccountInfo {
                nonce: 1,
                balance: U256::ZERO,
                code_hash: keccak256(stub_bridge_bytecode()),
                code: Some(code),
            },
        );
        db
    }

    /// Drives a single empty block through the executor with the supplied bridge context.
    /// Returns the final state of the bridge contract's storage slots 0 and 1.
    fn run_with_bridge_ctx(spec: Arc<ChainSpec>, bridge_calldata: Option<Bytes>) -> (U256, U256) {
        let provider = EthEvmConfig::new(spec.clone());

        // Empty block, post-Prague.
        let header = Header {
            timestamp: 100,
            number: 1,
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..Header::default()
        };

        let db = database_with_bridge_stub();
        let mut state = State::builder().with_database(db).with_bundle_update().build();

        let evm = provider.evm_for_block(&mut state, &header);
        let ctx = EthBlockExecutionCtx {
            parent_hash: header.parent_hash,
            parent_beacon_block_root: header.parent_beacon_block_root,
            ommers: &[],
            withdrawals: Some(Cow::Owned(Withdrawals::new(vec![]))),
            timestamp: header.timestamp,
            bridge_request: bridge_calldata.map(Cow::Owned),
            // This test exercises only the bridge system call's storage side-effects, not the
            // returned `requests` list. `None` here keeps the test focused; the 0xf0 push path
            // is exercised by `finish_appends_0xf0_entry_when_raw_attached` and
            // `finish_appends_0xf0_after_pectra_types` below (same module), which assert the
            // `requests` list returned by `finish()` ends with `0xf0 || raw_bytes`.
            bridge_request_raw: None,
        };

        let executor = provider.block_executor_factory().create_executor(evm, ctx);

        // No transactions; just exercise pre/post-execution hooks.
        let mut executor = executor;
        BlockExecutor::apply_pre_execution_changes(&mut executor)
            .expect("pre-execution should succeed");
        let _ = BlockExecutor::finish(executor).expect("finish should succeed");

        // Read slots 0 and 1 from the persisted bridge contract storage. Pre-load the
        // account so `storage()` doesn't trip its "must be loaded first" assertion on the
        // skip paths where the system call never touched it.
        let _ =
            state.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);
        let _ = state.basic(BRIDGE_ADDR);
        let slot0 = state.storage(BRIDGE_ADDR, U256::ZERO).unwrap_or_default();
        let slot1 = state.storage(BRIDGE_ADDR, U256::from(1u64)).unwrap_or_default();
        (slot0, slot1)
    }

    #[test]
    fn bridge_call_fires_when_active_with_calldata() {
        let spec = build_chain_spec(true);
        // Calldata: 32 bytes of 0xAB followed by a 4-byte tail. Slot 0 should hold
        // 0xAB.. (first 32 bytes); slot 1 should hold 36.
        let mut cd: Vec<u8> = vec![0xAB; 32];
        cd.extend_from_slice(&[1, 2, 3, 4]);
        let cd_len = cd.len();
        let (slot0, slot1) = run_with_bridge_ctx(spec, Some(Bytes::from(cd)));

        assert_eq!(
            slot0,
            U256::from_be_bytes::<32>([0xAB; 32]),
            "stub should have stored the first 32 bytes of calldata"
        );
        assert_eq!(slot1, U256::from(cd_len as u64), "stub should record calldata length");
    }

    #[test]
    fn bridge_call_skipped_when_fork_inactive() {
        let spec = build_chain_spec(false); // bridge_activation_time = 0 -> always inactive
        let cd = vec![0xCD; 64];
        let (slot0, slot1) = run_with_bridge_ctx(spec, Some(Bytes::from(cd)));
        assert_eq!(slot0, U256::ZERO, "fork inactive: no system call");
        assert_eq!(slot1, U256::ZERO, "fork inactive: no system call");
    }

    #[test]
    fn bridge_call_skipped_when_no_calldata_attached() {
        let spec = build_chain_spec(true); // active
        let (slot0, slot1) = run_with_bridge_ctx(spec, None);
        assert_eq!(slot0, U256::ZERO, "no calldata: no system call");
        assert_eq!(slot1, U256::ZERO, "no calldata: no system call");
    }

    #[test]
    fn bridge_calldata_is_passed_through_verbatim() {
        // Build real ABI calldata via the bridge crate and verify the stub sees the same
        // selector + payload.
        use reth_0g_bridge::{encode_execute_remote_messages_calldata, BridgeMessage};

        let spec = build_chain_spec(true);
        let local_chain_id = spec.chain.id();
        let msg = BridgeMessage {
            src_chain_id: 16700,
            dst_chain_id: local_chain_id,
            nonce: 1,
            local_token: alloy_primitives::FixedBytes([0x11; 20]),
            recipient: alloy_primitives::FixedBytes([0x22; 20]),
            amount: alloy_primitives::FixedBytes(U256::from(42u64).to_be_bytes::<32>()),
            mode: 1,
            src_block: 7,
        };
        let fee_recipient = address!("0x00000000000000000000000000000000000000Fe");
        let cd = encode_execute_remote_messages_calldata(&[msg], local_chain_id, fee_recipient);
        let expected_first_word = U256::from_be_bytes::<32>(
            // ABI calldata starts with 4-byte selector + zero-padded args. The first 32
            // bytes are the 4-byte selector left-aligned, padded with the head of the
            // args tuple-encoding.
            cd[..32].try_into().unwrap(),
        );
        let (slot0, _slot1) = run_with_bridge_ctx(spec, Some(cd));
        assert_eq!(
            slot0, expected_first_word,
            "bridge calldata first 32 bytes must match what we encoded"
        );
    }

    /// Runs an empty post-Prague block through the executor and returns
    /// `BlockExecutionResult.requests` so callers can assert on the EIP-7685 entries
    /// `EthBlockExecutor::finish` produced.
    ///
    /// Distinct from [`run_with_bridge_ctx`] which only inspects bridge-contract storage. These
    /// tests target the `0xf0` entry append path introduced to fix the block-hash mismatch
    /// where the sealed `requests_hash` excluded `0xf0` while the wire response included it.
    fn finish_requests_with_raw(
        spec: Arc<ChainSpec>,
        bridge_calldata: Option<Bytes>,
        bridge_request_raw: Option<Bytes>,
    ) -> alloy_eips::eip7685::Requests {
        let provider = EthEvmConfig::new(spec.clone());
        let header = Header {
            timestamp: 100,
            number: 1,
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..Header::default()
        };
        let db = database_with_bridge_stub();
        let mut state = State::builder().with_database(db).with_bundle_update().build();
        let evm = provider.evm_for_block(&mut state, &header);
        let ctx = EthBlockExecutionCtx {
            parent_hash: header.parent_hash,
            parent_beacon_block_root: header.parent_beacon_block_root,
            ommers: &[],
            withdrawals: Some(Cow::Owned(Withdrawals::new(vec![]))),
            timestamp: header.timestamp,
            bridge_request: bridge_calldata.map(Cow::Owned),
            bridge_request_raw: bridge_request_raw.map(Cow::Owned),
        };
        let mut executor = provider.block_executor_factory().create_executor(evm, ctx);
        BlockExecutor::apply_pre_execution_changes(&mut executor)
            .expect("pre-execution should succeed");
        let (_evm, result) = BlockExecutor::finish(executor).expect("finish should succeed");
        result.requests
    }

    #[test]
    fn finish_appends_0xf0_entry_when_raw_attached() {
        // Prague active + bridge_request_raw=Some(bytes) → returned `requests` must end with
        // `0xf0 || bytes`. This is the build-path invariant: `EthBlockAssembler` consumes the
        // `requests` returned by `finish()` to compute `requests_hash` for the sealed block
        // header. The 0xf0 entry must be present in that list so the proposer-built
        // `block.block_hash` covers it and matches what the CL reconstructs from the same
        // wire bytes.
        let spec = build_chain_spec(true);
        let raw = Bytes::from_static(&[0x04, 0x00, 0x00, 0x00]); // SSZ empty-list sentinel (4 bytes)
        let requests = finish_requests_with_raw(spec, None, Some(raw.clone()));
        let entries: Vec<&[u8]> = requests.iter().map(|b| b.as_ref()).collect();
        assert!(
            entries.iter().any(|e| e.first() == Some(&0xf0) && &e[1..] == raw.as_ref()),
            "post-Prague + bridge_request_raw=Some must produce 0xf0||bytes entry; got {:?}",
            entries
        );
    }

    #[test]
    fn finish_omits_0xf0_entry_when_raw_none() {
        // Prague active but bridge_request_raw=None → no 0xf0 entry emitted. This is the replay
        // path (`context_for_block` always sets None) and any pre-Bridge-fork scenario.
        let spec = build_chain_spec(true);
        let requests = finish_requests_with_raw(spec, None, None);
        let entries: Vec<&[u8]> = requests.iter().map(|b| b.as_ref()).collect();
        assert!(
            entries.iter().all(|e| e.first() != Some(&0xf0)),
            "bridge_request_raw=None must NOT push 0xf0 entry; got {:?}",
            entries
        );
    }

    /// Regression-locks the 2026-04-29 slot-1 halt invariant: the sealed block header's
    /// `requests_hash` must cover the `0xf0` entry whenever the bridge fork is active.
    ///
    /// `EthBlockAssembler::assemble_block` (`build.rs`) computes the header's `requests_hash`
    /// from `output.requests.requests_hash()` directly — no filtering, no transformation. The
    /// existing `finish_*` tests prove `EthBlockExecutor::finish` puts `0xf0||raw` into
    /// `output.requests`. The gap this test closes is: if a refactor accidentally builds the
    /// `Requests` list without `0xf0` (or strips it), would the resulting `requests_hash`
    /// silently match the (no-0xf0) hash and let a corrupt block pass validation?
    ///
    /// Answer is no, because `requests_hash()` is order-and-content-sensitive. This test pins
    /// that property explicitly: building a multi-type `Requests` with all four EIP-7685 types
    /// (`0x00` / `0x01` / `0x02` / `0xf0` in ascending order) yields a hash that differs from
    /// the same list with `0xf0` stripped. Combined with `finish_emits_0xf0_*` (which proves
    /// `0xf0` ends up in `output.requests`) and the assembler's direct call to
    /// `requests.requests_hash()` (single-line invariant visible in code review), this locks
    /// the end-to-end chain: `finish() → output.requests → requests_hash() → header.requests_hash`.
    #[test]
    fn requests_hash_is_sensitive_to_0xf0_entry() {
        use alloy_eips::eip7685::Requests;

        let mut with_0xf0 = Requests::default();
        with_0xf0.push_request_with_type(0x00, vec![0xDE, 0xAD]);
        with_0xf0.push_request_with_type(0x01, vec![0xBE, 0xEF]);
        with_0xf0.push_request_with_type(0x02, vec![0xCA, 0xFE]);
        with_0xf0.push_request_with_type(0xf0, vec![0x04, 0x00, 0x00, 0x00]);

        // Lock the EIP-7685 ordering invariant on a multi-type list (the empty-block fixture in
        // `finish_emits_0xf0_as_last_entry_in_single_request_block` can only verify single-entry
        // ordering trivially).
        let type_bytes: Vec<u8> =
            with_0xf0.iter().map(|e| e.first().copied().expect("non-empty entry")).collect();
        assert_eq!(
            type_bytes,
            vec![0x00, 0x01, 0x02, 0xf0],
            "EIP-7685 type bytes must be strictly ascending; 0xf0 strictly after 0x00/0x01/0x02"
        );

        let mut without_0xf0 = Requests::default();
        without_0xf0.push_request_with_type(0x00, vec![0xDE, 0xAD]);
        without_0xf0.push_request_with_type(0x01, vec![0xBE, 0xEF]);
        without_0xf0.push_request_with_type(0x02, vec![0xCA, 0xFE]);

        assert_ne!(
            with_0xf0.requests_hash(),
            without_0xf0.requests_hash(),
            "0xf0 must contribute to requests_hash; the assembler's header.requests_hash relies \
             on this sensitivity for the sealed hash to actually cover the bridge entry"
        );
    }

    #[test]
    fn finish_emits_0xf0_as_last_entry_in_single_request_block() {
        // Empty-block fixture — no deposits/withdrawals/consolidations are produced by the
        // executor, so the resulting `Requests` list has exactly the 0xf0 entry. This locks the
        // single-entry case: 0xf0 is the (only, therefore last) entry, and its type byte is the
        // bridge type byte. The stronger invariant "0xf0 comes strictly after 0x00/0x01/0x02
        // when they're present" is exercised separately by
        // [`requests_hash_includes_0xf0_after_standard_pectra_types`], which builds a multi-type
        // `Requests` directly and feeds it through the assembler.
        let spec = build_chain_spec(true);
        let raw = Bytes::from_static(&[0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD]);
        let requests = finish_requests_with_raw(spec, None, Some(raw));
        assert_eq!(requests.iter().count(), 1, "empty-block fixture produces a single entry");
        let only = requests.iter().last().expect("at least one request entry");
        assert_eq!(only.first(), Some(&0xf0), "0xf0 entry must be the type byte; got {:?}", only);
    }

    /// Build path: `EthEvmConfig::context_for_next_block` must thread
    /// `attributes.suggested_fee_recipient` into every `InboundMessage.feeRecipient` of the
    /// resulting ABI calldata. This is the proposer-side wiring of the dest-chain block
    /// proposer's withdrawal address into the bridge fee distribution.
    #[test]
    fn bridge_call_uses_attributes_suggested_fee_recipient_in_build_path() {
        use alloy_primitives::FixedBytes;
        use alloy_sol_types::SolCall;
        use reth_0g_bridge::{encode::executeRemoteMessagesCall, BridgeMessage, BridgeRequests};
        use reth_evm::NextBlockEnvAttributes;
        use reth_primitives_traits::SealedHeader;
        use ssz::Encode;

        let spec = build_chain_spec(true);
        let local_chain_id = spec.chain.id();
        let provider = EthEvmConfig::new(spec);

        // Pick a non-zero, non-default address so a missing wire-up surfaces clearly.
        const SUGGESTED: Address = address!("0xCafeBabeCafeBabeCafeBabeCafeBabeCafeBabe");

        // CL-style SSZ blob: one BridgeMessage targeted at the local chain.
        let msg = BridgeMessage {
            src_chain_id: 16700,
            dst_chain_id: local_chain_id,
            nonce: 1,
            local_token: FixedBytes([0x11; 20]),
            recipient: FixedBytes([0x22; 20]),
            amount: FixedBytes(U256::from(42u64).to_be_bytes::<32>()),
            mode: 1,
            src_block: 7,
        };
        let ssz = BridgeRequests { messages: vec![msg] }.as_ssz_bytes();

        // Minimal sealed parent header — `context_for_next_block` only reads `parent_hash`
        // off the parent (the rest of the EVM env is sourced from `attributes`).
        let parent = SealedHeader::seal_slow(Header::default());

        let attrs = NextBlockEnvAttributes {
            timestamp: 100,
            suggested_fee_recipient: SUGGESTED,
            prev_randao: B256::ZERO,
            gas_limit: 30_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals: None,
            bridge_request: Some(Bytes::from(ssz)),
        };

        let ctx = provider.context_for_next_block(&parent, attrs);
        let cd = ctx.bridge_request.as_deref().expect("build path produces calldata");

        let decoded = executeRemoteMessagesCall::abi_decode(cd.as_ref()).expect("calldata decodes");
        assert_eq!(decoded.msgs.len(), 1, "one InboundMessage");
        assert_eq!(
            decoded.msgs[0].feeRecipient, SUGGESTED,
            "InboundMessage.feeRecipient must be sourced from attributes.suggested_fee_recipient"
        );
    }

    /// Verify path: `EthEvmConfig::context_for_payload` must source the per-message
    /// `feeRecipient` from `payload.fee_recipient()` (the block-header `beneficiary`). This
    /// is byte-equal to what the proposer's build path produces when CL pins the same
    /// address into both `attrs.suggested_fee_recipient` and the sealed coinbase
    /// (post-MinerReward fork invariant). Any drift here breaks `requests_hash` consistency
    /// and the dest CL would reject the block.
    #[test]
    fn bridge_call_uses_payload_beneficiary_in_verify_path_byte_equal_to_build() {
        use alloy_eips::eip7685::Requests;
        use alloy_primitives::FixedBytes;
        use alloy_rpc_types_engine::{
            CancunPayloadFields, ExecutionData, ExecutionPayloadSidecar, ExecutionPayloadV3,
            PraguePayloadFields,
        };
        use alloy_sol_types::SolCall;
        use reth_0g_bridge::{
            encode::executeRemoteMessagesCall, BridgeMessage, BridgeRequests, BRIDGE_REQUEST_TYPE,
        };
        use reth_ethereum_primitives::{Block, BlockBody};
        use reth_evm::ConfigureEngineEvm;
        use ssz::Encode;

        let spec = build_chain_spec(true);
        let local_chain_id = spec.chain.id();
        let provider = EthEvmConfig::new(spec);

        // Same fee-recipient pinned on both sides (proposer attrs and block header). In
        // production this byte-equality is guaranteed by the post-MinerReward fork: CL
        // writes `withdrawals[0].Address` into `attrs.suggested_fee_recipient`, and the EL
        // pins that into `block.header.beneficiary` when sealing.
        const PROPOSER_X: Address = address!("0x00112233445566778899AABBCCDDEEFF00112233");

        let msg = BridgeMessage {
            src_chain_id: 16700,
            dst_chain_id: local_chain_id,
            nonce: 1,
            local_token: FixedBytes([0x11; 20]),
            recipient: FixedBytes([0x22; 20]),
            amount: FixedBytes(U256::from(42u64).to_be_bytes::<32>()),
            mode: 1,
            src_block: 7,
        };
        let ssz_bytes = BridgeRequests { messages: vec![msg.clone()] }.as_ssz_bytes();
        let mut entry_0xf0 = Vec::with_capacity(1 + ssz_bytes.len());
        entry_0xf0.push(BRIDGE_REQUEST_TYPE);
        entry_0xf0.extend_from_slice(&ssz_bytes);

        // Build a minimal block with the proposer-coinbase pinned. Only fields touched by
        // `ExecutionPayloadV3::from_block_unchecked` and `context_for_payload` matter.
        let header = Header {
            beneficiary: PROPOSER_X,
            timestamp: 100,
            number: 1,
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(B256::ZERO),
            ..Header::default()
        };
        let block = Block {
            header,
            body: BlockBody { withdrawals: Some(Default::default()), ..Default::default() },
        };
        let block_hash = block.header.hash_slow();

        let payload = ExecutionPayloadV3::from_block_unchecked(block_hash, &block);

        // Sidecar carries v3 cancun fields plus v4 prague requests inline.
        let mut requests = Requests::default();
        requests.push_request(entry_0xf0.clone().into());
        let sidecar = ExecutionPayloadSidecar::v4(
            CancunPayloadFields { versioned_hashes: vec![], parent_beacon_block_root: B256::ZERO },
            PraguePayloadFields { requests: requests.into() },
        );
        let exec_data = ExecutionData { payload: payload.into(), sidecar };

        let ctx_verify = provider.context_for_payload(&exec_data);
        let cd_verify = ctx_verify
            .bridge_request
            .as_deref()
            .expect("verify path produces calldata when 0xf0 entry present");

        // Build calldata directly with the same fee-recipient — what the proposer's
        // `context_for_next_block` produces given matching attrs.
        let cd_build = reth_0g_bridge::encode_execute_remote_messages_calldata(
            &[msg],
            local_chain_id,
            PROPOSER_X,
        );

        assert_eq!(
            cd_verify.as_ref(),
            cd_build.as_ref(),
            "verify-path calldata (sourcing fee_recipient from payload.beneficiary) must be \
             byte-equal to build-path calldata (sourcing from attrs.suggested_fee_recipient); \
             any drift would break dest-chain block-hash consistency"
        );

        let decoded = executeRemoteMessagesCall::abi_decode(cd_verify.as_ref()).expect("decode");
        assert_eq!(decoded.msgs.len(), 1);
        assert_eq!(decoded.msgs[0].feeRecipient, PROPOSER_X);
    }

    /// Replay path (`context_for_block`) must zero out both bridge ctx fields. The historical
    /// block's 0xf0 raw SSZ has no on-chain source (not in body, not in receipts, not in any
    /// system contract storage), so the replay-path `finish()` skips both the bridge system call
    /// and the 0xf0 push. The lenient 0G `validate_block_post_execution` then overwrites
    /// `requests_hash` on the in-memory header rather than diffing against the sealed value, so
    /// replay tolerates the missing entry. Locking this wiring invariant here prevents a future
    /// refactor from accidentally repopulating either field from receipts / system storage and
    /// breaking the byte-equivalence with the original execution.
    #[test]
    fn context_for_block_clears_bridge_fields() {
        use reth_ethereum_primitives::{Block, BlockBody};
        use reth_evm::ConfigureEvm;
        use reth_primitives_traits::SealedBlock;

        let spec = build_chain_spec(true);
        let provider = EthEvmConfig::new(spec);

        let header = Header {
            timestamp: 100,
            number: 1,
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(B256::ZERO),
            ..Header::default()
        };
        let block = Block {
            header,
            body: BlockBody { withdrawals: Some(Default::default()), ..Default::default() },
        };
        let sealed = SealedBlock::seal_slow(block);

        let ctx = provider.context_for_block(&sealed);
        assert!(
            ctx.bridge_request.is_none(),
            "replay path must NOT populate bridge_request (no calldata to recover)",
        );
        assert!(
            ctx.bridge_request_raw.is_none(),
            "replay path must NOT populate bridge_request_raw (no SSZ source to recover)",
        );
    }

    /// Defense-in-depth: with Bridge fork inactive at the block timestamp, the 0xf0 push gate
    /// in `EthBlockExecutor::finish` must NOT emit a 0xf0 entry even if `bridge_request_raw` is
    /// somehow attached. Production path is locked at the engine validator layer (V4 requires
    /// `bridge_active`, V3 forbids `bridge_requests`), but test fixtures and any future hot
    /// path can bypass that layer — we still need `finish()` to refuse the push so a
    /// pre-Bridge block can never seal a `requests_hash` covering a 0xf0 entry that the bridge
    /// system call didn't actually execute (would silently diverge bridge state from the
    /// network).
    #[test]
    fn finish_omits_0xf0_entry_when_bridge_inactive_but_prague_active() {
        let spec = build_chain_spec(false); // Prague active (from MAINNET base), Bridge inactive
        let raw = Bytes::from_static(&[0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD]);
        let requests = finish_requests_with_raw(spec, None, Some(raw));
        let entries: Vec<&[u8]> = requests.iter().map(|b| b.as_ref()).collect();
        assert!(
            entries.iter().all(|e| e.first() != Some(&0xf0)),
            "bridge_request_raw=Some + bridge_inactive must NOT push 0xf0 entry; got {:?}",
            entries
        );
    }

    /// Both crates declare `BRIDGE_REQUEST_TYPE = 0xf0` independently (alloy-evm can't depend on
    /// reth-0g-bridge — the dependency goes the other way). If anyone updates the constant in
    /// one crate without the other, wire format silently diverges (CL ↔ EL block-hash mismatch
    /// repeat of 2026-04-29 Bug #2). Lock the two constants together at test time.
    ///
    /// Note: this does NOT catch CL Go-side drift. The Go-side `BridgeRequestType` constant
    /// in `0g-chain-ng/primitives/constants` is frozen by cross-stream convention; ensuring it
    /// matches `BRIDGE_REQUEST_TYPE` is a release-engineering / review-time guarantee, not a
    /// compile-time one (the Go and Rust toolchains can't share constants directly).
    #[test]
    fn bridge_request_type_matches_alloy_evm_constant() {
        assert_eq!(
            reth_0g_bridge::BRIDGE_REQUEST_TYPE,
            alloy_evm::block::system_calls::bridge::BRIDGE_REQUEST_TYPE,
            "BRIDGE_REQUEST_TYPE must match between reth-0g-bridge (wire decoder) and alloy-evm \
             (block executor 0xf0 push)",
        );
    }

    // Silence dead-code checks in this submodule for utilities used selectively.
    #[allow(dead_code)]
    fn _unused() -> HashMap<Address, AccountInfo> {
        HashMap::default()
    }
}
