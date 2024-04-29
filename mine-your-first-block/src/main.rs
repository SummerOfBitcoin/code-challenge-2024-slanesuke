mod transactions;
mod validation;
mod utils;
mod block;

use transactions::*;
use validation::*;
use utils::*;
use block::*;
use itertools::Itertools;

fn main() {
    // Path to the mempool folder
    let mempool_path = "../mempool";

    // Initialize nonce value;
    let mut nonce = 0u32;

    // Get the valid txs from the mempool
    let valid_txs = process_mempool(mempool_path).unwrap();

    // Initializing block weight
    let mut block_txs: Vec<TransactionForProcessing> = Vec::new();
    let mut total_weight = 0u64;

    // My calculate_transaction_weight function is off so I increased the weight limit for a quick fix
    // FIX calc_tx_weight
    let max_block_weight = 4000000u64;
    let mut total_fees = 0u64;

    // Sort transactions by fee in descending order before processing
    let sorted_valid_txs: Vec<_> = valid_txs.iter()
        .sorted_by(|a, b| b.fee.cmp(&a.fee))
        .collect();

    // Select transactions to include in the block based on sorted order
    for tx in sorted_valid_txs {
        let tx_weight = calculate_transaction_weight(&tx.transaction);
        if total_weight + tx_weight > max_block_weight {
            break;  // Stop if adding this transaction would exceed the max block weight
        }
        block_txs.push(tx.clone());
        total_weight += tx_weight;
        total_fees += tx.fee;
    }

    // Sorting the transactions from fees in desencding order
    block_txs.sort_by(|a, b| b.fee.cmp(&a.fee));

    // Get the wtxids for the witness root
    let mut wtx_ids_for_witness_root = vec!["0000000000000000000000000000000000000000000000000000000000000000".to_string()];
    //let mut wtx_ids_for_witness_root: Vec<String> = vec![];
    for tx in &block_txs {
        // println!("TransactionID: {}, IS_P2WPKH: {}", tx.txid, tx.is_p2wpkh);
        if tx.is_p2wpkh {
            if let Some(ref wtxid) = tx.wtxid {
                wtx_ids_for_witness_root.push(wtxid.clone());  // Collect wtxid if valid
            }
        } else {
            wtx_ids_for_witness_root.push(tx.txid.clone());  // Collect txid if not p2wpkh
        }
    }

    // Generate coinbase tx
    let coinbase_tx = create_coinbase_tx(total_fees, wtx_ids_for_witness_root.clone());
    let serialized_cb_tx = serialized_segwit_tx(&coinbase_tx);
    let cd_tx_bytes = hex::decode(serialized_cb_tx.clone()).unwrap();

    // coinbase txid
    let coinebase_tx_for_txid = coinbase_tx.clone();
    let serialized_cb_tx_for_txid = serialize_tx(&coinebase_tx_for_txid);
    let cb_txid_bytes = hex::decode(serialized_cb_tx_for_txid).unwrap();
    let coinbase_txid = double_sha256(cb_txid_bytes.clone());
    let mut coinbase_txid_le = coinbase_txid.to_vec();
    coinbase_txid_le.reverse();
    let coinbase_txid = hex::encode(coinbase_txid_le);

    // Insert the coinbase transaction at the beginning of block_txs
    let coinbase_tx_for_processing = TransactionForProcessing {
        transaction: coinbase_tx.clone(),
        txid: coinbase_txid.clone(),
        wtxid: Some("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
        fee: 0,
        is_p2wpkh: true,
    };
    block_txs.insert(0, coinbase_tx_for_processing);

    // Use block_txs to generate Merkle root
    let txids_for_merkle = block_txs.iter().map(|tx| tx.txid.clone()).collect::<Vec<_>>();
    let merkle_root = get_merkle_root(txids_for_merkle.clone());

    // Start Mining!
    loop {
        // Get the block header and serialize it
        let block_header = construct_block_header(nonce, merkle_root.clone());
        let serialized_block_header = serialize_block_header(&block_header);

        // Calculate the hash of the block header
        let  block_hash =  double_sha256(serialized_block_header.clone());
        let mut block_h = block_hash;
        block_h.reverse();
        let block_hash = hex::encode(block_h);

        // Check if the hash meets the target
        if hash_meets_difficulty_target(&block_hash) {
            write_block_to_file(&serialized_block_header, &cd_tx_bytes, &block_txs);
            println!("Success, the block met the target difficulty!");
            break;
        } else {
            nonce += 1;
        }
    }
}