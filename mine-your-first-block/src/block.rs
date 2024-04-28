use std::time::{SystemTime, UNIX_EPOCH};
extern crate secp256k1;
use crate::transactions::{BlockHeader, Prevout, Transaction, Vin, Vout};
use crate::utils::{double_sha256, get_merkle_root};

/// This function will return the coinbase transaction
pub fn create_coinbase_tx(total_tx_fee: u64, witness_root_vec: Vec<String>) -> Transaction {
    // Create a coinbase transaction and return it
    let mut coinbase_tx = Transaction {
        version: 0,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        sighash: None,
    };


    //  The block subsidy is 6.25 btc plus the fees from the transactions
    let block_sub_plus_fees: u64 = 625000000 + total_tx_fee;

    // A p2pkh scriptpubkey for return address
    let scriptpubkey = "76a91406f1b66fd59a34755c37a8f701f43e937cdbeb1388ac".to_string();

    // OP_PUSHBYTES_3 + block height. block_height = 837122
    let block_scriptsig = "03837122".to_string();

    // version is 4 bytes lil endian 00000000
    coinbase_tx.version = 0;

    // witness data also
    let txid= "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    // input count is 1 byte 01
    coinbase_tx.vin.push(Vin {
        txid,
        vout: 0xffffffff,
        prevout: Prevout {
            scriptpubkey: "".to_string(),
            scriptpubkey_asm: "".to_string(),
            scriptpubkey_type: "".to_string(),
            scriptpubkey_address: "".to_string(),
            value: 0,
        },
        scriptsig: block_scriptsig,
        scriptsig_asm: "OP_PUSHBYTES_3 837122".to_string(),
        witness: Some(vec![txid]),
        is_coinbase: true,
        sequence: 0xffffffff,
    });

    // Output count is 1 byte 01
    coinbase_tx.vout.push(Vout {
        scriptpubkey,
        scriptpubkey_asm: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 06f1b66fd59a34755c37a8f701f43e937cdbeb13 OP_EQUALVERIFY OP_CHECKSIG".to_string(),
        scriptpubkey_type: "p2pkh".to_string(),
        scriptpubkey_address: None,
        value: block_sub_plus_fees,
    });


    // Output count 2 for the wtxid stuff
    // the witness root hash gets hashed with the witness reserve value and put into
    // the scriptpubkey of the second output
    let witness_root_hash = get_merkle_root(witness_root_vec);
    // the txid below is the witness reserve value. It's just a 32 byte string of numbers
    let concant_items = format!("{}{}", witness_root_hash, txid);

    let wtxid_items_bytes = hex::decode(concant_items).unwrap();
    let wtxid_commitment_test =  double_sha256(wtxid_items_bytes);
    let wtxid_commitment = hex::encode(wtxid_commitment_test);
    let scriptpubkey_for_wtxid_test = format!("6a24aa21a9ed{}", wtxid_commitment);
    coinbase_tx.vout.push(Vout {
        scriptpubkey: scriptpubkey_for_wtxid_test,
        scriptpubkey_asm: "OP_RETURN OP_PUSHBYTES_36 aa21a9ed".to_string() + &wtxid_commitment,
        scriptpubkey_type: "op_return".to_string(),
        scriptpubkey_address: None,
        value: 0,
    });
    coinbase_tx
}

/// This function creates the block header struct
pub fn construct_block_header(nonce: u32, merkle_root: String) -> BlockHeader {

    let mut block_header = BlockHeader{
        version: 0x20000000,
        prev_block_hash: "".to_string(),
        merkle_root: merkle_root.to_string(),
        timestamp: 0,
        bits: 0x1f00ffff, // Hard coded 'bits' value
        nonce: 0,
    };

    let prev_block_hash = "0000000000000000000205e5b86991b1b0a370fb7e2b7126d32de18e48e556c4";
    let decode_prev_block_hash = hex::decode(prev_block_hash).unwrap();
    let reversed_prev_block_hash = decode_prev_block_hash.iter().rev().cloned().collect::<Vec<u8>>();
    let reversed_hex = hex::encode(reversed_prev_block_hash);
    block_header.prev_block_hash = reversed_hex.to_string();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    block_header.timestamp = timestamp as u32;

    // Nonce
    block_header.nonce = nonce; // pass in a nonce from main

    block_header
}
