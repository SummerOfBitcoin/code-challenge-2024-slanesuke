mod transactions;

use transactions::Transaction;

use transactions::*;

use std::fmt::{Debug};
use serde::Deserialize;
use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{self, Write, BufReader};
use ripemd::Ripemd160;
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;
extern crate secp256k1;
use secp256k1::{PublicKey, Secp256k1, Message};
use std::error::Error;
use std::fs;
use secp256k1::ecdsa::Signature;
use primitive_types::U256;
use byteorder::{LittleEndian, WriteBytesExt};


/// This function will return the coinbase transaction
fn create_coinbase_tx(total_tx_fee: u64, witness_root_vec: Vec<String>) -> Transaction {
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

    // witness data
    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    let txid= "0000000000000000000000000000000000000000000000000000000000000000";
    // input count is 1 byte 01
    coinbase_tx.vin.push(Vin {
        txid: txid.to_string(),
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
        witness: Some(vec![witness_reserved_value.to_string()]),
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
    let concant_items = format!("{}{}", witness_root_hash, witness_reserved_value);

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

// This function creates the block header struct
fn construct_block_header(nonce: u32, merkle_root: String) -> BlockHeader {

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
    // 4 byte little endian unsigned integer
    // I guess start nonce at 0 and increment until the block hash is less than the target
    block_header.nonce = nonce; // pass in a nonce from main

    block_header
}

/// This function serializes the block header because it's a bit different from a reg tx
fn serialize_block_header(block_header: &BlockHeader) -> Vec<u8> {
    let mut buffer = vec![0u8; 80];  // 80 bytes for Bitcoin block header

    {
        let mut writer = &mut buffer[..];

        // Write each field directly into the buffer at the correct position
        writer.write_u32::<LittleEndian>(block_header.version).unwrap();
        writer.write_all(&hex::decode(&block_header.prev_block_hash).unwrap()).unwrap();
        writer.write_all(&hex::decode(&block_header.merkle_root).unwrap()).unwrap();
        writer.write_u32::<LittleEndian>(block_header.timestamp).unwrap();
        writer.write_u32::<LittleEndian>(block_header.bits).unwrap();
        writer.write_u32::<LittleEndian>(block_header.nonce).unwrap();
    }
    buffer
}

/// This function calcluates the merkle root. It putes txids in natural byte order then
/// Hashes the tree
fn get_merkle_root(txids: Vec<String>) -> String {
    // Convert the txids to big endian to hash
    let mut be_txid = txids.iter()
        .map(|txid| {
            let decoded_id = hex::decode(txid).unwrap();
            let reversed_id = decoded_id.iter().rev().cloned().collect::<Vec<u8>>();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&reversed_id);
            arr
        })
        .collect::<Vec<[u8; 32]>>();

    // While the merkle tree has more than one txid
    while be_txid.len() > 1 {
        if be_txid.len() % 2 != 0 {
            be_txid.push(be_txid.last().unwrap().clone());
        }

        // a bit confused so skipped the doublehash fn
        be_txid = be_txid.chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                let first_hash = hasher.finalize_reset().to_vec();
                hasher.update(first_hash);
                hasher.finalize().try_into().expect("Hash should be 32 bytes")
            }).collect()
    }

    // merkle root in little endian
    let merkle_root = be_txid[0].to_vec();
    hex::encode(merkle_root)
}

fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    let tx: Transaction = serde_json::from_reader(reader).unwrap();

    // return a transaction if the deserialization is successful
    tx
}

/// This function will serialize a transaction into a string of hex bytes
fn serialize_tx(transaction: &Transaction) -> String {
    // Returning the serialized tx as a string
    let mut serialized_tx = String::new();

    // Serialize version field, little endian
    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));


    // Serialize vin count
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    // Sereialize txid
    for vin in &transaction.vin {

        // I believe the txid needs to be in reversed byte order
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();
        let reversed_txid = hex::encode(reversed_txid_bytes);
        serialized_tx.push_str(&reversed_txid);

        // Serialize vout
        let vout = &vin.vout.to_le_bytes();
        serialized_tx.push_str(&hex::encode(vout));

        // Serialize scriptSig size I kept getting trailing zeros after my compactsize hex
        let scriptsig_size = vin.scriptsig.len() / 2;

        // IMPLEMENT THE COMPACT SIZE FUNCTION (this was first draft)
        // So I had to do this to remove the trailing zeros
        // It basically converts the u64 to bytes then to a vec then removes the trailing zeros
        let mut scriptsig_size_bytes = (scriptsig_size as u64).to_le_bytes().to_vec();

        if let Some(last_non_zero_position) = scriptsig_size_bytes.iter().rposition(|&x| x != 0) {
            scriptsig_size_bytes.truncate(last_non_zero_position + 1);
        }

        let scriptsig_size_hex = hex::encode(&scriptsig_size_bytes);
        serialized_tx.push_str(&scriptsig_size_hex);

        // Now push scriptsig itself
        serialized_tx.push_str(&vin.scriptsig);

        // push sequence
        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);
    }

    //  The output count has to be outside the vout loop because it's a single byte before it
    // was inside
    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // Now serialize vout count
    for vout in &transaction.vout {

        // Next push the amount of satoshis
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey cpmpact size

        // Just like above I had to remove the trailing zeros}
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let mut scriptpubkey_size_bytes = (scriptpubkey_size as u64).to_le_bytes().to_vec();
        if let Some(last_non_zero_position) = scriptpubkey_size_bytes.iter().rposition(|&x| x != 0) {
            scriptpubkey_size_bytes.truncate(last_non_zero_position + 1);
        }
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_bytes);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

    if transaction.sighash.is_some() {
        serialized_tx.push_str(&<Option<String> as Clone>::clone(&transaction.sighash).unwrap());
    }

    serialized_tx
}

/// This function should serialize a transaction into a string of hex bytes for segwit transactions
fn serialized_segwit_tx(transaction: &Transaction) -> String {
    let mut serialized_tx = String::new();

    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // For the coinbase transaction in between the version and vin count I need to add the marker and flag
    // If the is_coinbase == true push 00 and 01
    if transaction.vin[0].is_coinbase {
        serialized_tx.push_str("0001");
    }

    // Serialize vin count and push the numb of inputs
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    for vin in &transaction.vin {
        // Serialize txid and push
        //serialized_tx.push_str(&vin.txid);
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();
        let reversed_txid = hex::encode(reversed_txid_bytes);
        serialized_tx.push_str(&reversed_txid);

        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        // If its strictly a segwit tx, scriptsig field is empty so push zero
        if vin.scriptsig.is_empty() {
            serialized_tx.push_str("00");
        } else {
            // Serialize scriptSig size
            let scriptsig_size = vin.scriptsig.len() / 2;
            let mut scriptsig_size_bytes = (scriptsig_size as u64).to_le_bytes().to_vec();
            if let Some(last_non_zero_position) = scriptsig_size_bytes.iter().rposition(|&x| x != 0) {
                scriptsig_size_bytes.truncate(last_non_zero_position + 1);
            }
            let scriptsig_size_hex = hex::encode(&scriptsig_size_bytes);
            serialized_tx.push_str(&scriptsig_size_hex);

            // Now push scriptsig itself
            serialized_tx.push_str(&vin.scriptsig);
        }

        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);
    }

    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // Serialize vout count and push the numb of outputs
    for vout in &transaction.vout {
        // Next push the amount of satoshis
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey compact size
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let mut scriptpubkey_size_bytes = (scriptpubkey_size as u64).to_le_bytes().to_vec();
        if let Some(last_non_zero_position) = scriptpubkey_size_bytes.iter().rposition(|&x| x != 0) {
            scriptpubkey_size_bytes.truncate(last_non_zero_position + 1);
        }
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_bytes);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    // Need the witness to be added to the coinbase tx so if there is a witness field that is equal to
    // "0000000000000000000000000000000000000000000000000000000000000000" then push to the serialized tx
    // before the locktime
    for vin in &transaction.vin {
        if let Some(witness) = &vin.witness {
            if witness[0] == "0000000000000000000000000000000000000000000000000000000000000000" {
                serialized_tx.push_str("01");
                serialized_tx.push_str("20");
                serialized_tx.push_str(&witness[0]);
            }
        }
    }

    // Finally add the locktime
    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

    serialized_tx
}


/// This function will serialize a segwit wtransaction into a string of hex bytes
fn serialized_segwit_wtx(transaction: &Transaction) -> String {
    let mut serialized_tx = String::new();

    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // In a segwit transaction I have to add a marker and a flag
    // Marker is always 00 and flag is always 01
    serialized_tx.push_str("00");
    serialized_tx.push_str("01");

    // Serialize vin count and push the numb of inputs
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));


    for vin in &transaction.vin {
        // Serialize txid and push
        // I believe the txid needs to be in reversed byte order
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();
        let reversed_txid = hex::encode(reversed_txid_bytes);
        serialized_tx.push_str(&reversed_txid);


        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        serialized_tx.push_str("00");


        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);

    }

    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));


    for vout in &transaction.vout {
        // Serialize the value in sats
        let value_bytes = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value_bytes));

        // Serialize scriptPubKey size using compact size
        let scriptpubkey_size_bytes = compact_size_as_bytes(vout.scriptpubkey.len() / 2);
        serialized_tx.push_str(&hex::encode(&scriptpubkey_size_bytes));

        // serialize the scriptpubkey
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    for vin in &transaction.vin {
        if let Some(witness) = &vin.witness {
            // Serialize the number of stack items in the witness using CompactSize
            let stack_items_bytes = compact_size_as_bytes(witness.len());
            serialized_tx.push_str(&hex::encode(&stack_items_bytes));

            for witness_item in witness {
                // Decode witness item to get actual bytes
                let witness_data = hex::decode(witness_item).unwrap();

                // Get compact size of the witness item
                let witness_data_size_bytes = compact_size_as_bytes(witness_data.len());
                serialized_tx.push_str(&hex::encode(&witness_data_size_bytes));

                // Append the witness data itself
                serialized_tx.push_str(witness_item);
            }
        }
    }

    // Finally add the locktime
    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

     serialized_tx
}

/// This function will verify the signature of a transaction when passed into OP_CHECKSIG
fn verify_signature(
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    serialized_tx: Vec<u8>) -> Result<bool, Box<dyn Error>> {

    // Removing the sighash type from the signature
    let signature = &signature[..signature.len()-1];
    let secp = Secp256k1::new();


    let hash_array: [u8; 32] = double_sha256(serialized_tx);
    let message_result = Message::from_digest_slice(&hash_array).unwrap();
    let public_key =  PublicKey::from_slice(&pubkey).expect("Failed to create public key");
    let signature = Signature::from_der(&signature).unwrap();

    // Return Ok(true) if the signature is valid, Ok(false) if it's invalid
    match secp.verify_ecdsa(&message_result, &signature,  &public_key) {
        Ok(_) => {
            Ok(true)
        },
        Err(_e) => {
            Ok(false)
        },
    }
}

/// This function gets the signature and public key from the scriptsig of a legacy transaction
// Would it be easier to get the signature and pubkey from the scriptsig_asm field?
fn get_signature_and_publickey_from_scriptsig(scriptsig: &str) -> Result<(String, String), Box<dyn Error>> {
    // Convert the scriptsig hex string to bytes
    let scriptsig_bytes = hex::decode(scriptsig)?;

    let mut index = 0;
    let mut sig_and_pubkey_vec = Vec::new();

    // Loop through the scriptsig bytes to parse
    while index < scriptsig_bytes.len() {
        if index+1 >= scriptsig_bytes.len() {
            return Err("Unexpected end of scriptSig".into());
        }

        let length = scriptsig_bytes[index] as usize; // This byte is the length of data to push (sig or pub)
        index += 1; // Move to the next byte

        // Checks if the length is greater than the remaining bytes in the scriptsig
        if index + length > scriptsig_bytes.len() {
            return Err("ScriptSig length byte exceeds remaining data".into());
        }

        // Get the data of the opcode length
        let data = &scriptsig_bytes[index..index+length];
        index+=length; // Move the index to the next opcode

        sig_and_pubkey_vec.push(hex::encode(data));
    }
    // Checking if the sig_and_pubkey_vec has two elements if not fail
    if sig_and_pubkey_vec.len() != 2 {
        return Err(format!("Expected 2 elements, found {}", sig_and_pubkey_vec.len()).into());
    }

    Ok((sig_and_pubkey_vec[0].clone(), sig_and_pubkey_vec[1].clone()))
}

// This function will get the tx ready for signing by removing the scriptsig and adding the
// scriptpubkeyto the scriptsig field and adding the sighash to the transaction
fn get_tx_readyfor_signing_legacy(transaction : &mut Transaction) -> Transaction {
    // Get the signature and public key from the scriptsig
    let scriptsig = &transaction.vin[0].scriptsig;
    let (signature, _pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig).unwrap();

    // removing the scriptsig for each vin and adding the scriptpubkey to the scriptsig field
    for vin in transaction.vin.iter_mut() {
        vin.scriptsig = String::new();
        vin.scriptsig = vin.prevout.scriptpubkey.clone();
    }

    // Using the last two bytes of the signature as the sighash type for now
    let sighash_type = &signature[signature.len()-2..];

    // Hard coding the sighash type for now
     let sighash = format!("{}000000", sighash_type);

    // Adding the sighash to the transaction
    // It turns a string into a u32
    transaction.sighash = Some(sighash);

    // Emptying the scriptsig fields for each input
    for vin in transaction.vin.iter_mut() {
        // Empty
        vin.scriptsig = String::new();

        // Copy the scriptpubkey to the scriptsig field
        vin.scriptsig  = vin.prevout.scriptpubkey.clone();
    }

    // Return the tx
    Transaction {
        version: transaction.version,
        locktime: transaction.locktime,
        vin: transaction.vin.clone(),
        vout: transaction.vout.clone(),
        sighash: transaction.sighash.clone(),
    }
}


/// Function to get segwit message
fn get_segwit_tx_message(
    transaction: &mut Transaction,
    vin_index: usize,
    pubkey_hash: &str,
    sighash_type: u8) ->  Result<String, Box<dyn Error>> {
    let mut tx = transaction.clone();


    let version = tx.version.to_le_bytes();
    let version = hex::encode(version);

    // Serialze and hash txid+vout for each vin
    let mut input_bytes = Vec::new();
    let mut sequences_bytes = Vec::new();

    for vin in tx.vin.iter() {
        let txid_bytes = hex::decode(vin.txid.clone()).map_err(|e| e.to_string())?;
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();

        let vout_bytes = vin.vout.to_le_bytes();

        input_bytes.extend_from_slice(&reversed_txid_bytes);
        input_bytes.extend_from_slice(&vout_bytes);


        //sequence
        let sequence_bytes = vin.sequence.to_le_bytes();
        sequences_bytes.extend_from_slice(&sequence_bytes);
    }
    let input_hash = double_sha256(input_bytes);
    let sequences_hash = double_sha256(sequences_bytes);

    //  Serialize the txid+vout for the specific input
    let vin = &tx.vin[vin_index];

    let txid_bytes = hex::decode(vin.txid.clone()).unwrap();
    let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();
    let txid = hex::encode(reversed_txid_bytes);

    let vout = vin.vout.to_le_bytes();
    let vout = hex::encode(vout);

    let input = format!("{}{}", txid, vout);

    // Create a scriptcode for the input being signed
    let scriptcode = format!("1976a914{}88ac", pubkey_hash);

    // Get input amount in sats
    let input_amount = vin.prevout.value;
    let amount_le = input_amount.to_le_bytes();
    let amount_le = hex::encode(amount_le);

    // Sequence for input we sign
    let sequence = vin.sequence.to_le_bytes();
    let sequence= hex::encode(sequence);


    let mut output_bytes = Vec::new();
    for vout in tx.vout.iter() {
        let amount_le = vout.value.to_le_bytes();
        output_bytes.extend_from_slice(&amount_le);

        // For some reason i get trailing zeros after the compact size so i had to remove them
        // Do i need to divide the scriptpubkey size by 2?
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let scriptpubkey_size_bytes = compact_size_as_bytes(scriptpubkey_size);
        output_bytes.extend_from_slice(&scriptpubkey_size_bytes);

        let scriptpubkey = vout.scriptpubkey.clone();
        // This is the scriptpubkey in bytes the .
        let scriptpubkey_bytes = hex::decode(scriptpubkey).map_err(|e| e.to_string())?;
        output_bytes.extend_from_slice(&scriptpubkey_bytes);
    }

    let output_hash = double_sha256(output_bytes);

    // Locktime
    let locktime = tx.locktime.to_le_bytes();
    let locktime = hex::encode(locktime);

    // Need to add the sighash type to the preimage
    let sighash_type_u32 = u32::from_le(sighash_type as u32);
    let formatted_sighash = hex::encode(sighash_type_u32.to_le_bytes());

    // preimage or message to be signed
    // Assuming all the variables are already defined and have the correct values
    let preimage = format!("{}{}{}{}{}{}{}{}{}{}",
                           version,
                           hex::encode(input_hash),
                           hex::encode(sequences_hash),
                           input,
                           scriptcode,
                           amount_le,
                           sequence,
                           hex::encode(output_hash),
                           locktime,
                           formatted_sighash,
    );

    Ok(preimage)
}

fn compact_size_as_bytes(size: usize) -> Vec<u8> {
    match size {
        0..=0xfc => vec![size as u8],
        0xfd..=0xffff => {
            let mut bytes = vec![0xfd];
            bytes.extend_from_slice(&(size as u16).to_le_bytes());
            bytes
        },
        0x10000..=0xffffffff => {
            let mut bytes = vec![0xfe];
            bytes.extend_from_slice(&(size as u32).to_le_bytes());
            bytes
        },
        _ => {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&(size as u64).to_le_bytes());
            bytes
        },
    }
}


/// This function will validate P2WPKH transactions
fn p2wpkh_script_validation(transaction: &mut Transaction) -> Result<(bool, String, String), Box<dyn Error>> {
    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

    for (i, vin) in transaction.vin.iter().enumerate() {
        stack.clear();

        let witness = vin.witness.clone().ok_or("Witness data not found")?;
        if witness.len() < 2 {
            return Err("Witness data is missing elements".into());
        }
        let signature = hex::decode(witness[0].clone())?;
        if signature.is_empty(){
            return Err("Signature is empty".into());
        }

        // sighash type off sig
        let sighash_type = signature[signature.len()-1];

        let pubkey= hex::decode(witness[1].clone())?;
        stack.push(signature);
        stack.push(pubkey);

        // Get the pubkey hash from script_pubkey_asm
        let script_pubkey = vin.prevout.scriptpubkey_asm.clone();
        let parts: Vec<&str> = script_pubkey.split_whitespace().collect();
        let pubkey_hash = parts.last().unwrap();

        // Message hash
       let message_hash = get_segwit_tx_message(
            &mut transaction.clone(),
            i,
            pubkey_hash.clone(),
            sighash_type.clone()
       )?;
        let message_in_bytes = hex::decode(&message_hash)?;

        // Now it execute like a p2pkh locking script where the pubkeyhah is pushed after ophash160
        let script_pubkey_asm = format!("OP_DUP OP_HASH160 OP_PUSHBYTES_20 {} OP_EQUALVERIFY OP_CHECKSIG", pubkey_hash);

        for op in script_pubkey_asm.split_whitespace(){
            match op {
                "OP_DUP" => {
                    // If the stack is empty return false
                    // Otherwise clone the last item on the stack and push it to the stack
                    if stack.last().is_none() {
                        return Err(format!("Stack underflow in OP_DUP for input {}", i).into());
                    }
                    stack.push(stack.last().unwrap().clone());
                }
                "OP_HASH160" => {
                    // If the stack is empty return false
                    // Otherwise take the last item from the stack, hash it with sha256 then ripemd160
                    // and push it to the stack
                    if let Some(pubkey) = stack.pop() {
                        let sha256_hash = sha256(pubkey);
                        let ripemd160_hash = ripemd160(sha256_hash);
                        stack.push(ripemd160_hash.clone());
                    } else {
                        return Err(format!("Stack underflow in OP_HASH160 for input {}", i).into());
                    }
                }
                "OP_EQUALVERIFY" => {
                    // if stack is less than 2 return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_EQUALVERIFY for input {}", i).into());
                    }
                    // Otherwise pop the last two items from the stack and compare them
                    // if they are not equal return false, if they are just continue
                    let stack_item1 = stack.pop().unwrap();
                    // unsure why but i diregard an extra item on the stack
                    // then it compares the top two items
                    let _stack_temp = stack.pop().unwrap();
                    let stack_item2 = stack.pop().unwrap();
                    if stack_item1 != stack_item2 {
                        return Err(format!("Stackitem1: {} aND Stackitem 2: {} and Hash: {} .OP_EQUALVERIFY failed for input",hex::encode(stack_item1), hex::encode(stack_item2), i).into());
                    }
                }
                "OP_CHECKSIG" => {
                    // If the stack has less than two items return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_CHECKSIG for input {}", i).into());
                    }
                    // otherwise pop the last two items from the stack (pubkey and signature)
                    // and validate the signature
                    let pubkey = stack.pop().unwrap();
                    let signature = stack.pop().unwrap();


                    match verify_signature(signature.clone(), pubkey.clone(), message_in_bytes.clone()) {
                        Ok(true) => {
                            // If the signature is valid, push a truthy value onto the stack to indicate success
                            stack.push(vec![1]);
                        },
                        Ok(false) => {
                            // The signature verification was successful but reported the signature as invalid
                            let pubkey_hex = hex::encode(&pubkey);
                            let signature_hex = hex::encode(&signature);
                            return Err(format!(
                                "Signature verification failed for input {}. The signature does not match the provided public key and message. PubKey: {}, Signature: {}",
                                i, pubkey_hex, signature_hex
                            ).into());
                        },
                        Err(e) => {
                            // An error occurred during the signature verification process
                            return Err(format!(
                                "An error occurred while verifying the signature for input {}: {}",
                                i, e
                            ).into());
                        }
                    }
                }
                _ => {
                    // If it's not an operator, it's an ordinary data (like sig or pubkey) and push it onto the stack
                    // Verify !!!
                    let data = hex::decode(op).unwrap_or_default(); // Convert hex string to bytes
                    stack.push(data);
                }
            }
        }
        if stack.len() != 1 || stack.is_empty() {
            return Err(format!("Final stack validation failed for input {}", i).into());
        }
    }

    // May need to change this a bit...
    // FOR WTXID
    let serialized_validwtx = serialized_segwit_wtx(transaction);
    let wtx_bytes = hex::decode(serialized_validwtx.clone())?;
    let wtxid_be = double_sha256(wtx_bytes);
    let mut wtxid_le = wtxid_be;
    wtxid_le.reverse();
    let wtxid = hex::encode(wtxid_le);

    // FOR TXID
    let serialized_validtx = serialized_segwit_tx(transaction);
    let tx_bytes = hex::decode(serialized_validtx).unwrap();
    let txid_be = double_sha256(tx_bytes);
    let mut txid_le = txid_be;
    txid_le.reverse();
    let txid = hex::encode(txid_le);

    Ok((true, wtxid, txid))
}

/// This function will validate a P2PKH transaction
fn p2pkh_script_validation(transaction: &mut Transaction) -> Result<(bool, String), Box<dyn Error>> {

    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // Initalize the serialized tx
    let mut serialized_tx_for_message = String::new();

    for (i,vin) in transaction.vin.iter().enumerate() {

        // Clearing the stack
        stack.clear();

        // Get ScriptSig and ScriptPubKey
        // Should i just do this from the ScriptSig_asm???
        let scriptsig = &vin.scriptsig;
        let script_pub_key = &vin.prevout.scriptpubkey_asm.clone();

        let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig)
            .map_err(|e| format!("Error getting signature and public key from scriptsig for input {}: {}", i, e))?;

        // Prepare the transaction for signing
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.vin = vec![vin.clone()];
        let message_tx = get_tx_readyfor_signing_legacy(&mut tx_for_signing);

        // Update the serialized tx
        serialized_tx_for_message = serialize_tx(&message_tx);

        // Convert the serialized tx into bytes for the message
        let message_in_bytes = hex::decode(serialized_tx_for_message.clone())
            .map_err(|_e| format!("Failed to decode the hex string for input: {}", i))?;

        let decoded_signature = hex::decode(signature).map_err(|e| format!("Failed to decode signature: {}", e))?;
        let decoded_pubkey = hex::decode(pubkey).map_err(|e| format!("Failed to decode pubkey: {}", e))?;
        stack.push(decoded_signature);
        stack.push(decoded_pubkey);

        for op in script_pub_key.split_whitespace() {
            match op {
                "OP_DUP" => {
                    // If the stack is empty return false
                    // Otherwise clone the last item on the stack and push it to the stack
                    if stack.last().is_none() {
                        return Err(format!("Stack underflow in OP_DUP for input {}", i).into());
                    }
                    stack.push(stack.last().unwrap().clone());
                }
                "OP_HASH160" => {
                    // If the stack is empty return false
                    // Otherwise take the last item from the stack, hash it with sha256 then ripemd160
                    // and push it to the stack
                    if let Some(pubkey) = stack.pop() {
                        let sha256_hash = sha256(pubkey);
                        let ripemd160_hash = ripemd160(sha256_hash);
                        stack.push(ripemd160_hash.clone());
                    } else {
                        return Err(format!("Stack underflow in OP_HASH160 for input {}", i).into());
                    }
                }
                "OP_EQUALVERIFY" => {
                    // if stack is less than 2 return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_EQUALVERIFY for input {}", i).into());
                    }
                    // Otherwise pop the last two items from the stack and compare them
                    // if they are not equal return false, if they are just continue
                    let stack_item1 = stack.pop().unwrap();
                    // unsure why but i diregard an extra item on the stack
                    // then it compares the top two items
                    let _stack_temp = stack.pop().unwrap();
                    let stack_item2 = stack.pop().unwrap();
                    if stack_item1 != stack_item2 {
                        return Err(format!("Stackitem1: {} aND Stackitem 2: {} and Hash: {} .OP_EQUALVERIFY failed for input",hex::encode(stack_item1), hex::encode(stack_item2), i).into());
                    }
                }
                "OP_CHECKSIG" => {
                    // If the stack has less than two items return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_CHECKSIG for input {}", i).into());
                    }
                    // otherwise pop the last two items from the stack (pubkey and signature)
                    // and validate the signature
                    let pubkey = stack.pop().unwrap();
                    let signature = stack.pop().unwrap();


                    match verify_signature(signature.clone(), pubkey.clone(), message_in_bytes.clone()) {
                        Ok(true) => {
                            // If the signature is valid, push a truthy value onto the stack to indicate success
                            stack.push(vec![1]);
                        },
                        Ok(false) => {
                            // The signature verification was successful but reported the signature as invalid
                            let pubkey_hex = hex::encode(&pubkey);
                            let signature_hex = hex::encode(&signature);
                            return Err(format!(
                                "Signature verification failed for input {}. The signature does not match the provided public key and message. PubKey: {}, Signature: {}",
                                i, pubkey_hex, signature_hex
                            ).into());
                        },
                        Err(e) => {
                            // An error occurred during the signature verification process
                            return Err(format!(
                                "An error occurred while verifying the signature for input {}: {}",
                                i, e
                            ).into());
                        }
                    }
                }
                _ => {
                    // If it's not an operator,it'a ordinary data (like sig or pubkey) and push it onto the stack
                    // Verify !!!
                    let data = hex::decode(op).unwrap_or_default(); // Convert hex string to bytes
                    stack.push(data);
                }
            }
        }
        if stack.len() != 1 || stack.is_empty() {
            return Err(format!("Final stack validation failed for input {}", i).into());
        }
    }

    let serialized_validtx = serialize_tx(transaction);
    let tx_bytes = hex::decode(serialized_validtx).unwrap();
    let txid_be = double_sha256(tx_bytes);
    let mut txid_le = txid_be;
    txid_le.reverse();
    let txid = hex::encode(txid_le);

    Ok((true, txid))
}

/// This function will remove dust transactions from a transaction
// I will need to look more into this
fn is_dust_output(output: &Vout, min_fee_per_byte: u64) -> bool {
    // Looked up the avg size of a P2PKH input
    let input_size = 148;
    // Calculate the minimum value that makes spending this output worthwhile
    let min_output_value = input_size * min_fee_per_byte;
    output.value < min_output_value
}

fn remove_dust_transactions(transaction: &mut Transaction, min_fee_per_byte: u64) {
    transaction.vout.retain(|output| !is_dust_output(output, min_fee_per_byte));
}

/// Function to get the tx amount so
fn verify_tx_fee(transaction: &Transaction) -> u64 {
    let total_input_amount: u64 = transaction.vin.iter()
        .map(|input| input.prevout.value)
        .sum();

    let total_output_amount: u64 = transaction.vout.iter()
        .map(|output| output.value)
        .sum();

    total_input_amount - total_output_amount
}

// Check double spend
fn check_double_spending(transaction: &Transaction, mempool: &Vec<TransactionForProcessing>) -> bool {
    // Loop through mempool
    for tx in mempool {
        let tx = &tx.transaction;
        // Loop through the vin of the transaction
        for vin in &tx.vin {
            // Loop through the vin of the mempool tx
            for vin2 in &transaction.vin {
                // If the txid and vout match return false
                if vin.txid == vin2.txid && vin.vout == vin2.vout {
                    return false; // DOuble spent!!
                }
            }
        }
    }
    true
}

/// Hashing Functions
// Takes in data and returns a ripemd160 hash
fn ripemd160(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Takes in data and returns a sha256 hash
fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn double_sha256(input: Vec<u8>) -> [u8; 32] {
    let first_hash = sha256(input);
    let second_hash = sha256(first_hash);
    second_hash.try_into().expect("Expected a Vec<u8> of length 32")
}

/// Creating the file
// This function will create a file with the given filename and write contents to it
fn append_to_file(filename: &str, contents: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;

    writeln!(file, "{}", contents)?;
    Ok(())
}

/// Combing through the meempool folder
// Need to implement logic so that if it passes all these checks it will be added to a vec
fn process_mempool(mempool_path: &str) -> io::Result<Vec<TransactionForProcessing>> {
    let mut valid_txs: Vec<TransactionForProcessing> = Vec::new();
    for tx in fs::read_dir(mempool_path)? {
        let tx = tx?;
        let path = tx.path();
        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                let mut transaction = deserialize_tx(path_str);

                let mut is_valid = false;
                let mut txid = String::new();
                let mut wtxid = None;

                // Check script type and validate accordingly
                match transaction.vin[0].prevout.scriptpubkey_type.as_str() {
                    "v0_p2wpkh" => {
                        // If it's a p2wpkh transaction validate it
                        match p2wpkh_script_validation(&mut transaction) {
                            Ok((valid, wtx_id, tx_id)) if valid => {
                                is_valid = true;
                                wtxid = Some(wtx_id);
                                txid = tx_id;

                            },
                            _ => continue,
                        }
                    },
                    "p2pkh" => {
                        // If it's a p2pkh transaction validate it
                        match p2pkh_script_validation(&mut transaction) {
                            Ok((valid, tx_id)) if valid => {
                                is_valid = true;
                                txid = tx_id;
                            },
                            _ => continue,
                        }
                    },
                    _ => continue,
                }

                if !is_valid {
                    //eprintln!("Transaction is not valid: {:?}", path);
                }

                // Check if locktime is valid by comparing it to the current time
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32;
                if transaction.locktime > current_time && transaction.locktime >= 500_000_000 {
                    continue;
                }


                // Get the fee if valid so  i can add it to my vec
                let fee = verify_tx_fee(&transaction);
                if fee < 1000 {
                    //eprintln!("Transaction has a negative fee: {:?}", path);
                    continue;
                }

                // Remove dust transactions
                let min_relay_fee_per_byte: u64 = 3; // 3 satoshis per byte  could go up or down 1-5
                remove_dust_transactions(&mut transaction, min_relay_fee_per_byte);

                // Check for double spending
                if !check_double_spending(&transaction, &valid_txs) {
                    continue;
                }

                // Add the transaction to the list of valid transactions
                valid_txs.push(TransactionForProcessing {
                    transaction,
                    txid,
                    wtxid: wtxid.clone(),
                    fee,
                    is_p2wpkh: wtxid.is_some(),
                });
            }else {
                //eprintln!("Failed to convert path to string: {:?}", path);
            }
        }
    }
    Ok(valid_txs)
}

/// This function takes the target and hash, converts them to a big int, then compares
fn hash_meets_difficulty_target(hash: &str) -> bool {
    let target_string = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target = U256::from_str_radix(target_string, 16).unwrap();
    let hash_as_num = U256::from_str_radix(hash, 16).unwrap();
    hash_as_num < target
}

fn  calculate_transaction_weight(tx: &Transaction)  ->  u64  {
    // Serialized tx size without witness
    let base_size = serialize_tx(tx).len() as u64;
    let total_size = base_size; // Need to update once i include more tx types

    // Calculate weight of the transaction
    let tx_weight = base_size * 3 + total_size;

    tx_weight
}


fn main() {
    // Uncomment for the project to mine
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
    let max_block_weight = 7000000u64;
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
            write_block_to_file(&serialized_block_header, &cd_tx_bytes, txids_for_merkle.clone(), &block_txs);
            println!("Success, the block met the target difficulty!");
            break;
        } else {
            nonce += 1;
        }
    }
}

fn write_block_to_file(serialized_header: &[u8], serialized_cb_tx: &[u8], txs: Vec<String>, block_txs: &[TransactionForProcessing]) {
    fs::write("../output.txt", "").unwrap();  // Clear the output file
    append_to_file("../output.txt", &hex::encode(serialized_header)).unwrap();
    append_to_file("../output.txt", &hex::encode(serialized_cb_tx)).unwrap();
    for tx in block_txs {
        append_to_file("../output.txt", &tx.txid).unwrap();
    }
}






