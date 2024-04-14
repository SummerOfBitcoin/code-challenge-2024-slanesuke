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



// Transaction struct that may be overcomplicated right now. We will see
#[derive(Debug, Deserialize, Clone)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    sighash: Option<String>,
}

// This struct is used to store the transaction and its fee for processing into the block
#[derive(Clone)]
struct TransactionForProcessing {
    transaction: Transaction,
    txid: String,
    fee: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Vin {
    txid: String,
    vout: u32,
    prevout: Prevout,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u32,
}

#[derive(Debug, Deserialize, Clone)]
struct Prevout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

struct BlockHeader {
    version: u32,
    prev_block_hash: String,
    merkle_root: String,
    timestamp: u32,
    bits: u32,
    nonce: u32
}

/// This function will return the coinbase transaction
fn create_coinbase_tx(total_tx_fee: u64) -> Transaction {
    let mut coinbase_tx = Transaction {
        version: 0,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        sighash: None,
    };

    // Just chose a recent block height
    let block_height: u32 = 837122;
    let block_height_bytes = block_height.to_le_bytes();
    let block_height_hex = hex::encode(block_height_bytes);

    //  The block subsidy is 6.25 btc plus the fees from the transactions
    let block_substidy_plus_fees: u64 = 625000000 + total_tx_fee;

    let address_hex =  "053918f36132b92f65c11de2deeccf2f0b35177df3297ed5db".to_string();

    let extra_nonce_hex = hex::encode("SlanesukeSOBIntern2024".as_bytes());

    let block_scriptsig = format!("{}{}", block_height_hex, extra_nonce_hex);

    // version is 4 bytes lil endian 01000000
    coinbase_tx.version = 1;

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
        scriptsig_asm: "".to_string(),
        witness: None,
        is_coinbase: true,
        sequence: 0xffffffff,
    });

    // Output count is 1 byte 01
    coinbase_tx.vout.push(Vout {
        scriptpubkey: address_hex,
        scriptpubkey_asm: "".to_string(),
        scriptpubkey_type: "".to_string(),
        scriptpubkey_address: None,
        value: block_substidy_plus_fees,
    });

    coinbase_tx
}

// This function creates the block header struct
fn construct_block_header(valid_tx_vec: Vec<String>, nonce: u32) -> BlockHeader {

    let mut block_header = BlockHeader{
        version: 0,
        prev_block_hash: "".to_string(),
        merkle_root: "".to_string(),
        timestamp: 0,
        bits:  0x1d00ffff,  // Hard coded 'bits' value
        nonce: 0,
    };
    // The default block version using a BIP 9 bit field is 0b00100000000000000000000000000000.
    // In hex this is 0x20000000 little endian
    let block_version = 0b00100000000000000000000000000000u32.to_le_bytes();
    let block_version_hex = hex::encode(block_version);
    block_header.version = block_version_hex.parse().unwrap();

    // I chose to use block height 837122 for my block just becase that was the current block height
    // at the time of my project (when i made my coinbase tx fn)
    // So I will use the previous block hash of block 837121
    let prev_block_hash = "0000000000000000000205e5b86991b1b0a370fb7e2b7126d32de18e48e556c4";
    block_header.prev_block_hash = prev_block_hash.to_string();

    // Left off on merkle root!!  Lets go!
    // Need to get the txids from the valid txs vec But this is just a placeholder for now
    let txids: Vec<String> = valid_tx_vec.iter().map(|txid| txid.clone()).collect();
    let merkle_root = get_merkle_root(txids);
    block_header.merkle_root = merkle_root;

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
// Previously i serialized each input at a time but this fn does each field at a once  so it should
// speed up the process???
fn serialize_block_header(block_header: &BlockHeader) -> Vec<u8> {
    // Create a buffer of the exact size needed for the block header
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
// fn serialize_block_header(block_header: &BlockHeader) -> Vec<u8> {
//     let mut serialized_bh = Vec::new();
//
//     // Version 4 bytes lil endian
//    serialized_bh.extend(&block_header.version.to_le_bytes());
//
//     // Previous Block natural byte order 32 bytes
//     serialized_bh.extend_from_slice(&hex::decode(&block_header.prev_block_hash).unwrap());
//
//     // Merkle root natural byte order 32 bytes
//     serialized_bh.extend_from_slice(&hex::decode(&block_header.merkle_root).unwrap());
//
//     // Timestamp 4 bytes lil endian
//     serialized_bh.extend(&block_header.timestamp.to_le_bytes());
//
//     // Bits 4 bytes
//     serialized_bh.extend(&block_header.bits.to_le_bytes());
//
//     // Nonce bytes lil endian
//     serialized_bh.extend(&block_header.nonce.to_le_bytes());
//
//     serialized_bh
// }

fn get_merkle_root(txids: Vec<String>) -> String {
    // In natural byte order

    // Need to hash all txids in the block until i get one merkle root
    // if valid txs is odd duplicate the last one and hash it with itself
    // let _merkle_root = String::new();
    let mut merkle_tree = txids.clone();

    // If the number of txs is odd, duplicate the last tx and hash it with itself
    if merkle_tree.len() % 2 != 0 {
        let last_tx = merkle_tree.last().unwrap().clone();
        merkle_tree.push(last_tx);
    }


    // I need to Loop through the merkle tree and hash each pair of txids
    // First I must concatenate the two txids (in order) and they must be 512 bits because each tx is 256 bits
    // double sha256 is used to hash

    // While the merkle tree has more than one txid
    while merkle_tree.len() > 1 {
        let mut temp_merkle_tree = Vec::new();

        // For each pair of txids in the merkle tree
        // Hash them together and push the hash to the temp merkle tree
        // Then once there is the merkle root left, return it as
        for i in (0..merkle_tree.len()).step_by(2) {
            let txid0 = &merkle_tree[i];
            let txid1 = if i+1 < merkle_tree.len() {
                &merkle_tree[i+1]
            } else {
                // This is a catch statement for when the number of txs is odd
                // It shouldn't be though because I duplicated the last txid
                &merkle_tree[i]
            };

            let concatenated_txids = format!("{}{}", txid0, txid1);
            let merkle_hash = double_sha256(concatenated_txids.as_bytes().to_vec());
            let merkle_hash_hex = hex::encode(merkle_hash);

            temp_merkle_tree.push(merkle_hash_hex);
        }
        merkle_tree = temp_merkle_tree;
    }
    // If the merkle tree has one txid left, return it as the merkle root
    if let Some(merkle_root) = merkle_tree.first() {
        if merkle_root.len() != 64 {
            panic!("Merkle root is over 32 bytes");
        } else {
            merkle_root.clone()
        }
    } else {
        panic!("Merkle root is empty");
    }
}

fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let file = File::open(filename).unwrap();

    // let mut json_string = String::new();
    // file.read_to_string(& mut json_string).unwrap();
    //
    // let tx: Transaction = serde_json::from_str(&json_string).unwrap();

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
        //serialized_tx.push_str(&vin.txid);

        // I believe the txid needs to be in reversed byte order
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();
        let reversed_txid = hex::encode(reversed_txid_bytes);
        serialized_tx.push_str(&reversed_txid);


        let vout = &vin.vout.to_le_bytes();
        serialized_tx.push_str(&hex::encode(vout));


        // Serialize scriptSig size I kept getting trailing zeros after my compactsize hex
        let scriptsig_size = vin.scriptsig.len() / 2;

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
        serialized_tx.push_str(&<std::option::Option<std::string::String> as Clone>::clone(&transaction.sighash).unwrap());
    }

    serialized_tx
}


// /// This function will serialize a segwit transaction into a string of hex bytes
// fn serialized_segwit_tx(transaction: &Transaction) -> String {
//     let mut serialized_tx = String::new();
//
//     let version = transaction.version.to_le_bytes();
//     serialized_tx.push_str(&hex::encode(version));
//
//     // In a segwit transaction I have to add a marker and a flag
//     // Marker is always 00 and flag is always 01
//     serialized_tx.push_str("00");
//     serialized_tx.push_str("01");
//
//     // Serialize vin count and push the numb of inputs
//     let vin_count = transaction.vin.len() as u64;
//     serialized_tx.push_str(&format!("{:02x}", vin_count));
//
//
//     for vin in &transaction.vin {
//         // Serialize txid and push
//         serialized_tx.push_str(&vin.txid);
//
//         // Serialize vout and push
//         let vout = &vin.vout.to_le_bytes();
//         let vout_hex = hex::encode(vout);
//         serialized_tx.push_str(&vout_hex);
//
//         // If its strictly a segwit tx, scriptsig field is empty so push zero
//         if vin.scriptsig.is_empty() {
//             serialized_tx.push_str("00");
//         } else {
//             // Otherwise it's a tx with both legacy and segwit inputs so I have to add the scriptsig
//             // Coppied from the legacy serialize_tx function
//             // Serialize scriptSig size I kept getting trailing zeros after my compactsize hex
//             let scriptsig_size = vin.scriptsig.len() / 2;
//
//             // So I had to do this to remove the trailing zeros
//             // It basically converts the u64 to bytes then to a vec then removes the trailing zeros
//             let mut scriptsig_size_bytes = (scriptsig_size as u64).to_le_bytes().to_vec();
//
//             if let Some(last_non_zero_position) = scriptsig_size_bytes.iter().rposition(|&x| x != 0) {
//                 scriptsig_size_bytes.truncate(last_non_zero_position + 1);
//             }
//
//             let scriptsig_size_hex = hex::encode(&scriptsig_size_bytes);
//             serialized_tx.push_str(&scriptsig_size_hex);
//
//             // Now push scriptsig itself
//             serialized_tx.push_str(&vin.scriptsig);
//         }
//
//         let sequence = &vin.sequence.to_le_bytes();
//         let sequence_hex = hex::encode(sequence);
//         serialized_tx.push_str(&sequence_hex);
//
//     }
//
//     let vout_count = transaction.vout.len() as u64;
//     serialized_tx.push_str(&format!("{:02x}", vout_count));
//
//
//     // Serialize vout count and push the numb of outputs
//     // I copied it from the legacy serialize_tx function
//     for vout in &transaction.vout {
//
//         // Next push the amount of satoshis
//         let value = &vout.value.to_le_bytes();
//         serialized_tx.push_str(&hex::encode(value));
//
//         // Now push the scriptpubkey cpmpact size
//
//         // Just like above I had to remove the trailing zeros}
//         let scriptpubkey_size = vout.scriptpubkey.len() / 2;
//         let mut scriptpubkey_size_bytes = (scriptpubkey_size as u64).to_le_bytes().to_vec();
//         if let Some(last_non_zero_position) = scriptpubkey_size_bytes.iter().rposition(|&x| x != 0) {
//             scriptpubkey_size_bytes.truncate(last_non_zero_position + 1);
//         }
//         let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_bytes);
//         serialized_tx.push_str(&scriptpubkey_size_hex);
//         serialized_tx.push_str(&vout.scriptpubkey);
//     }
//
//     // Now time for the witness fields
//     for vin in &transaction.vin {
//         if let Some(witness) = &vin.witness {
//             // Serialize the number of stack items for the witness!
//             let stack_items = witness.len() as u64;
//             serialized_tx.push_str(&format!("{:02x}", stack_items));
//
//             for witness_feild in witness {
//                 // Get compact size
//                 // Why does script_sig have trailing zeros but none here in compact size
//                 let compact_size = witness_feild.len() / 2;
//                 serialized_tx.push_str(&format!("{:02x}", compact_size));
//                 serialized_tx.push_str(witness_feild);
//
//             }
//         }
//     }
//
//     // Finally add the locktime
//     let lock = &transaction.locktime.to_le_bytes();
//     let lock_hex = hex::encode(lock);
//     serialized_tx.push_str(&lock_hex);
//
//     // Unsure if segwit tx's need a sighash type so will keep it commented for now
//     // if transaction.sighash.is_some() {
//     //         serialized_tx.push_str(&<std::option::Option<std::string::String> as Clone>::clone(&transaction.sighash).unwrap());
//     //     }
//
//      serialized_tx
// }

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
        let  scriptsig = &vin.scriptsig;
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

    //////
    let serialized_validtx = serialized_tx_for_message.as_bytes();
    let txid: [u8; 32] = double_sha256(serialized_validtx.to_vec());

    Ok((true, hex::encode(txid)))
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

                let (is_valid, txid) = match p2pkh_script_validation(&mut transaction) {
                    Ok(result) => result,
                    Err(_e) => {
                        //eprintln!("An error occured, failed to validate transaction: {:?}", e);
                        continue;
                    }
                };
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
                if fee < 0 {
                    //eprintln!("Transaction has a negative fee: {:?}", path);
                    continue;
                } else if fee < 1000 {
                    //eprintln!("Transaction has a fee below 1000 satoshis: {:?}", path);
                    continue;
                }

                // Remove dust transactions
                let min_relay_fee_per_byte: u64 = 3; // 3 satoshis per byte  could go up or down 1-5
                remove_dust_transactions(&mut transaction, min_relay_fee_per_byte);

                // Check for double spending
                if !check_double_spending(&transaction, &valid_txs) {
                    continue;
                }

                //println!("Transaction is valid for txid: {}", txid);

                // Push the txid and fee to the valid_txs vec
                valid_txs.push(TransactionForProcessing {
                    transaction,
                    txid,
                    fee: fee as u64,
                });
            }else {
                //eprintln!("Failed to convert path to string: {:?}", path);
            }
        }
    }
    Ok(valid_txs)
}

/// This function will calculate the hash of the block header!!!
// Test this fn next
fn calculate_hash(block_header: Vec<u8>) -> String {
    let hash = double_sha256(block_header);
    hex::encode(hash)
}

/// This function takes the target and hash, converts them to a big int, then compares
fn hash_meets_difficulty_target(hash: &str) -> bool {
    let target_string = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target = U256::from_str_radix(target_string, 16).unwrap();
    let hash_as_num = U256::from_str_radix(hash, 16).unwrap();
    hash_as_num < target
}

fn  calculate_transaction_weight(tx: &Transaction)  ->  u64  {

    let base_size = serialize_tx(tx).len() as u64;
    // Don't need yet because i've only verified p2pkh tx's
    let total_size = serialize_tx(tx).len() as u64;

    // Calculate weight of the transaction
    let tx_weight = base_size * 3 + total_size;

    tx_weight
}

// ISSUE Block does not meet target difficulty
// So my block hash is too big so maybe too many transations in a block?
fn main() {
    let mempool_path = "../mempool";

    // Initialize nonce value;
    let mut nonce = 0u32;

    // Get the valid txs from the mempool
    let mut valid_tx = process_mempool(mempool_path).unwrap();

    // Calculate the total fees and get the txids
    let mut valid_txids: Vec<String> = Vec::new();

    // Initializing block weight
    let mut block_txs: Vec<TransactionForProcessing> = Vec::new();
    let mut total_weight = 0u64;
    let mut total_fees = 0u64;

    let valid_tx_clone =  valid_tx.clone();

    for tx in valid_tx_clone {
        let tx_weight = calculate_transaction_weight(&tx.transaction);
        if total_weight + tx_weight > 4000000 {
            // If the block weight exceeds the limit, break the loop
            break;
        }
        block_txs.push(tx.clone());
        total_weight += tx_weight;
        total_fees  += tx.fee; // Add the fee to the total fees
        valid_txids.push(tx.txid.clone());
    }

    // Sort the transactions in descending order based on the fee
    let sorted_valid_tx: Vec<_> = block_txs.iter()
        .cloned().sorted_by(|a, b| b.fee.cmp(&a.fee)).
        collect();

    // Get txids from sorted valid txs
    let sorted_txids : Vec<String> = sorted_valid_tx.iter().map(|tx| tx.txid.clone()).collect();

    // Start Mining!
    loop {
        // Get the block header and serialize it
        let block_header = construct_block_header(sorted_txids.clone(), nonce);

        let serialized_block_header = serialize_block_header(&block_header);

        // Calculate the hash of the block header
        let block_hash = calculate_hash(serialized_block_header.clone());

        // Check if the hash meets the target
        if hash_meets_difficulty_target(&block_hash) {

            // Generate coinbase tx
            let coinbase_tx = create_coinbase_tx(total_fees);
            let serialized_cb_tx = serialize_tx(&coinbase_tx);

            // coinbase txid
            let coinbase_txid = double_sha256(serialized_cb_tx.as_bytes().to_vec());

            // Clear the output file
            fs::write("../output.txt", "").unwrap();

            // Write the block header, coinbase tx, and txids to the output file
            append_to_file("../output.txt", &hex::encode(serialized_block_header)).unwrap();
            append_to_file("../output.txt", &serialized_cb_tx).unwrap();

            // Insert the coinbase txid at the beginning of the valid_txids vector
            valid_txids.insert(0, hex::encode(coinbase_txid));

            // Add the txids to the block
            for txid in &sorted_txids {
                append_to_file("../output.txt", txid).unwrap();
            }

            println!("Success, the block met the target difficulty!");

            break;
        } else {
            nonce += 1;
        }
    }
}