/// TODO
/// FIGURE OUT HOW TO VERIFY THE SIGNATURE OF A TRANSACTION UGHH


use std::fmt::{Debug, format};
use serde::Deserialize;
use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{self, Read, read_to_string, Write};
use ripemd::Ripemd160;
// use ripemd::{Digest as RipemdDigest, Ripemd160};
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};


// Unsure if i need to use the extern crate for secp256k1
extern crate secp256k1;
use secp256k1::{PublicKey, Secp256k1, Message};
use std::error::Error;
use std::fs;
use secp256k1::ecdsa::Signature;
use sha2::digest::core_api::Block;



// Transaction struct that may be overcomplicated right now. We will see
#[derive(Debug, Deserialize, Clone)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    sighash: Option<String>,
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
    bits: String,
    nonce: u32
}

// TODO Before I turn it in
// Implement the CoinbaseTx function! Need to add the serialized coinbase tx to output.txt
// If the coinbase tx has a segwit tx according to BIP 141: all coinbase transactions since the segwit
// upgrade need to include a witness reserved value in
// the witness field for the input, and then use that along with a witness root hash to put a wTXID
// commitment in the ScriptPubKey of one of the outputs in the transaction.

// This function will create a coinbase transaction
fn create_coinbase_tx (total_tx_fee: u64) -> String {
    // Hard coding the current block height I see on mempool.space and current block reward
    let block_height: u32 = 837122;
    let block_height_bytes = block_height.to_le_bytes();
    let block_height_hex = hex::encode(block_height_bytes);


    let block_sub_plus_fees: u64 = 625000000 + total_tx_fee; // Block reward in satoshis
    let block_reward_bytes = block_sub_plus_fees.to_le_bytes();
    let block_reward_hex = hex::encode(block_reward_bytes);

    // adding an address to pay the block reward to
    let address = String::from("36tvL5nHzSffbx4v9UhBfyGLWAkBUKyoxn");
    // Same address converted to hex for serialization
    let address = "053918f36132b92f65c11de2deeccf2f0b35177df3297ed5db".to_string();


    let extra_nonce = String::from("SlanesukeSOBIntern2024");
    let extra_nonce_hex = hex::encode(extra_nonce.as_bytes());

    // Adding the block height and extra nonce to the coinbase input scriptSig
    // the block height is in little endian byte order then encoding in hex
    let block_scriptsig = format!("{}{}", block_height_hex, extra_nonce_hex);



    // Finish manually serializing the coinbase tx.
    // Left off concantingating the scriptPubKey SIze
    // The address might need to be in hex
    let version = "01000000".to_string();
    let input_count = "01".to_string();
    let txid = "0000000000000000000000000000000000000000000000000000000000000000";
    let vout = "ffffffff";
    let scriptsig_size = format!("{:02x}", block_scriptsig.len()/2);
    let sequence = "ffffffff";
    let output_count = "01".to_string();
    let scriptpubkey_size = format!("{:02x}", address.len()/2);
    let locktime = "00000000";


    let serialized_coinbase_tx = format!("{}{}{}{}{}{}{}{}{}{}{}{}", version, input_count, txid,
                                         vout, scriptsig_size, block_scriptsig, sequence, output_count, block_reward_hex, scriptpubkey_size,
                                         address, locktime);

    serialized_coinbase_tx
}

fn construct_block_header(valid_tx_vec: Vec<String>, nonce: u32) -> BlockHeader {

    let mut block_header = BlockHeader{
        version: 0,
        prev_block_hash: "".to_string(),
        merkle_root: "".to_string(),
        timestamp: 0,
        bits: String::new(),
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

    // The time the block was constructed in unix time
    // 4 bytes little endian
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();
    let timestamp_hex = hex::encode(timestamp_bytes);
    block_header.timestamp = timestamp_hex.parse().unwrap();

    // Bits
    // The target is a 256 bit number that the header hash must be less than or equal to in
    // order for the block to be valid
    // Our target is 0000ffff00000000000000000000000000000000000000000000000000000000
    //The basic format of the bits field is:
    // The last 3 bytes contain the rough precision of the full target.
    // The first byte indicates "how many bytes to the left" those 3 bytes sit in a full 32-byte field.
    let target ="0000ffff00000000000000000000000000000000000000000000000000000000";
    let significant_bytes = &target[0..6]; // is this 00ffff or 0000ff CHeCK
    let shifted_left_bytes = (target.len() / 2) - (significant_bytes.len() / 2); // 32 - 3 = 29
    let bits = format!("{:02x}{}", shifted_left_bytes, significant_bytes);
    // Should the bits be a string or an integer?
    block_header.bits = bits;

    // Nonce
    // 4 byte little endian unsigned integer
    // I guess start nonce at 0 and increment until the block hash is less than the target
    block_header.nonce = nonce; // pass in a nonce from main

    block_header
}

// Serialize block header
fn serialize_block_header(block_header: &BlockHeader) -> String {
    let mut serialized_bh = String::new();

    // Not sure if this function is nessesary but i don't want to also serialize the block header
    // in the block_header function and i need to pass in multiple nonces anways

    // Version 4 bytes lil endian
    let version = hex::decode(&block_header.version).unwrap();
    serialized_bh.push_str(&hex::encode(version));

    // Previous Block natural byte order 32 bytes
    serialized_bh.push_str(&block_header.prev_block_hash);

    // Merkle root natural byte order 32 bytes
    serialized_bh.push_str(&block_header.merkle_root);

    // Timestamp 4 bytes lil endian
    let timestamp = hex::decode(&block_header.timestamp).unwrap();
    serialized_bh.push_str(&hex::encode(timestamp));

    // Bits 4 bytes
    serialized_bh.push_str(&block_header.bits);

    // Nonce bytes lil endian
    let nonce = block_header.nonce.to_le_bytes();
    serialized_bh.push_str(&hex::encode(nonce));

    serialized_bh
}

fn get_merkle_root(txids: Vec<String>) -> String {
    // In natural byte order

    // Need to hash all txids in the block until i get one merkle root
    // if valid txs is odd duplicate the last one and hash it with itself
    let mut merkle_root = String::new();
    let mut merkle_tree = txids.clone();

    // If the number of txs is odd, duplicate the last tx and hash it with itself
    if merkle_tree.len() % 2 != 0 {
        let last_tx = merkle_tree.last().unwrap().clone();
        merkle_tree.push(last_tx);
    }


    // I need to Loop through the merkle tree and hash each pair of txids
    // First i must concantenate the two txids (in order) and they must be 512 bits becasue each tx is 256 bits
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

// TODO
// Need to get my head together and figure out how to simplify and verify the .json transactions. After
// that i need to write a mining algo to efficiently fit the transactions with the highest fees into a block
// and pass the block fees to coinbase tx so I can add it to the block reward.
// Need to then just get there txid's and put them in a vec to add to output.txt

// TODO
// Implement the BlockHeader function! Need to add the serialized block header to output.txt






// First just  working  with one tx so I can learn
fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let mut file = File::open(filename).unwrap();

    let mut json_string = String::new();
    file.read_to_string(& mut json_string).unwrap();

    let tx: Transaction = serde_json::from_str(&json_string).unwrap();

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


/// This function will serialize a segwit transaction into a string of hex bytes
fn serialized_segwit_tx(transaction: &Transaction) -> String {
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
        serialized_tx.push_str(&vin.txid);

        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        // If its strictly a segwit tx, scriptsig field is empty so push zero
        if vin.scriptsig.is_empty() {
            serialized_tx.push_str("00");
        } else {
            // Otherwise it's a tx with both legacy and segwit inputs so I have to add the scriptsig
            // Coppied from the legacy serialize_tx function
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
        }

        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);

    }

    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));


    // Serialize vout count and push the numb of outputs
    // I copied it from the legacy serialize_tx function
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

    // Now time for the witness fields
    for vin in &transaction.vin {
        if let Some(witness) = &vin.witness {
            // Serialize the number of stack items for the witness!
            let stack_items = witness.len() as u64;
            serialized_tx.push_str(&format!("{:02x}", stack_items));

            for witness_feild in witness {
                // Get compact size
                // Why does script_sig have trailing zeros but none here in compact size
                let compact_size = witness_feild.len() / 2;
                serialized_tx.push_str(&format!("{:02x}", compact_size));
                serialized_tx.push_str(witness_feild);

            }
        }
    }

    // Finally add the locktime
    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

    // Unsure if segwit tx's need a sighash type so will keep it commented for now
    // if transaction.sighash.is_some() {
    //         serialized_tx.push_str(&<std::option::Option<std::string::String> as Clone>::clone(&transaction.sighash).unwrap());
    //     }



     serialized_tx
}

/// This function will verify the signature of a transaction when passed into OP_CHECKSIG
fn verify_signature(
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    mut serialized_tx: Vec<u8>) -> Result<bool, Box<dyn Error>> {

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
        Err(e) => {
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
    let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig).unwrap();

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

// Check double spend
fn check_double_spending(transaction: &Transaction, mempool: &Vec<Transaction>) -> bool {
    // Loop through mempool
    for tx in mempool {
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

/// This function will validate a P2PKH transaction
fn p2pkh_script_validation(transaction: &mut Transaction) -> Result<bool, Box<dyn Error>> {

    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

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
        let serialized_tx_for_message = serialize_tx(&message_tx);

        // Convert the serialized tx into bytes for the message
        let message_in_bytes = hex::decode(serialized_tx_for_message)
            .map_err(|e| format!("Failed to decode the hex string for input: {}", i))?;

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
                    let stack_temp = stack.pop().unwrap();
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

    Ok(true)
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
fn process_mempool(mempool_path: &str) -> io::Result<Vec<(String, u64)>> {
    let mut valid_txs = Vec::new();

    for tx in fs::read_dir(mempool_path)? {
        let tx = tx?;
        let path = tx.path();
        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                let mut transaction = deserialize_tx(path_str);
                // I can add this once i put all the valid tx's  in a vec
                // if !check_double_spending(&transaction, Vec<>) {
                //   continue;
                // }

                match p2pkh_script_validation(&mut transaction) {
                    Ok(is_valid) => {
                        if !is_valid {
                            eprintln!("Transaction is not valid: {:?}", path);
                            continue;
                        }
                    },
                    Err(e) => {
                        eprintln!("An error occured, failed to validate transaction: {:?}", e);
                        continue;
                    }
                }

                // Get the fee if valid so  i can add it to my vec
                let fee = verify_tx_fee(&transaction);
                if fee < 0 {
                    eprintln!("Transaction has a negative fee: {:?}", path);
                    continue;
                } else if fee < 1000 {
                    eprintln!("Transaction has a fee below 1000 satoshis: {:?}", path);
                    continue;
                }

                // Remove dust transactions
                let min_relay_fee_per_byte: u64 = 3; // 3 satoshis per byte  could go up or down 1-5
                remove_dust_transactions(&mut transaction, min_relay_fee_per_byte);


                println!("Transaction is valid for txid: {}", transaction.vin[0].txid);
                valid_txs.push((transaction.vin[0].txid.clone(), fee));
            }else {
                eprintln!("Failed to convert path to string: {:?}", path);
            }
        }
    }
    Ok(valid_txs)
}

/// This function will convert the valid txs into a vec of txids
///  Should i implement a check for the fee here? or how do i decide which txs to put in the block
fn valid_txs_to_vec(valid_txs: Vec<(String, u64)>) -> Vec<String> {
    let mut txids:Vec<String> = Vec::new();
    for (txid, _) in valid_txs {
        txids.push(txid);
    }
    txids
}

/// This function will calculate the hash of the block header!!!
// Test this fn next
fn calculate_hash(block_header: &str) -> String {
    let hash = double_sha256(block_header.as_bytes().to_vec());
    hex::encode(hash)
}

fn hash_meets_difficulty_target(hash: &str) -> bool {
    // if target is below the hash return true
}

/// This function will generate the output file
// May remove the formatting
fn generate_output_file(block_header: &str, coinbase_tx: String, txids_vec: &Vec<&str>)
    -> io::Result<()> {
    let file = "../output.txt";

    std::fs::write(file, "")?;

    // FOrmatting the block header
    let header_border = "+------------------------------------------------------------------+";
    append_to_file(file, header_border)?;
    let block_header = format!("|{:^66}|", block_header);
    append_to_file(file, &block_header)?;
    append_to_file(file, header_border)?;

    // Formatting the coinbase transaction
    let coinbase_tx = format!("|{:^66}|", coinbase_tx);
    append_to_file(file, &coinbase_tx)?;
    append_to_file(file, header_border)?;

    // Formatting the txids
    for txids in txids_vec {
        let txid = format!("|{:^66}|", txids);
        append_to_file(file, &txid)?;
    }
    append_to_file(file, header_border)?;

    Ok(())
}


fn main() {
    let mempool_path = "../mempool";
    match process_mempool(mempool_path) {
        Ok(valid_transactions) => {
            for (txid, fee) in valid_transactions {
                println!("Transaction ID: {}, Fee: {}", txid, fee);
            }
        },
        // Err(e) => eprintln!("An error occurred while processing the mempool: {}", e),
        _ => todo!(),
    }
}

fn main2() {
    let mut nonce = 0u32;
    // valid_txs pulls from the process_mempool function and returns a vec of valid txids
    let valid_txs = valid_txs_to_vec(process_mempool("../mempool").unwrap());
    loop {
        // function to construct  block header
        let block_header = construct_block_header(valid_txs.clone(), nonce);
        // function to calculate the hash of the block header
        let hash = calculate_hash(&block_header);

        // function to check if the hash meets the difficulty target
        if hash_meets_difficulty_target(&hash) {
            println!("Found valid nonce: {}", nonce);
            break;
        }

        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            println!("Exhausted all nonces without finding a valid one");
            break;
        }
    }
}


