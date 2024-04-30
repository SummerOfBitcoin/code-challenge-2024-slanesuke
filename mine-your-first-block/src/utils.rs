use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{self, Write, BufReader};
use ripemd::Ripemd160;
use std::fs::OpenOptions;
extern crate secp256k1;
use std::error::Error;
use std::fs;
use byteorder::{LittleEndian, WriteBytesExt};
use crate::transactions::{BlockHeader, Transaction, TransactionForProcessing};


/// This function calculates the merkle root.
pub fn get_merkle_root(txids: Vec<String>) -> String {

    // This will iterate over each txid, decode from hex and reverse the byte order and collect
    // into a vector of 32 byte arrays for hashing
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
        // If the number of txids is odd, duplicate the last txid and push
        if be_txid.len() % 2 != 0 {
            be_txid.push(be_txid.last().unwrap().clone());
        }

        // This will iterate over the txids (as bytes) in pairs of 2, concatenate them together and hash them
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

    // Return the merkle root as a hex string
    let merkle_root = be_txid[0].to_vec();
    hex::encode(merkle_root)
}

/// This function deserialize a tx from the mempool module
pub fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let file = File::open(filename).unwrap();

    // Create a buffer reader
    let reader = BufReader::new(file);
    // Deserialize the tx from the buffer reader
    let tx: Transaction = serde_json::from_reader(reader).unwrap();

    // Return a transaction if the deserialization is successful
    tx
}

//  Serialization functions
/// This function serializes the block header because it's a bit different from a reg tx
pub fn serialize_block_header(block_header: &BlockHeader) -> Vec<u8> {
    // Allocates 80 bytes for the block header
    let mut buffer = vec![0u8; 80];

    // Write the block header fields into the buffer
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

    // Return the serialized block header
    buffer
}

//  Transaction serializations
/// This function will serialize a transaction into a hex string
pub fn serialize_tx(transaction: &Transaction) -> String {
    // Returning the serialized tx as a string
    let mut serialized_tx = String::new();

    // Serialize version field, little endian
    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // Serialize vin count
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    // Serialize txid
    for vin in &transaction.vin {

        // Reverse the byte order of txid and push
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid = reverse_bytes(txid_bytes);
        serialized_tx.push_str(&reversed_txid);

        // Serialize vout
        let vout = &vin.vout.to_le_bytes();
        serialized_tx.push_str(&hex::encode(vout));

        // Get the scriptsig compact size and push it
        let scriptsig_size_hex = compact_size_as_bytes(vin.scriptsig.len() / 2);
        let scriptsig_size_hex = hex::encode(&scriptsig_size_hex);
        serialized_tx.push_str(&scriptsig_size_hex);

        // Now push scriptsig itself
        serialized_tx.push_str(&vin.scriptsig);

        // Push sequence
        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);
    }

    // Serialize vout count
    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // Now serialize vout count
    for vout in &transaction.vout {

        // Next push the amount of sats little endian
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey compact size then the scriptpubkey
        let scriptpubkey_size_hex = compact_size_as_bytes(vout.scriptpubkey.len() / 2);
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_hex);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    // Finally add the locktime
    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

    // If the transaction has a sighash field, add it to the serialized tx
    if transaction.sighash.is_some() {
        serialized_tx.push_str(&<Option<String> as Clone>::clone(&transaction.sighash).unwrap());
    }

    // Return the serialized tx
    serialized_tx
}

/// This function should serialize a transaction into a string of hex bytes for segwit transactions
pub fn serialized_segwit_tx(transaction: &Transaction) -> String {
    // Create a string to hold the serialized tx
    let mut serialized_tx = String::new();

    // Serialize version field, little endian
    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // For the coinbase transaction in between the version and vin count I need to add the marker and flag
    // If the is_coinbase == true push 00 and 01
    if transaction.vin[0].is_coinbase {
        serialized_tx.push_str("0001");
    }

    // Serialize vin count and push the number of inputs
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    for vin in &transaction.vin {
        // Serialize txid and push
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid= reverse_bytes(txid_bytes);
        serialized_tx.push_str(&reversed_txid);

        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        // If its strictly a segwit tx, scriptsig field is empty so push zero
        if vin.scriptsig.is_empty() {
            serialized_tx.push_str("00");
        } else {
            // Otherwise
            // Serialize scriptSig size
            let scriptsig_size_hex = compact_size_as_bytes(vin.scriptsig.len() / 2);
            let scriptsig_size_hex = hex::encode(&scriptsig_size_hex);
            serialized_tx.push_str(&scriptsig_size_hex);

            // Now push scriptsig itself
            serialized_tx.push_str(&vin.scriptsig);
        }
        // Push sequence
        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);
    }

    // Push the vout count
    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // Serialize vout count and push the numb of outputs
    for vout in &transaction.vout {
        // Next push the amount of sats little endian
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey compact size and then the scriptpubkey
        let scriptpubkey_size_hex = compact_size_as_bytes(vout.scriptpubkey.len() / 2);
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_hex);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    // If the witness field is == to the witness reserve value, serialize the witness data
    // This only for the coinbase transaction
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

    // Return the serialized tx
    serialized_tx
}


/// This function will serialize a segwit wtransaction into a string of hex bytes
pub fn serialized_segwit_wtx(transaction: &Transaction) -> String {
    let mut serialized_tx = String::new();

    // Serialize version field, little endian
    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // In a segwit transaction I have to add a marker and a flag
    // Marker is always 00 and flag is always 01
    serialized_tx.push_str("00");
    serialized_tx.push_str("01");

    // Serialize vin count and push the numb of inputs
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    // For each vin in the transaction
    for vin in &transaction.vin {
        // Serialize txid, reverse the bytes and push
        let txid_bytes = hex::decode(&vin.txid).unwrap();
        let reversed_txid = reverse_bytes(txid_bytes);
        serialized_tx.push_str(&reversed_txid);


        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        // If its strictly a segwit tx, scriptsig field is empty so push zero
        serialized_tx.push_str("00");

        // Push sequence
        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);

    }

    // Push the vout count
    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // For each vout in the transaction
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

    // For each vin in the transaction
    for vin in &transaction.vin {
        if let Some(witness) = &vin.witness {
            // Serialize the number of stack items in the witness using CompactSize
            let stack_items_bytes = compact_size_as_bytes(witness.len());
            serialized_tx.push_str(&hex::encode(&stack_items_bytes));

            // For each item in the witness
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

    // Return the serialized tx
    serialized_tx
}

// Compact size helper method
/// This function will return the compact size of a given number of bytes
pub fn compact_size_as_bytes(size: usize) -> Vec<u8> {
    // Match the size of the bytes
    match size {

        // If the size is less than 0xfd, return the size as a single byte
        0..=0xfc => vec![size as u8],
        0xfd..=0xffff => {
            // If the size is between 0xfd and 0xffff, return the size as a 2-byte little-endian
            let mut bytes = vec![0xfd];
            bytes.extend_from_slice(&(size as u16).to_le_bytes());
            bytes
        },
        // If the size is between 0x10000 and 0xffffffff, return the size as a 4-byte little-endian
        0x10000..=0xffffffff => {
            let mut bytes = vec![0xfe];
            bytes.extend_from_slice(&(size as u32).to_le_bytes());
            bytes
        },
        // If the size is greater than 0xffffffff, return the size as an 8-byte little-endian
        _ => {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&(size as u64).to_le_bytes());
            bytes
        },
    }
}

// File io operations
/// This function constructs the block. It adds the header, coinbase tx and other txs to the output file
pub fn write_block_to_file(serialized_header: &[u8], serialized_cb_tx: &[u8], block_txs: &[TransactionForProcessing]) {
    fs::write("../output.txt", "").unwrap();  // Clear the output file

    // Append the serialized header and coinbase tx to the output file
    append_to_file("../output.txt", &hex::encode(serialized_header)).unwrap();
    append_to_file("../output.txt", &hex::encode(serialized_cb_tx)).unwrap();

    // Append the txids of the block txs to the output file
    for tx in block_txs {
        append_to_file("../output.txt", &tx.txid).unwrap();
    }
}

/// This function will create the file output.txt and write contents to it
pub fn append_to_file(filename: &str, contents: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;

    writeln!(file, "{}", contents)?;
    Ok(())
}

// Hashing functions
/// This function takes in data and returns a ripemd160 hash
pub fn ripemd160(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Takes in data and returns a sha256 hash
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// This function will double sha256 hash the input
pub fn double_sha256(input: Vec<u8>) -> [u8; 32] {
    let first_hash = sha256(input);
    let second_hash = sha256(first_hash);
    second_hash.try_into().expect("Expected a Vec<u8> of length 32")
}

/// This function will get the tx ready for signing by removing the scriptsig and adding the
/// scriptpubkey to the scriptsig field and adding the sighash to the transaction
pub fn get_tx_readyfor_signing_legacy(transaction : &mut Transaction) -> Transaction {
    // Get the signature and public key from the scriptsig
    let scriptsig = &transaction.vin[0].scriptsig;
    let (signature, _pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig).unwrap();

    // Removing the scriptsig for each vin and adding the scriptpubkey to the scriptsig field
    for vin in transaction.vin.iter_mut() {
        vin.scriptsig = String::new();
        vin.scriptsig = vin.prevout.scriptpubkey.clone();
    }

    // Using the last two bytes of the signature as the sighash type for now
    let sighash_type = &signature[signature.len()-2..];

    // Hard coding the sighash type for now
    let sighash = format!("{}000000", sighash_type);

    // Adding the sighash to the transaction
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
pub fn get_segwit_tx_message(
    transaction: &mut Transaction,
    vin_index: usize,
    pubkey_hash: &str,
    sighash_type: u8) ->  Result<String, Box<dyn Error>> {
    let tx = transaction.clone();

    // Serialize the version field of the tx little endian
    let version = tx.version.to_le_bytes();
    let version = hex::encode(version);

    // Serialize and hash txid+vout for each vin
    let mut input_bytes = Vec::new();
    let mut sequences_bytes = Vec::new();

    // For each input in the transaction
    for vin in tx.vin.iter() {
        // Serialize the txid and vout
        let txid_bytes = hex::decode(vin.txid.clone()).map_err(|e| e.to_string())?;
        let reversed_txid_bytes: Vec<u8> = txid_bytes.into_iter().rev().collect();

        let vout_bytes = vin.vout.to_le_bytes();

        // And push them to the input_bytes
        input_bytes.extend_from_slice(&reversed_txid_bytes);
        input_bytes.extend_from_slice(&vout_bytes);

        // Same thing with sequence
        let sequence_bytes = vin.sequence.to_le_bytes();
        sequences_bytes.extend_from_slice(&sequence_bytes);
    }

    // Hash the input and sequences bytes
    let input_hash = double_sha256(input_bytes);
    let sequences_hash = double_sha256(sequences_bytes);

    //  Serialize the txid+vout for the specific input
    // Vin gets the specific input
    let vin = &tx.vin[vin_index];

    // Get the txid and reverse the bytes
    let txid_bytes = hex::decode(vin.txid.clone()).unwrap();
    let txid = reverse_bytes(txid_bytes);

    // Get the vout and convert to little endian bytes
    let vout = vin.vout.to_le_bytes();
    let vout = hex::encode(vout);

    // Format the input (txid+vout)
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

    // Initialize the output hash
    let mut output_bytes = Vec::new();

    // For the outputs in the transaction
    for vout in tx.vout.iter() {
        // Get the amount in sats and push it
        let amount_le = vout.value.to_le_bytes();
        output_bytes.extend_from_slice(&amount_le);

        // Get the scriptpubkey size and push it
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let scriptpubkey_size_bytes = compact_size_as_bytes(scriptpubkey_size);
        output_bytes.extend_from_slice(&scriptpubkey_size_bytes);

        // Get the scriptpubkey in bytes
        let scriptpubkey = vout.scriptpubkey.clone();
        // This is the scriptpubkey in bytes then push it
        let scriptpubkey_bytes = hex::decode(scriptpubkey).map_err(|e| e.to_string())?;
        output_bytes.extend_from_slice(&scriptpubkey_bytes);
    }

    // Hash the output bytes
    let output_hash = double_sha256(output_bytes);

    // Locktime
    let locktime = tx.locktime.to_le_bytes();
    let locktime = hex::encode(locktime);

    // Need to add the sighash type to the preimage
    // Convert the sighash type to u32
    let sighash_type_u32 = u32::from_le(sighash_type as u32);
    // Format the sighash type as a hex string
    let formatted_sighash = hex::encode(sighash_type_u32.to_le_bytes());

    // Preimage or message to be signed
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

    // Return the preimage
    Ok(preimage)
}

/// This function gets the signature and public key from the scriptsig of a legacy transaction
pub fn get_signature_and_publickey_from_scriptsig(scriptsig: &str) -> Result<(String, String), Box<dyn Error>> {
    // Convert the scriptsig hex string to bytes
    let scriptsig_bytes = hex::decode(scriptsig)?;

    // Initialize the index and the vector to hold the signature and public key
    let mut index = 0;
    let mut sig_and_pubkey_vec = Vec::new();

    // Loop through the scriptsig bytes to parse
    while index < scriptsig_bytes.len() {
        // Check if the index is greater than the length of the scriptsig bytes
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

        // Push the data to the sig_and_pubkey_vec
        sig_and_pubkey_vec.push(hex::encode(data));
    }
    // Checking if the sig_and_pubkey_vec has two elements if not fail
    if sig_and_pubkey_vec.len() != 2 {
        return Err(format!("Expected 2 elements, found {}", sig_and_pubkey_vec.len()).into());
    }

    // Return the signature and public key
    Ok((sig_and_pubkey_vec[0].clone(), sig_and_pubkey_vec[1].clone()))
}


/// This function will reverse the bytes and return a hex string
pub fn reverse_bytes(mut bytes: Vec<u8>) -> String {
    bytes.reverse();
    hex::encode(bytes)
}

pub fn calculate_transaction_weight(tx: &Transaction) -> u64 {
    // Serialized tx size without witness
    let base_size = serialize_tx(tx).len() as u64;

    // Serialized tx size with witness
    let total_size = serialized_segwit_tx(tx).len() as u64;

    // Calculate weight of the transaction
    let tx_weight = base_size * 1.8 as u64 + total_size;

    tx_weight   // Return the weight of the transaction
}
