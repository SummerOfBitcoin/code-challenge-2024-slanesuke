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


/// This function calcluates the merkle root. It putes txids in natural byte order then
/// Hashes the tree
pub fn get_merkle_root(txids: Vec<String>) -> String {
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

/// This function deserialize a tx from the mempool module
pub fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    let tx: Transaction = serde_json::from_reader(reader).unwrap();

    // return a transaction if the deserialization is successful
    tx
}


//  Serialization functions
/// This function serializes the block header because it's a bit different from a reg tx
pub fn serialize_block_header(block_header: &BlockHeader) -> Vec<u8> {
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

//  Transaction serializations
/// This function will serialize a transaction into a string of hex bytes
pub fn serialize_tx(transaction: &Transaction) -> String {
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
pub fn serialized_segwit_tx(transaction: &Transaction) -> String {
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
pub fn serialized_segwit_wtx(transaction: &Transaction) -> String {
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

// Compact size helper method
/// This function will return the compact size of a given number of bytes
pub fn compact_size_as_bytes(size: usize) -> Vec<u8> {
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

// File io operations
/// This function constructs the block. It adds the header, coinbase tx and other txs to the output file
pub fn write_block_to_file(serialized_header: &[u8], serialized_cb_tx: &[u8], block_txs: &[TransactionForProcessing]) {
    fs::write("../output.txt", "").unwrap();  // Clear the output file
    append_to_file("../output.txt", &hex::encode(serialized_header)).unwrap();
    append_to_file("../output.txt", &hex::encode(serialized_cb_tx)).unwrap();
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
/// Hashing Functions
// Takes in data and returns a ripemd160 hash
pub fn ripemd160(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Takes in data and returns a sha256 hash
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn double_sha256(input: Vec<u8>) -> [u8; 32] {
    let first_hash = sha256(input);
    let second_hash = sha256(first_hash);
    second_hash.try_into().expect("Expected a Vec<u8> of length 32")
}


// Constructing the message that is needed to validate  singnatue
/// Function to get segwit message
pub fn get_segwit_tx_message(
    transaction: &mut Transaction,
    vin_index: usize,
    pubkey_hash: &str,
    sighash_type: u8) ->  Result<String, Box<dyn Error>> {
    let tx = transaction.clone();


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

/// This function gets the signature and public key from the scriptsig of a legacy transaction
pub fn get_signature_and_publickey_from_scriptsig(scriptsig: &str) -> Result<(String, String), Box<dyn Error>> {
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

/// This function will get the tx ready for signing by removing the scriptsig and adding the
/// scriptpubkey to the scriptsig field and adding the sighash to the transaction
pub fn get_tx_readyfor_signing_legacy(transaction : &mut Transaction) -> Transaction {
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