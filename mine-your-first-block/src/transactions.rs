use serde::Deserialize;

// Transaction struct that may be overcomplicated right now. We will see
#[derive(Debug, Deserialize, Clone)]
pub struct Transaction {
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    pub sighash: Option<String>,
}

// This struct is used to store the transaction and its fee for processing into the block
#[derive(Clone)]
pub struct TransactionForProcessing {
    pub transaction: Transaction,
    pub txid: String,
    pub wtxid: Option<String>,
    pub fee: u64,
    pub is_p2wpkh: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    pub prevout: Prevout,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Prevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Vout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32
}