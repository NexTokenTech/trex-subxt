mod utils;
use crate::utils::*;
use aes_gcm::{
	aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
	Aes256Gcm, Nonce,
};
use clap::Parser;
use codec::Encode;
use serde::{Deserialize, Serialize};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::{SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE};
use std::time::SystemTime;
use log::{debug, error};
use subxt::{
	ext::sp_core::{
		crypto::{AccountId32 as AccountId, Ss58Codec},
		sr25519, Pair,
	},
	tx::PairSigner,
	OnlineClient, PolkadotConfig,
};

use crate::trex_node::runtime_types::trex_primitives::KeyPiece;
/// Arguments for the cli.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[clap(short = 'n', long, default_value_t = String::from("ws://127.0.0.1:9944"))]
	node_host: String,
	#[clap(short = 't', long, default_value_t = String::from("tee_account_id.txt"))]
	tee_account_file: String,
	#[clap(short = 's', long, default_value_t = String::from("seed.yml"))]
	seed: String,
}

/// Seed of signature keypair for testing
#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
struct Seed {
	#[serde(with = "hex::serde")]
	hex: Vec<u8>,
}

#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod trex_node {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	tracing_subscriber::fmt::init();
	// parse arguments
	let args = Args::parse();

	// Create a client to use:
	let ws_url = args.node_host;
	let api = OnlineClient::<PolkadotConfig>::from_url(ws_url.to_string()).await?;

	// obtain enclave count through rpc
	let enclave_count_addr = trex_node::storage().tee().enclave_count();
	let enclave_count = api.storage().fetch(&enclave_count_addr, None).await?.unwrap_or(0u64);
	println!("{:?}", enclave_count);
	if enclave_count < 1 {
		println!("Enclaves not registered on-chain");
		return Ok(())
	}

	// load testing seed file.
	let f = std::fs::File::open(&args.seed).unwrap();
	let seed: Seed = serde_yaml::from_reader(f).expect("Could not read seed.");
	let signer = sr25519::Pair::from_seed_slice(seed.hex.as_slice()).unwrap();
	let pubkey = signer.public();
	let tx_sender_account_id = AccountId::from(*pubkey.as_array_ref());
	println!("Account ID: {:?}", tx_sender_account_id.to_ss58check());

	// get ras pubkey and enclave account id, will insert into ShieldedKey.
	let enclave_addr = trex_node::storage().tee().enclave_registry(1u64);
	let enclave_op = api.storage().fetch(&enclave_addr, None).await?;
	let enclave = enclave_op.unwrap();
	let tee_account_id = enclave.pubkey;

	// transmute shielding_key to rsa_pubkey
	let pubkey: [u8; SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE] =
		enclave.shielding_key.clone().try_into().unwrap();
	let rsa_pubkey: Rsa3072PubKey = unsafe { std::mem::transmute(pubkey) };

	// get aes key
	let mut key_slice = [0u8; KEY_SIZE];
	let nonce_slice = AES_NONCE;
	OsRng.fill_bytes(&mut key_slice);
	let cipher =
		Aes256Gcm::new_from_slice(&key_slice).expect("Random key slice does not match the size!");
	let aes_nonce = Nonce::from_slice(nonce_slice);

	// create cipher text
	let ciphertext = cipher.encrypt(aes_nonce, b"a test cipher text".as_ref()).unwrap();

	// encrypt private key through rsa pubkey
	let mut key_piece = [0u8; AES_KEY_MAX_SIZE];
	let (first, second) = key_piece.split_at_mut(KEY_SIZE);
	first.copy_from_slice(&key_slice);
	second.copy_from_slice(nonce_slice);

	// generate hash of Sha256PrivateKeyTime which contains key_piece and release_time
	let release_time = release_time();
	let key_time = Sha256PrivateKeyTime {
		aes_private_key: key_piece.clone().to_vec(),
		timestamp: release_time.clone(),
	};
	let key_time_hash = key_time.hash();

	// construct key hash struct for shielding
	let key_hash =
		Sha256PrivateKeyHash { aes_private_key: key_piece.clone().to_vec(), hash: key_time_hash };
	let key_hash_encode = key_hash.encode();

	// shielding key hash struct
	let mut cipher_private_key: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&key_hash_encode, &mut cipher_private_key)
		.expect("Cannot shield key pieces!");

	// construct key_pieces
	let key: ShieldedKey = cipher_private_key;
	let key_piece = KeyPiece { holder: tee_account_id.clone(), shielded: key.clone() };
	let key_pieces = vec![key_piece];

	// send trex data to trex node
	let tx = trex_node::tx()
		.trex()
		.send_trex_data(ciphertext.clone(), release_time, key_pieces);
	let signer_send = PairSigner::new(signer);
	let tx_submit_hash = api.tx().sign_and_submit_default(&tx, &signer_send).await?;
	println!("trex send data extrinsic submitted: {}", tx_submit_hash);

	Ok(())
}

/// Release time: take the current time and push it back 60s
fn release_time() -> u64 {
	let now = SystemTime::now();
	let mut now_time: u64 = 0;
	match now.duration_since(SystemTime::UNIX_EPOCH) {
		Ok(elapsed) => {
			// it prints '2'
			debug!("{}", elapsed.as_secs());
			now_time = elapsed.as_secs();
		},
		Err(e) => {
			// an error occurred!
			error!("Error: {:?}", e);
		},
	};
	// convert to milliseconds!
	now_time * 1000 + ONE_MINUTE
}
