use sp_keyring::AccountKeyring;
use subxt::{
    tx::PairSigner,
    OnlineClient,
    PolkadotConfig,
    ext::sp_runtime::AccountId32
};
use subxt::ext::sp_core::crypto::Ss58Codec;

use std::fs;
use clap::Parser;

/// Arguments for the cli.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(short = 'n', long, default_value_t = String::from("ws://127.0.0.1:9944"))]
    node_host: String,
    #[clap(short = 't', long, default_value_t = String::from("tee_account_id.txt"))]
    tee_account_file: String
}

#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod trex_node {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    // parse arguments
    let args = Args::parse();
    let contents = fs::read_to_string(args.tee_account_file).expect("fail to read");

    let accountid = AccountId32::from_ss58check(&contents).unwrap();
    println!("{:?}",accountid);
    let signer = PairSigner::new(AccountKeyring::Alice.pair());
    let dest = accountid.into();

    // Create a client to use:
    let ws_url = args.node_host;
    let api = OnlineClient::<PolkadotConfig>::from_url(ws_url.to_string()).await?;
    // Create a transaction to submit:
    let tx = trex_node::tx()
        .balances()
        .transfer(dest, 123_456_789_012_345);

    // Submit the transaction with default params:
    let hash = api.tx().sign_and_submit_default(&tx, &signer).await?;

    println!("Balance transfer extrinsic submitted: {}", hash);

    Ok(())
}
