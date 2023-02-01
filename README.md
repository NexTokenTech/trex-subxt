
#### 1.Install subxt-cli:
``` rust
cargo install subxt-cli
``` 

#### 2.Save the encoded metadata to a file:
``` rust
subxt metadata -f bytes > metadata.scale
``` 

#### 3.Usage
``` rust
./target/release/trex-account-funds -n "host:port" -t "account_path"
``` 
