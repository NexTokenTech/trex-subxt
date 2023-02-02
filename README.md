#### 1.Install SGX Environment
[linux-sgx](https://github.com/intel/linux-sgx)

#### 2.Install subxt-cli:
``` rust
cargo install subxt-cli
``` 

#### 3.Save the encoded metadata to a file:
``` rust
subxt metadata -f bytes > metadata.scale
``` 

#### 4.Usage
``` rust
./target/release/trex-subxt -n "host:port" -t "account_path" -s "seed.yml_file_path(e.g. ./src/seed.yml)"
``` 
