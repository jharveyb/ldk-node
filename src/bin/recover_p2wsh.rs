// This file is Copyright its original authors, licensed under the terms of the MIT/Apache 2.0
// licenses. See the COPYING-MIT and COPYING-APACHE files at the project root for full license info.

//! Recovery tool for P2WSH `to_remote` outputs from counterparty force-closes.
//!
//! When a node database is lost after a channel is funded, the peer may force-close and send our
//! funds to a P2WSH output. Because `ChannelMonitor` state is gone, the node cannot sweep it
//! automatically.
//!
//! Since ldk-node sets `v2_remote_key_derivation = true`, the `to_remote` output is always one
//! of 1000 deterministic P2WSH scripts derived purely from the seed. This tool identifies the
//! correct key and produces a signed spending transaction in hex.
//!
//! Usage:
//!   recover-p2wsh \
//!     --seed-path <path>        64-byte seed file (keys_seed)
//!     --network <mainnet|testnet|signet|regtest>
//!     --spk <hex>               P2WSH scriptpubkey of the UTXO
//!     --txid <txid>             txid of the commitment tx holding the output
//!     --vout <n>                output index of the UTXO
//!     --amount-sats <n>         value of the UTXO in satoshis
//!     --dest-address <addr>     destination address for recovered funds
//!     --feerate <sat/vbyte>     fee rate for the spending transaction
//!
//! The tool prints the signed raw transaction hex, which can be broadcast via:
//!   bitcoin-cli sendrawtransaction <hex>
//!   (or any Esplora/mempool.space broadcast endpoint)

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::opcodes;
use bitcoin::consensus::verify_transaction;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
	Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
	Witness,
};
use lightning::sign::KeysManager;

fn usage() -> ! {
	eprintln!(
		"Usage: recover-p2wsh \
		<mnemonic> <outpoint> <input_sats> <spk>
        --network <mainnet|testnet|signet|regtest> \
        --dest-address <addr> \
        --feerate <sat/vbyte> \
	--run"
	);
	std::process::exit(1);
}

fn parse_args() -> Args {
	let args: Vec<String> = std::env::args().collect();
	if args.len() < 4 {
		usage();	
	}

	let mnemonic = args[1].clone();
	let outpoint = OutPoint::from_str(&args[2]).expect("Malformed outpoint");
	let input_sats = args[3].parse::<u64>().expect("Malformed input sat amt");
	let spk_hex = args[4].clone();
	let mut network = None;
	let mut dest_address = None;
	let mut feerate = None;
	let mut check = true;

	let mut i = 5;
	while i < args.len() {
		match args[i].as_str() {
			"--network" => {
				network = Some(args[i + 1].clone());
				i += 2
			},
			"--dest-address" => {
				dest_address = Some(args[i + 1].clone());
				i += 2
			},
			"--feerate" => {
				feerate = Some(args[i + 1].parse::<u64>().expect("feerate must be a number"));
				i += 2
			},
			"--run" => {
				check = false;
				i += 1
			}
			_ => {
				eprintln!("Unknown argument: {}", args[i]);
				usage();
			},
		}
	}

	let checked_network = if let Some(network) = network {
	// Parse network
	match network.as_str() {
		"mainnet" | "bitcoin" => Network::Bitcoin,
		"testnet" => Network::Testnet,
		"signet" => Network::Signet,
		"regtest" => Network::Regtest,
		n => {
			eprintln!("Unknown network: {}", n);
			usage();
		},
	}
	} else {
		usage();
	};


	Args {
		mnemonic,
		network: checked_network,
		spk_hex,
		outpoint,
		input_sats,
		dest_address: dest_address.unwrap_or_else(|| usage()),
		feerate: feerate.unwrap_or_else(|| usage()),
		check,
	}
}

struct Args {
	mnemonic: String,
	network: Network,
	spk_hex: String,
	outpoint: OutPoint,
	input_sats: u64,
	dest_address: String,
	feerate: u64,
	check: bool,
}

fn main() {
	let args = parse_args();


	// Load 64-byte seed
	let mnemonic: Mnemonic = args.mnemonic.parse().unwrap_or_else(|e| {
		eprintln!("Invalid mnemonic: {}", e);
		std::process::exit(1);
	});
	let bip39_seed = mnemonic.to_seed("");
	println!("Network: {:?}", args.network);

	// Derive the 32-byte LDK seed: same path as builder.rs
	//   Xpriv::new_master(network, &seed_bytes) → xprv.private_key.secret_bytes()
	let secp = Secp256k1::new();
	let xprv =
		Xpriv::new_master(args.network, &bip39_seed).expect("Failed to derive BIP32 master from seed");
	let ldk_seed: [u8; 32] = xprv.private_key.secret_bytes();

	// Create KeysManager with v2_remote_key_derivation=true (matches ldk-node's WalletKeysManager)
	// starting_time values are irrelevant for v2 static payment keys
	let keys_manager = KeysManager::new(&ldk_seed, 0, 0, true);

	// Enumerate all 2000 possible scriptpubkeys: 1000 keys × (non-anchor P2WPKH, anchor P2WSH)
	let all_spks = keys_manager.possible_v2_counterparty_closed_balance_spks(&secp);

	// Parse the target scriptpubkey
	let target_spk = ScriptBuf::from_hex(&args.spk_hex).expect("Invalid scriptpubkey hex (--spk)");

	// Find the matching index
	let matching_idx = all_spks.iter().position(|s| s == &target_spk).expect(
		"Scriptpubkey not found among the 2000 v2 static payment scripts.\n\
             Possible reasons:\n\
             - Wrong seed file\n\
             - Channel was opened before v2_remote_key_derivation support (older ldk-node)\n\
             - Wrong network\n\
             - The UTXO is not a to_remote output (e.g. it may be to_local, HTLC, or anchor)",
	);

	// Entries are interleaved: [non-anchor(key0), anchor(key0), non-anchor(key1), anchor(key1), ...]
	// Anchor (P2WSH) entries are at odd indices; each key covers 2 indices.
	if matching_idx % 2 == 0 {
		panic!(
			"Matched a non-anchor (P2WPKH) entry at index {}. \
             This tool handles P2WSH (anchor) outputs. \
             If this is a P2WPKH output, you can sweep it directly with the node wallet.",
			matching_idx
		);
	}
	let key_child_idx = (matching_idx / 2) as u32;

	eprintln!(
		"Found matching scriptpubkey at v2 key index {} (static_payment_key child {})",
		matching_idx, key_child_idx
	);

	// Derive the private key:
	//   KeysManager::new() → Xpriv::new_master(Testnet, ldk_seed) → derive(H(8)) → derive(H(idx))
	// Note: LDK's KeysManager::new() always uses Network::Testnet internally for BIP32 derivation
	// (network doesn't affect the private key bytes, only the serialization prefix)
	let ldk_internal_root =
		Xpriv::new_master(Network::Testnet, &ldk_seed).expect("Failed to derive LDK internal root");
	// KeysManager::new(), STATIC_PAYMENT_KEY_INDEX	
	let static_payment_key = ldk_internal_root
		.derive_priv(&secp, &[ChildNumber::Hardened { index: 8 }])
		.expect("Failed to derive static_payment_key");
	let child_key: SecretKey = static_payment_key
		.derive_priv(&secp, &[ChildNumber::Hardened { index: key_child_idx }])
		.expect("Failed to derive child key")
		.private_key;
	let payment_pubkey = child_key.public_key(&secp);

	// Build the witness script: <payment_pubkey> OP_CHECKSIGVERIFY 1 OP_CSV
	let witness_script = Builder::new()
		.push_slice(payment_pubkey.serialize())
		.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
		.push_int(1)
		.push_opcode(opcodes::all::OP_CSV)
		.into_script();

	// Verify: P2WSH of witness_script must equal the target scriptpubkey
	let computed_spk = witness_script.to_p2wsh();
	assert_eq!(
		computed_spk, target_spk,
		"Witness script P2WSH hash does not match target scriptpubkey — internal error"
	);
	eprintln!("Witness script verified: SHA256(witness_script) matches target scriptpubkey");
	eprintln!("Payment pubkey: {}", payment_pubkey);

	// Estimate transaction size and compute output amount
	// P2WSH input: 41 bytes non-witness + witness overhead
	// Witness: [sig (~73 bytes), witness_script (~35 bytes)] + lengths = ~112 bytes witness
	// Non-witness: version(4) + vin_count(1) + outpoint(36) + scriptSig_len(1) + sequence(4) +
	//              vout_count(1) + value(8) + spk_len(1) + spk(22) + locktime(4) = 82 bytes
	// Segwit discount: witness bytes / 4
	// Total vbytes ≈ 82 + ceil(112 / 4) = 82 + 28 = 110 vbytes (conservative estimate)
	let estimated_vbytes: u64 = 120; // slightly conservative
	let fee_sats = args.feerate * estimated_vbytes;
	if fee_sats >= args.input_sats {
		panic!(
			"Fee ({} sats at {} sat/vbyte × {} vbytes) exceeds input amount ({} sats)",
			fee_sats, args.feerate, estimated_vbytes, args.input_sats
		);
	}
	let output_sats = args.input_sats - fee_sats;

	// Parse destination address and txid
	let dest_addr = Address::from_str(&args.dest_address)
		.expect("Invalid destination address")
		.require_network(args.network)
		.expect("Destination address is for a different network");

	// Build the spending transaction
	// sequence = 1 to satisfy the OP_1 OP_CSV in the witness script
	let mut tx = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: args.outpoint,
			script_sig: ScriptBuf::new(),
			sequence: Sequence(1),
			witness: Witness::default(),
		}],
		output: vec![TxOut {
			value: Amount::from_sat(output_sats),
			script_pubkey: dest_addr.script_pubkey(),
		}],
	};

	// Compute the P2WSH sighash
	let sighash = SighashCache::new(&tx)
		.p2wsh_signature_hash(
			0,
			&witness_script,
			Amount::from_sat(args.input_sats),
			EcdsaSighashType::All,
		)
		.expect("Failed to compute sighash");

	// Sign
	let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &child_key);
	let mut sig_bytes = sig.serialize_der().to_vec();
	sig_bytes.push(EcdsaSighashType::All as u8);

	// Assemble witness: [<sig>, <witness_script>]
	tx.input[0].witness = Witness::from_slice(&[sig_bytes.as_slice(), witness_script.as_bytes()]);
	let txo_fetcher = |outpoint: &OutPoint| -> Option<TxOut> { match outpoint {
		outpoint if outpoint == &args.outpoint => Some(TxOut {
			value: Amount::from_sat(args.input_sats),
			script_pubkey: target_spk.clone(),
		}),
		_ => None,
	}};
	verify_transaction(&tx, txo_fetcher).expect("TX failed verification");
	println!("Final TX:");
	println!("{:?}", tx);
	println!("Vsize: {}", tx.vsize());
	if args.check {
		println!("Found signing key for balance recovery, run with --run to build TX");
		return;
	}


	let tx_hex = serialize_hex(&tx);

	eprintln!("---");
	eprintln!("Input:  {} ({} sats)", args.outpoint, args.input_sats);
	eprintln!("Output: {} ({} sats, fee {} sats)", args.dest_address, output_sats, fee_sats);
	eprintln!("Txid:   {}", tx.compute_txid());
	eprintln!("---");
	eprintln!("Broadcast with: bitcoin-cli sendrawtransaction <hex>");
	eprintln!("Or POST to: https://mempool.space/api/tx (mainnet)");
	eprintln!("---");

	// Print the raw transaction hex to stdout for easy capture
	println!("{}", tx_hex);
}
