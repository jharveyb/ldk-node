// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Logging-related objects.

#[cfg(not(feature = "uniffi"))]
use core::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64_engine;
use base64::Engine;
use bitcoin::{constants::ChainHash, secp256k1::PublicKey};
use chrono::Utc;
use lightning::ln::msgs::{SocketAddress, UnsignedNodeAnnouncement};
use lightning::ln::wire::Message;
use lightning::ln::{msgs::UnsignedChannelUpdate, peer_handler::IgnoringMessageHandler};
use lightning::routing::gossip::{NodeAlias, NodeId};
pub use lightning::util::logger::Level as LogLevel;
use lightning::util::logger::{ExportMessageDirection, MessageExporter, MessageType};
pub(crate) use lightning::util::logger::{Logger as LdkLogger, Record as LdkRecord};
use lightning::util::ser::Writeable;
pub(crate) use lightning::{log_bytes, log_debug, log_error, log_info, log_trace};
use lightning_types::features::NodeFeatures;
use log::{Level as LogFacadeLevel, Record as LogFacadeRecord};
use twox_hash::xxhash3_64::Hasher as XX3Hasher;

/// A unit of logging output with metadata to enable filtering `module_path`,
/// `file`, and `line` to inform on log's source.
#[cfg(not(feature = "uniffi"))]
pub struct LogRecord<'a> {
	/// The verbosity level of the message.
	pub level: LogLevel,
	/// The message body.
	pub args: fmt::Arguments<'a>,
	/// The module path of the message.
	pub module_path: &'a str,
	/// The line containing the message.
	pub line: u32,
}

/// A unit of logging output with metadata to enable filtering `module_path`,
/// `file`, and `line` to inform on log's source.
///
/// This version is used when the `uniffi` feature is enabled.
/// It is similar to the non-`uniffi` version, but it omits the lifetime parameter
/// for the `LogRecord`, as the Uniffi-exposed interface cannot handle lifetimes.
#[cfg(feature = "uniffi")]
pub struct LogRecord {
	/// The verbosity level of the message.
	pub level: LogLevel,
	/// The message body.
	pub args: String,
	/// The module path of the message.
	pub module_path: String,
	/// The line containing the message.
	pub line: u32,
}

#[cfg(feature = "uniffi")]
impl<'a> From<LdkRecord<'a>> for LogRecord {
	fn from(record: LdkRecord) -> Self {
		Self {
			level: record.level,
			args: record.args.to_string(),
			module_path: record.module_path.to_string(),
			line: record.line,
		}
	}
}

#[cfg(not(feature = "uniffi"))]
impl<'a> From<LdkRecord<'a>> for LogRecord<'a> {
	fn from(record: LdkRecord<'a>) -> Self {
		Self {
			level: record.level,
			args: record.args,
			module_path: record.module_path,
			line: record.line,
		}
	}
}

/// Defines the behavior required for writing log records.
///
/// Implementors of this trait are responsible for handling log messages,
/// which may involve formatting, filtering, and forwarding them to specific
/// outputs.
#[cfg(not(feature = "uniffi"))]
pub trait LogWriter: Send + Sync {
	/// Log the record.
	fn log<'a>(&self, record: LogRecord<'a>);
}

/// Defines the behavior required for writing log records.
///
/// Implementors of this trait are responsible for handling log messages,
/// which may involve formatting, filtering, and forwarding them to specific
/// outputs.
/// This version is used when the `uniffi` feature is enabled.
/// It is similar to the non-`uniffi` version, but it omits the lifetime parameter
/// for the `LogRecord`, as the Uniffi-exposed interface cannot handle lifetimes.
#[cfg(feature = "uniffi")]
pub trait LogWriter: Send + Sync {
	/// Log the record.
	fn log(&self, record: LogRecord);
}

/// Defines a writer for [`Logger`].
pub(crate) enum Writer {
	/// Writes logs to the file system.
	FileWriter { file_path: String, max_log_level: LogLevel },
	/// Forwards logs to the `log` facade.
	LogFacadeWriter,
	/// Forwards logs to a custom writer.
	CustomWriter(Arc<dyn LogWriter>),
}

impl LogWriter for Writer {
	fn log(&self, record: LogRecord) {
		match self {
			Writer::FileWriter { file_path, max_log_level } => {
				if record.level < *max_log_level {
					return;
				}

				let log = format!(
					"{} {:<5} [{}:{}] {}\n",
					Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
					record.level.to_string(),
					record.module_path,
					record.line,
					record.args
				);

				fs::OpenOptions::new()
					.create(true)
					.append(true)
					.open(file_path)
					.expect("Failed to open log file")
					.write_all(log.as_bytes())
					.expect("Failed to write to log file")
			},
			Writer::LogFacadeWriter => {
				let mut builder = LogFacadeRecord::builder();

				match record.level {
					LogLevel::Gossip | LogLevel::Trace => builder.level(LogFacadeLevel::Trace),
					LogLevel::Debug => builder.level(LogFacadeLevel::Debug),
					LogLevel::Info => builder.level(LogFacadeLevel::Info),
					LogLevel::Warn => builder.level(LogFacadeLevel::Warn),
					LogLevel::Error => builder.level(LogFacadeLevel::Error),
				};

				#[cfg(not(feature = "uniffi"))]
				log::logger().log(
					&builder
						.target(record.module_path)
						.module_path(Some(record.module_path))
						.line(Some(record.line))
						.args(format_args!("{}", record.args))
						.build(),
				);
				#[cfg(feature = "uniffi")]
				log::logger().log(
					&builder
						.target(&record.module_path)
						.module_path(Some(&record.module_path))
						.line(Some(record.line))
						.args(format_args!("{}", record.args))
						.build(),
				);
			},
			Writer::CustomWriter(custom_logger) => custom_logger.log(record),
		}
	}
}

pub(crate) struct Logger {
	/// Specifies the logger's writer.
	writer: Writer,
}

impl Logger {
	/// Creates a new logger with a filesystem writer. The parameters to this function
	/// are the path to the log file, and the log level.
	pub fn new_fs_writer(file_path: String, max_log_level: LogLevel) -> Result<Self, ()> {
		if let Some(parent_dir) = Path::new(&file_path).parent() {
			fs::create_dir_all(parent_dir)
				.map_err(|e| eprintln!("ERROR: Failed to create log parent directory: {}", e))?;

			// make sure the file exists.
			fs::OpenOptions::new()
				.create(true)
				.append(true)
				.open(&file_path)
				.map_err(|e| eprintln!("ERROR: Failed to open log file: {}", e))?;
		}

		Ok(Self { writer: Writer::FileWriter { file_path, max_log_level } })
	}

	pub fn new_log_facade() -> Self {
		Self { writer: Writer::LogFacadeWriter }
	}

	pub fn new_custom_writer(log_writer: Arc<dyn LogWriter>) -> Self {
		Self { writer: Writer::CustomWriter(log_writer) }
	}
}

impl LdkLogger for Logger {
	fn log(&self, record: LdkRecord) {
		match &self.writer {
			Writer::FileWriter { file_path: _, max_log_level } => {
				if record.level < *max_log_level {
					return;
				}
				self.writer.log(record.into());
			},
			Writer::LogFacadeWriter => {
				self.writer.log(record.into());
			},
			Writer::CustomWriter(_arc) => {
				self.writer.log(record.into());
			},
		}
	}
}

/// UnsignedNodeAnnouncement, without the timestamp. If we index over this, we can detect when nodes
/// are rebroadcasting the same essential information.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct InnerNodeAnnouncement {
	/// The advertised features
	pub features: NodeFeatures,
	/// The `node_id` this announcement originated from (don't rebroadcast the `node_announcement` back
	/// to this node).
	pub node_id: NodeId,
	/// An RGB color for UI purposes
	pub rgb: [u8; 3],
	/// An alias, for UI purposes.
	///
	/// This should be sanitized before use. There is no guarantee of uniqueness.
	pub alias: NodeAlias,
	/// List of addresses on which this node is reachable
	pub addresses: Vec<SocketAddress>,
	/// Excess address data which was signed as a part of the message which we do not (yet) understand how
	/// to decode.
	///
	/// This is stored to ensure forward-compatibility as new address types are added to the lightning gossip protocol.
	pub excess_address_data: Vec<u8>,
}

impl From<&UnsignedNodeAnnouncement> for InnerNodeAnnouncement {
	fn from(msg: &UnsignedNodeAnnouncement) -> Self {
		InnerNodeAnnouncement {
			features: msg.features.clone(),
			node_id: msg.node_id,
			rgb: msg.rgb,
			alias: msg.alias,
			addresses: msg.addresses.clone(),
			excess_address_data: msg.excess_address_data.clone(),
		}
	}
}

/// UnsignedChannelUpdate, without the timestamp. If we index over this, we can detect when nodes
/// are rebroadcasting the same essential information.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct InnerChannelUpdate {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: ChainHash,
	/// The short channel ID
	pub short_channel_id: u64,
	/// Flags pertaining to this message.
	pub message_flags: u8,
	/// Flags pertaining to the channel, including to which direction in the channel this update
	/// applies and whether the direction is currently able to forward HTLCs.
	pub channel_flags: u8,
	/// The number of blocks such that if:
	/// `incoming_htlc.cltv_expiry < outgoing_htlc.cltv_expiry + cltv_expiry_delta`
	/// then we need to fail the HTLC backwards. When forwarding an HTLC, `cltv_expiry_delta` determines
	/// the outgoing HTLC's minimum `cltv_expiry` value -- so, if an incoming HTLC comes in with a
	/// `cltv_expiry` of 100000, and the node we're forwarding to has a `cltv_expiry_delta` value of 10,
	/// then we'll check that the outgoing HTLC's `cltv_expiry` value is at least 100010 before
	/// forwarding. Note that the HTLC sender is the one who originally sets this value when
	/// constructing the route.
	pub cltv_expiry_delta: u16,
	/// The minimum HTLC size incoming to sender, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The maximum HTLC value incoming to sender, in milli-satoshi.
	///
	/// This used to be optional.
	pub htlc_maximum_msat: u64,
	/// The base HTLC fee charged by sender, in milli-satoshi
	pub fee_base_msat: u32,
	/// The amount to fee multiplier, in micro-satoshi
	pub fee_proportional_millionths: u32,
	/// Excess data which was signed as a part of the message which we do not (yet) understand how
	/// to decode.
	///
	/// This is stored to ensure forward-compatibility as new fields are added to the lightning gossip protocol.
	pub excess_data: Vec<u8>,
}

impl From<&UnsignedChannelUpdate> for InnerChannelUpdate {
	fn from(msg: &UnsignedChannelUpdate) -> Self {
		Self {
			chain_hash: msg.chain_hash,
			short_channel_id: msg.short_channel_id,
			message_flags: msg.message_flags,
			channel_flags: msg.channel_flags,
			cltv_expiry_delta: msg.cltv_expiry_delta,
			htlc_minimum_msat: msg.htlc_minimum_msat,
			htlc_maximum_msat: msg.htlc_maximum_msat,
			fee_base_msat: msg.fee_base_msat,
			fee_proportional_millionths: msg.fee_proportional_millionths,
			excess_data: msg.excess_data.clone(),
		}
	}
}

// Build a CSV row from our message and forward to the inner writer.
fn export_record<T: core::fmt::Debug + MessageType>(
	logger: Arc<dyn LogWriter + 'static>, sender_node_id: PublicKey, msg: &Message<T>,
	direction: ExportMessageDirection,
) {
	let now = chrono::Utc::now().timestamp_micros();
	let recv_peer = sender_node_id.to_string();
	let mut send_ts = String::new();
	let mut node_id = String::new();
	let mut scid = String::new();

	// This func. should match on all types with arms in
	// lightning::ln::peer_handler::is_inbound_msg_for_export.
	// TODO: Unify these in some observer-common lib? So type field is less hacky
	let mut msg_hasher = XX3Hasher::new();
	let msg_type = match msg {
		Message::Ping(pi) => {
			pi.hash(&mut msg_hasher);
			"ping"
		},
		Message::Pong(po) => {
			po.hash(&mut msg_hasher);
			"pong"
		},
		// TODO: hash all msgs
		Message::ChannelAnnouncement(ca) => {
			scid = ca.contents.short_channel_id.to_string();
			ca.contents.hash(&mut msg_hasher);
			"ca"
		},
		Message::NodeAnnouncement(na) => {
			// Scale timestamp from secs to usecs.
			send_ts = ((na.contents.timestamp as u64) * 1000000).to_string();
			node_id = na.contents.node_id.to_string();
			InnerNodeAnnouncement::from(&na.contents).hash(&mut msg_hasher);
			"na"
		},
		Message::ChannelUpdate(cu) => {
			// Scale timestamp from secs to usecs.
			send_ts = ((cu.contents.timestamp as u64) * 1000000).to_string();
			scid = cu.contents.short_channel_id.to_string();
			InnerChannelUpdate::from(&cu.contents).hash(&mut msg_hasher);
			"cu"
		},
		_ => {
			println!("rust-lightning msg handler filter should not export this msg type");
			println!("wtf: {}, {:?}", msg.type_id(), msg);
			return;
		},
	};
	let inner_hash = msg_hasher.finish();
	// TODO: replace with to_string(), impl Display?
	let msg_dir = match direction {
		ExportMessageDirection::Inbound => "inbound",
		ExportMessageDirection::Outbound => "outbound",
		_ => todo!("rust-lightning should not export with this"),
	};

	let msg = msg.encode();
	let msg_size = msg.len();
	let msg_str = b64_engine.encode(&msg);

	// CSV string for our final Record. The logger will filter by module_path.
	let args = format_args!(
		"{now},{recv_peer},{msg_type},{msg_dir},{msg_size},{inner_hash},{msg_str},{send_ts},{node_id},{scid}",
	);
	let record = LogRecord {
		level: LogLevel::Gossip,
		module_path: "custom::gossip_collector",
		line: 0,
		args,
	};
	logger.log(record)
}

impl MessageExporter for Logger {
	// Ingest an LN wire message, annotate it with a timestamp + some parsed fields,
	// and pass it as a custom Record to the parent CustomWriter.
	fn export<T: core::fmt::Debug + MessageType>(
		&self, their_node_id: PublicKey, msg: &Message<T>, direction: ExportMessageDirection,
	) {
		if let Writer::CustomWriter(logger) = &self.writer {
			export_record(logger.clone(), their_node_id, msg, direction);
		}
	}

	fn export_bin<T: core::fmt::Debug + MessageType>(
		&self, their_node_id: PublicKey, msg: &T, direction: ExportMessageDirection,
	) {
		if let Writer::CustomWriter(logger) = &self.writer {
			// Imitate lightning::ln::peer_channel_encryptor::PeerChannelEncryptor::encrypt_message().
			// Write our (unencrypted) message with a type prefix; T.V. in the C.P.T.
			// We assume most messages will be below 2KB.
			let mut msg_buf = Vec::with_capacity(2 * 1024);
			lightning::ln::wire::write(msg, &mut msg_buf).expect("Failed to encode message");

			// Imitate lightning::ln::wire::read_message_encoded_with_write() test.
			// Decode the buffer to a Message enum. Infallible is the custom message
			// type parameter since we're only handling standard Lightning messages
			// by using IgnoringMessageHandler here.
			let decoded_msg =
				lightning::ln::wire::read(&mut msg_buf.as_slice(), &IgnoringMessageHandler {})
					.expect("Failed to decode message");

			export_record(logger.clone(), their_node_id, &decoded_msg, direction);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::{Message, Secp256k1};
	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use std::convert::Infallible;
	use std::sync::Mutex;

	use bitcoin::constants::ChainHash;
	use ExportMessageDirection::{Inbound, Outbound};

	use bitcoin::network::Network;
	use lightning::ln::msgs;
	use lightning::ln::types::ChannelId;
	use lightning::ln::wire;

	const MSG_PARTS: usize = 10;

	struct MockMessageExporter {
		exported_logs: Mutex<Vec<String>>,
	}

	impl LogWriter for MockMessageExporter {
		fn log(&self, record: LogRecord) {
			self.exported_logs.lock().unwrap().push(record.args.to_string());
		}
	}

	fn new_mock_exporter() -> (Arc<MockMessageExporter>, Logger) {
		let mock_exporter = Arc::new(MockMessageExporter { exported_logs: Mutex::new(Vec::new()) });
		let logger = Logger::new_custom_writer(mock_exporter.clone());

		(mock_exporter, logger)
	}

	fn verify_logger_entry_count(exporter: Arc<MockMessageExporter>, msg_count: usize) {
		let logs = exporter.exported_logs.lock().unwrap();
		assert_eq!(logs.len(), msg_count);
	}

	fn verify_logger_exports(exporter: Arc<MockMessageExporter>, msg_type: &str, msg_count: usize) {
		verify_logger_entry_count(exporter.clone(), msg_count);

		let logs = exporter.exported_logs.lock().unwrap();
		let log_entry = &logs[0];
		assert!(log_entry.contains(msg_type), "Log should contain message type '{msg_type}'");
		assert!(log_entry.contains("inbound"), "Log should contain direction 'inbound'");
		let log_entry = &logs[1];
		assert!(log_entry.contains(msg_type), "Log should contain message type '{msg_type}'");
		assert!(log_entry.contains("outbound"), "Log should contain direction 'outbound'");
		let msg_parts = log_entry.split(',').count();
		assert!(msg_parts == MSG_PARTS, "Log should contain {MSG_PARTS} parts");
	}

	// Stolen from lightning::ln::msgs::tests unit tests.
	macro_rules! get_keys_from {
		($slice: expr, $secp_ctx: expr) => {{
			let privkey = SecretKey::from_slice(&<Vec<u8>>::from_hex($slice).unwrap()[..]).unwrap();
			let pubkey = PublicKey::from_secret_key(&$secp_ctx, &privkey);
			(privkey, pubkey)
		}};
	}

	macro_rules! get_sig_on {
		($privkey: expr, $ctx: expr, $string: expr) => {{
			let sighash = Message::from_digest_slice(&$string.into_bytes()[..]).unwrap();
			$ctx.sign_ecdsa(&sighash, &$privkey)
		}};
	}

	fn static_keypair() -> (SecretKey, PublicKey) {
		let secp_ctx = Secp256k1::new();
		get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx)
	}

	fn do_encoding_channel_update(
		direction: bool, disable: bool, excess_data: bool,
	) -> msgs::ChannelUpdate {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!(
			"0101010101010101010101010101010101010101010101010101010101010101",
			secp_ctx
		);
		let sig_1 =
			get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let unsigned_channel_update = msgs::UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Bitcoin),
			short_channel_id: 2316138423780173,
			timestamp: 20190119,
			message_flags: 1, // Only must_be_one
			channel_flags: if direction { 1 } else { 0 } | if disable { 1 << 1 } else { 0 },
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1000000,
			htlc_maximum_msat: 131355275467161,
			fee_base_msat: 10000,
			fee_proportional_millionths: 20,
			excess_data: if excess_data { vec![0, 0, 0, 0, 59, 154, 202, 0] } else { Vec::new() },
		};
		let channel_update =
			msgs::ChannelUpdate { signature: sig_1, contents: unsigned_channel_update };
		let encoded_value = channel_update.encode();
		let mut target_value = <Vec<u8>>::from_hex("d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		target_value.append(
			&mut <Vec<u8>>::from_hex(
				"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
			)
			.unwrap(),
		);
		target_value.append(&mut <Vec<u8>>::from_hex("00083a840000034d013413a7").unwrap());
		target_value.append(&mut <Vec<u8>>::from_hex("01").unwrap());
		target_value.append(&mut <Vec<u8>>::from_hex("00").unwrap());
		if direction {
			let flag = target_value.last_mut().unwrap();
			*flag = 1;
		}
		if disable {
			let flag = target_value.last_mut().unwrap();
			*flag |= 1 << 1;
		}
		target_value
			.append(&mut <Vec<u8>>::from_hex("009000000000000f42400000271000000014").unwrap());
		target_value.append(&mut <Vec<u8>>::from_hex("0000777788889999").unwrap());
		if excess_data {
			target_value.append(&mut <Vec<u8>>::from_hex("000000003b9aca00").unwrap());
		}
		assert_eq!(encoded_value, target_value);
		channel_update
	}

	#[test]
	fn export_ping() {
		let (mock_exporter, logger) = new_mock_exporter();
		let (_, pubkey) = static_keypair();

		let ping_msg = msgs::Ping { ponglen: 64, byteslen: 64 };

		logger.export_bin(pubkey, &ping_msg, Inbound);
		logger.export(pubkey, &wire::Message::Ping::<Infallible>(ping_msg), Outbound);

		let expected_msg_type = "ping";
		verify_logger_exports(mock_exporter.clone(), expected_msg_type, 2);
	}

	#[test]
	fn export_channel_update() {
		let (mock_exporter, logger) = new_mock_exporter();
		let (_, pubkey) = static_keypair();

		let chan_update = do_encoding_channel_update(true, true, true);

		logger.export_bin(pubkey, &chan_update, Inbound);
		logger.export(pubkey, &wire::Message::ChannelUpdate::<Infallible>(chan_update), Outbound);

		let expected_msg_type = "cu";
		verify_logger_exports(mock_exporter.clone(), expected_msg_type, 2);
	}

	#[test]
	fn export_stfu() {
		let (mock_exporter, logger) = new_mock_exporter();
		let (_, pubkey) = static_keypair();

		let stfu = msgs::Stfu { channel_id: ChannelId::from_bytes([2; 32]), initiator: true };

		logger.export_bin(pubkey, &stfu, Inbound);
		logger.export(pubkey, &wire::Message::Stfu::<Infallible>(stfu), Outbound);

		// Msgs of unsupported type are rejected.
		verify_logger_entry_count(mock_exporter.clone(), 0);
	}
}
