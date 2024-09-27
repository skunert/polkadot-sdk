// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains the [`OverheadCmd`] as entry point for the CLI to execute
//! the *overhead* benchmarks.

use super::remark_builders::*;
use crate::{
	extrinsic::{
		bench::{Benchmark, BenchmarkParams as ExtrinsicBenchmarkParams},
		ExtrinsicBuilder,
	},
	overhead::{
		cmd::ChainType::{Parachain, Relaychain, Unknown},
		fake_runtime_api,
		template::TemplateData,
	},
	shared::{self, GenesisBuilderPolicy, HostInfoParams, WeightParams},
};
use clap::{Args, Parser};
use codec::{Decode, Encode};
use fake_runtime_api::RuntimeApi as FakeRuntimeApi;
use frame_support::Deserialize;
use log::info;
use polkadot_parachain_primitives::primitives::Id as ParaId;
use polkadot_primitives::v8::PersistedValidationData;
use sc_block_builder::BlockBuilderApi;
use sc_chain_spec::{
	ChainSpec, ChainSpecExtension, GenericChainSpec, GenesisBlockBuilder,
};
use sc_cli::{CliConfiguration, ImportParams, Result, SharedParams};
use sc_client_api::{execution_extensions::ExecutionExtensions, UsageProvider};
use sc_client_db::{BlocksPruning, DatabaseSettings, DatabaseSource};
use sc_executor::WasmExecutor;
use sc_service::{new_client, new_db_backend, BasePath, ClientConfig, TFullClient, TaskManager};
use serde::Serialize;
use serde_json::{json, Value};
use sp_api::{ApiExt, CallApiAt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{
	crypto::AccountId32,
	traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode},
	OpaqueMetadata,
};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{traits::Block as BlockT, DigestItem, OpaqueExtrinsic};
use sp_state_machine::BasicExternalities;
use std::{
	borrow::Cow,
	fmt::Debug,
	path::PathBuf,
	sync::Arc,
};
use subxt::ext::futures;
use subxt_signer::{eth::Keypair as EthKeypair, DeriveJunction};

const DEFAULT_PARA_ID: u32 = 100;

/// Benchmark the execution overhead per-block and per-extrinsic.
#[derive(Debug, Parser)]
pub struct OverheadCmd {
	#[allow(missing_docs)]
	#[clap(flatten)]
	pub shared_params: SharedParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub import_params: ImportParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub params: OverheadParams,
}

/// Configures the benchmark, the post-processing and weight generation.
#[derive(Debug, Default, Serialize, Clone, PartialEq, Args)]
pub struct OverheadParams {
	#[allow(missing_docs)]
	#[clap(flatten)]
	pub weight: WeightParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub bench: ExtrinsicBenchmarkParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub hostinfo: HostInfoParams,

	/// Add a header to the generated weight output file.
	///
	/// Good for adding LICENSE headers.
	#[arg(long, value_name = "PATH")]
	pub header: Option<PathBuf>,

	/// Enable the Trie cache.
	///
	/// This should only be used for performance analysis and not for final results.
	#[arg(long)]
	pub enable_trie_cache: bool,

	#[arg(long, value_name = "PATH")]
	pub runtime: Option<PathBuf>,

	#[arg(long, default_value = sp_genesis_builder::DEV_RUNTIME_PRESET)]
	pub genesis_builder_preset: String,

	/// How to construct the genesis state.
	///
	/// Uses `GenesisBuilder::Spec` by default and  `GenesisBuilder::Runtime` if `runtime` is set.
	#[arg(long, value_enum)]
	pub genesis_builder: Option<GenesisBuilderPolicy>,

	#[arg(long)]
	pub config_variant: Option<ConfigVariant>,

	#[arg(long)]
	pub generate_accounts: Option<AccountType>,

	#[arg(long)]
	pub num_accounts: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Serialize)]
pub enum ConfigVariant {
	AddressIsMultiAddress,
	AddressIsAccountId,
	Eth,
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Serialize)]
pub enum AccountType {
	Sr25519,
	ECDSA,
}

/// Type of a benchmark.
#[derive(Serialize, Clone, PartialEq, Copy)]
pub(crate) enum BenchmarkType {
	/// Measure the per-extrinsic execution overhead.
	Extrinsic,
	/// Measure the per-block execution overhead.
	Block,
}

pub mod opaque {
	use sp_runtime::{generic, traits::BlakeTwo256, OpaqueExtrinsic};

	/// Block number
	pub type BlockNumber = u32;
	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, OpaqueExtrinsic>;
}

pub type HostFunctions = (
	cumulus_primitives_proof_size_hostfunction::storage_proof_size::HostFunctions,
	sp_io::SubstrateHostFunctions,
);

pub type OverheadClient = TFullClient<opaque::Block, FakeRuntimeApi, WasmExecutor<HostFunctions>>;

/// Creates inherent data for a given parachain ID.
///
/// This function constructs the inherent data required for block execution,
/// including the relay chain state and validation data. Not all of these
/// inherents are required for every chain. The runtime will pick the ones
/// it requires based on their identifier.
fn create_inherent_data<Client: UsageProvider<Block> + HeaderBackend<Block>, Block: BlockT>(
	client: &Arc<Client>,
	chain_type: &ChainType,
) -> InherentData {
	let genesis = client.usage_info().chain.best_hash;
	let header = client.header(genesis).unwrap().unwrap();

	let mut inherent_data = sp_inherents::InherentData::new();

	// Para inherent can only makes sense when we are handling a parachain.
	if let Parachain(para_id) = chain_type {
		// Data for parachain system inherent. Required for all FRAME-based parachains.
		let mut relay_state = cumulus_test_relay_sproof_builder::RelayStateSproofBuilder::default();
		relay_state.included_para_head = Some(header.encode().into());
		relay_state.para_id = ParaId::from(*para_id);

		let mut vfp = PersistedValidationData::default();
		let (root, proof) = relay_state.into_state_root_and_proof();
		vfp.relay_parent_storage_root = root;
		let para_data = cumulus_primitives_parachain_inherent::ParachainInherentData {
			validation_data: vfp,
			relay_chain_state: proof,
			downward_messages: Default::default(),
			horizontal_messages: Default::default(),
		};
		let _ = futures::executor::block_on(para_data.provide_inherent_data(&mut inherent_data));
	}

	// Parachain inherent that is used on relay chains to perform parachain validation.
	let para_inherent = polkadot_primitives::InherentData {
		bitfields: Vec::new(),
		backed_candidates: Vec::new(),
		disputes: Vec::new(),
		parent_header: header,
	};

	// Timestamp inherent that is very common in substrate chains.
	let timestamp = sp_timestamp::InherentDataProvider::new(std::time::Duration::default().into());

	let _ = futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data));
	let _ =
		inherent_data.put_data(polkadot_primitives::PARACHAINS_INHERENT_IDENTIFIER, &para_inherent);

	inherent_data
}

#[derive(Deserialize, Serialize, Clone, ChainSpecExtension)]
pub struct ParachainExtension {
	/// The id of the Parachain.
	pub para_id: Option<u32>,
}

fn generate_balances_sr25519(num_accounts: u64) -> Vec<Value> {
	let mut accounts = Vec::new();
	let pair = subxt_signer::sr25519::dev::alice();
	for i in 0..num_accounts {
		let derived = pair.derive([DeriveJunction::hard(i.to_string())]);
		accounts.push(derived);
	}
	accounts
		.into_iter()
		.map(|keypair| serde_json::json!((AccountId32::from(keypair.public_key().0), 1u64 << 60,)))
		.collect::<Vec<Value>>()
}

fn generate_balances_ecdsa(num_accounts: u64) -> Vec<Value> {
	let mut accounts = Vec::new();
	let pair = subxt_signer::ecdsa::dev::alice();
	for i in 0..num_accounts {
		let derived = pair.derive([DeriveJunction::hard(i.to_string())]).unwrap();
		accounts.push(derived);
	}
	accounts
		.into_iter()
		.map(|keypair| {
			let eth = EthKeypair::from(keypair);
			serde_json::json!(("0x".to_string() + &hex::encode(eth.account_id()), 1u64 << 60,))
		})
		.collect::<Vec<Value>>()
}

fn patch_genesis(
	mut input_value: Value,
	num_accounts: Option<u64>,
	chain_type: ChainType,
	generate_accounts: Option<AccountType>,
) -> Value {
	// If we identified a parachain we should patch a parachain id into the genesis config.
	// This ensures compatibility with the inherents that we provide to successfully build a
	// block.
	if let Parachain(para_id) = chain_type {
		if let Some(parachain_id) = input_value
			.get_mut("parachainInfo")
			.and_then(|info| info.get_mut("parachainId"))
		{
			log::info!(
				"Patching parachain id {} into genesis config for \"ParachainInfo\" pallet.",
				para_id
			);
			*parachain_id = json!(para_id);
		} else {
			// This branch should not be taken, since we identified before that we have a parachain.
			log::warn!("Was expecting \"ParachainInfo\" genesis config, but no entry was found. Unable to patch parachain ID.");
			log::debug!("{input_value:?}");
		}
	}

	if let Some(num_accounts) = num_accounts {
		// Attempt to patch balances
		if let Some(balances) = input_value
			.get_mut("balances")
			.and_then(|info| info.get_mut("balances"))
			.and_then(|balance| balance.as_array_mut())
		{
			let generated = match &generate_accounts {
				None => Default::default(),
				Some(AccountType::Sr25519) => generate_balances_sr25519(num_accounts),
				Some(AccountType::ECDSA) => generate_balances_ecdsa(num_accounts),
			};
			balances.extend(generated);
		} else {
			log::warn!("No balances found.");
		}
	}
	input_value
}

fn fetch_latest_metadata_from_blob(
	executor: &WasmExecutor<HostFunctions>,
	code_bytes: &Vec<u8>,
) -> Result<OpaqueMetadata> {
	let mut ext = BasicExternalities::default();
	let fetcher = BasicCodeFetcher(code_bytes.into());
	let version_result = executor
		.call(
			&mut ext,
			&fetcher.runtime_code(),
			"Metadata_metadata_versions",
			&[],
			CallContext::Offchain,
		)
		.0;

	let opaque_metadata: Option<OpaqueMetadata> = match version_result {
		Ok(supported_versions) => {
			let versions = Vec::<u32>::decode(&mut supported_versions.as_slice())
				.map_err(|e| format!("Error {e}"))?;
			let version_to_use = versions.last().ok_or("No versions available.")?;
			let parameters = (*version_to_use).encode();
			let encoded = executor
				.call(
					&mut ext,
					&fetcher.runtime_code(),
					"Metadata_metadata_at_version",
					&parameters,
					CallContext::Offchain,
				)
				.0
				.map_err(|e| format!("Unable to fetch metadata from blob: {e}"))?;
			Decode::decode(&mut encoded.as_slice())?
		},
		Err(_) => {
			let encoded = executor
				.call(
					&mut ext,
					&fetcher.runtime_code(),
					"Metadata_metadata",
					&[],
					CallContext::Offchain,
				)
				.0
				.map_err(|e| format!("Unable to fetch metadata from blob: {e}"))?;
			Decode::decode(&mut encoded.as_slice())?
		},
	};

	Ok(opaque_metadata.ok_or("Metadata not found")?)
}

impl OverheadCmd {
	fn identify_chain(
		&self,
		executor: &WasmExecutor<HostFunctions>,
		code_bytes: &Vec<u8>,
		para_id: Option<u32>,
	) -> Result<ChainType> {
		let opaque_metadata = fetch_latest_metadata_from_blob(executor, code_bytes)?;
		let metadata = subxt::Metadata::decode(&mut (*opaque_metadata).as_slice())?;

		let parachain_info_exists = metadata.pallet_by_name("ParachainInfo").is_some();
		let parachain_system_exists = metadata.pallet_by_name("ParachainSystem").is_some();
		let para_inherent_exists = metadata.pallet_by_name("ParaInherent").is_some();

		log::info!("Identifying chain type based on metadata.");
		log::debug!("{} ParachainSystem", if parachain_system_exists { "✅" } else { "❌" });
		log::debug!("{} ParachainInfo", if parachain_info_exists { "✅" } else { "❌" });
		log::debug!("{} ParaInherent", if para_inherent_exists { "✅" } else { "❌" });

		if parachain_system_exists && parachain_info_exists {
			log::info!("Parachain Identified");
			Ok(Parachain(para_id.or(self.params.bench.para_id).unwrap_or(DEFAULT_PARA_ID)))
		} else if para_inherent_exists {
			log::info!("Relaychain Identified");
			Ok(Relaychain)
		} else {
			log::info!("Found Custom chain");
			Ok(Unknown)
		}
	}
	fn chain_spec_from_path(&self) -> Result<(Option<Box<dyn ChainSpec>>, Option<u32>)> {
		let chain_spec = self
			.shared_params
			.chain
			.clone()
			.map(|path| {
				GenericChainSpec::<ParachainExtension, HostFunctions>::from_json_file(path.into())
					.map_err(|e| format!("Unable to load chain spec: {:?}", e))
			})
			.transpose()?;

		let para_id_from_chain_spec =
			chain_spec.as_ref().map(|spec| spec.extensions().para_id).flatten();
		Ok((chain_spec.map(|c| Box::new(c) as Box<_>), para_id_from_chain_spec))
	}

	/// Run the benchmark overhead command.
	pub fn run_with_extrinsic_builder(
		&self,
		ext_builder: Option<Box<dyn ExtrinsicBuilder>>,
	) -> Result<()> {
		let (chain_spec, para_id_from_chain_spec) = self.chain_spec_from_path()?;
		let code_bytes = shared::genesis_state::get_code_bytes::<HostFunctions>(
			&chain_spec,
			&self.params.runtime,
		)?;

		let executor = WasmExecutor::<HostFunctions>::builder()
			.with_allow_missing_host_functions(true)
			.build();

		let chain_type = self.identify_chain(&executor, &code_bytes, para_id_from_chain_spec)?;

		let client =
			self.build_client_components(chain_spec, &code_bytes, executor, &chain_type)?;

		let inherent_data = create_inherent_data(&client, &chain_type);

		let ext_builder: Box<dyn ExtrinsicBuilder> =
			match (ext_builder, &self.params.config_variant) {
				(Some(ext_builder), _) => ext_builder,
				(None, Some(ConfigVariant::AddressIsAccountId)) =>
					Box::new(DynamicRemarkBuilder::<AddressAccountIdConfig>::new(client.clone())),
				(None, Some(ConfigVariant::Eth)) =>
					Box::new(EthRemarkBuilder::<EthConfig>::new(client.clone())),
				(None, Some(ConfigVariant::AddressIsMultiAddress)) | (None, None) => Box::new(
					DynamicRemarkBuilder::<MultiAddressAccountIdConfig>::new(client.clone()),
				),
			};

		let digest_items = Default::default();

		self.run(
			"some_name".to_string(),
			client,
			inherent_data,
			digest_items,
			&*ext_builder,
			chain_type.requires_proof_recording(),
		)
	}

	fn build_client_components(
		&self,
		chain_spec: Option<Box<dyn ChainSpec>>,
		code_bytes: &Vec<u8>,
		executor: WasmExecutor<HostFunctions>,
		chain_type: &ChainType,
	) -> Result<Arc<OverheadClient>> {
		let extensions = ExecutionExtensions::new(None, Arc::new(executor.clone()));

		let backend = new_db_backend(DatabaseSettings {
			trie_cache_maximum_size: self.trie_cache_maximum_size()?,
			state_pruning: None,
			blocks_pruning: BlocksPruning::KeepAll,
			source: DatabaseSource::RocksDb {
				cache_size: self.database_cache_size()?.unwrap_or(1024),
				path: BasePath::new_temp_dir()?.path().into(),
			},
		})?;

		//let storage = self.storage(&code_bytes, chain_spec, &chain_type)?;
		let chain_type_for_closure = chain_type.clone();
		let num_accounts = self.params.num_accounts;
		let account_type = self.params.generate_accounts.clone();
		let storage = shared::genesis_state::genesis_storage::<HostFunctions>(
			self.params.genesis_builder,
			&self.params.runtime,
			Some(&code_bytes),
			&self.params.genesis_builder_preset,
			&chain_spec,
			Some(Box::new(move |val| {
				patch_genesis(val, num_accounts, chain_type_for_closure, account_type)
			})),
		)?;
		let genesis_block_builder = GenesisBlockBuilder::new_with_storage(
			storage,
			true,
			backend.clone(),
			executor.clone(),
		)?;

		let tokio_runtime = sc_cli::build_runtime()?;
		let task_manager = TaskManager::new(tokio_runtime.handle().clone(), None)
			.map_err(|_| "Unable to build task manager")?;

		let client: Arc<OverheadClient> = Arc::new(new_client(
			backend.clone(),
			executor,
			genesis_block_builder,
			Default::default(),
			Default::default(),
			extensions,
			Box::new(task_manager.spawn_handle()),
			None,
			None,
			ClientConfig {
				offchain_worker_enabled: false,
				offchain_indexing_api: false,
				wasm_runtime_overrides: None,
				no_genesis: false,
				wasm_runtime_substitutes: Default::default(),
				enable_import_proof_recording: chain_type.requires_proof_recording(),
			},
		)?);

		Ok(client)
	}

	/// Measure the per-block and per-extrinsic execution overhead.
	///
	/// Writes the results to console and into two instances of the
	/// `weights.hbs` template, one for each benchmark.
	pub fn run<Block, C>(
		&self,
		chain_name: String,
		client: Arc<C>,
		inherent_data: sp_inherents::InherentData,
		digest_items: Vec<DigestItem>,
		ext_builder: &dyn ExtrinsicBuilder,
		should_record_proof: bool,
	) -> Result<()>
	where
		Block: BlockT<Extrinsic = OpaqueExtrinsic>,
		C: ProvideRuntimeApi<Block>
			+ CallApiAt<Block>
			+ UsageProvider<Block>
			+ sp_blockchain::HeaderBackend<Block>,
		C::Api: ApiExt<Block> + BlockBuilderApi<Block>,
	{
		if ext_builder.pallet() != "system" || ext_builder.extrinsic() != "remark" {
			return Err(format!("The extrinsic builder is required to build `System::Remark` extrinsics but builds `{}` extrinsics instead", ext_builder.name()).into());
		}

		let bench = Benchmark::new(
			client,
			self.params.bench.clone(),
			inherent_data,
			digest_items,
			should_record_proof,
		);

		// per-block execution overhead
		{
			let (stats, proof_size) = bench.bench_block()?;
			info!("Per-block execution overhead [ns]:\n{:?}", stats);
			let template = TemplateData::new(
				BenchmarkType::Block,
				&chain_name,
				&self.params,
				&stats,
				proof_size,
			)?;
			template.write(&self.params.weight.weight_path)?;
		}
		// per-extrinsic execution overhead
		{
			let (stats, proof_size) = bench.bench_extrinsic(ext_builder)?;
			info!("Per-extrinsic execution overhead [ns]:\n{:?}", stats);
			let template = TemplateData::new(
				BenchmarkType::Extrinsic,
				&chain_name,
				&self.params,
				&stats,
				proof_size,
			)?;
			template.write(&self.params.weight.weight_path)?;
		}

		Ok(())
	}
}

impl BenchmarkType {
	/// Short name of the benchmark type.
	pub(crate) fn short_name(&self) -> &'static str {
		match self {
			Self::Extrinsic => "extrinsic",
			Self::Block => "block",
		}
	}

	/// Long name of the benchmark type.
	pub(crate) fn long_name(&self) -> &'static str {
		match self {
			Self::Extrinsic => "ExtrinsicBase",
			Self::Block => "BlockExecution",
		}
	}
}

struct BasicCodeFetcher<'a>(Cow<'a, [u8]>);
impl<'a> FetchRuntimeCode for BasicCodeFetcher<'a> {
	fn fetch_runtime_code(&self) -> Option<Cow<'a, [u8]>> {
		Some(self.0.clone())
	}
}
impl<'a> BasicCodeFetcher<'a> {
	pub fn runtime_code(&'a self) -> RuntimeCode<'a> {
		RuntimeCode {
			code_fetcher: self as &'a dyn FetchRuntimeCode,
			heap_pages: None,
			hash: sp_crypto_hashing::blake2_256(&self.0).to_vec(),
		}
	}
}

#[derive(Clone)]
enum ChainType {
	Parachain(u32),
	Relaychain,
	Unknown,
}

impl ChainType {
	fn requires_proof_recording(&self) -> bool {
		match self {
			Parachain(_) => true,
			Relaychain => false,
			Unknown => false,
		}
	}
}

// Boilerplate
impl CliConfiguration for OverheadCmd {
	fn shared_params(&self) -> &SharedParams {
		&self.shared_params
	}

	fn import_params(&self) -> Option<&ImportParams> {
		Some(&self.import_params)
	}

	fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
		if self.params.enable_trie_cache {
			Ok(self.import_params().map(|x| x.trie_cache_maximum_size()).unwrap_or_default())
		} else {
			Ok(None)
		}
	}

	fn base_path(&self) -> Result<Option<BasePath>> {
		Ok(Some(BasePath::new_temp_dir()?))
	}
}
