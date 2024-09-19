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
	shared::{GenesisBuilder, HostInfoParams, WeightParams},
};
use clap::{Args, Parser};
use codec::{Decode, Encode};
use fake_runtime_api::RuntimeApi as FakeRuntimeApi;
use frame_support::{Deserialize, __private::sp_tracing::tracing};
use log::info;
use polkadot_parachain_primitives::primitives::Id as ParaId;
use polkadot_primitives::v8::PersistedValidationData;
use sc_block_builder::BlockBuilderApi;
use sc_chain_spec::{
	ChainSpec, ChainSpecExtension, GenericChainSpec, GenesisBlockBuilder,
	GenesisConfigBuilderRuntimeCaller,
};
use sc_cli::{CliConfiguration, ImportParams, Result, SharedParams};
use sc_client_api::{execution_extensions::ExecutionExtensions, UsageProvider};
use sc_client_db::{BlocksPruning, DatabaseSettings, DatabaseSource};
use sc_executor::WasmExecutor;
use sc_service::{new_client, new_db_backend, BasePath, ClientConfig, TFullClient, TaskManager};
use serde::Serialize;
use serde_json::json;
use sp_api::{ApiExt, CallApiAt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{
	traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode},
	OpaqueMetadata,
};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{traits::Block as BlockT, BuildStorage, DigestItem, OpaqueExtrinsic};
use sp_state_machine::BasicExternalities;
use sp_storage::{well_known_keys::CODE, Storage};
use std::{borrow::Cow, fmt::Debug, fs, path::PathBuf, sync::Arc};
use subxt::ext::futures;

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

	#[arg(long)]
	pub genesis_builder_preset: Option<String>,

	/// How to construct the genesis state.
	///
	/// Uses `GenesisBuilder::Spec` by default and  `GenesisBuilder::Runtime` if `runtime` is set.
	#[arg(long, value_enum)]
	pub genesis_builder: Option<GenesisBuilder>,

	#[arg(long)]
	pub config_variant: Option<ConfigVariant>,
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Serialize)]
pub enum ConfigVariant {
	AddressIsMultiAddress,
	AddressIsAccountId,
	Eth,
}
/// Type of a benchmark.
#[derive(Serialize, Clone, PartialEq, Copy)]
pub(crate) enum BenchmarkType {
	/// Measure the per-extrinsic execution overhead.
	Extrinsic,
	/// Measure the per-block execution overhead.
	Block,
}

fn get_storage_from_code_bytes(
	code_bytes: &Vec<u8>,
	chain_type: &ChainType,
	preset: String,
) -> Result<Storage> {
	let genesis_config_caller = GenesisConfigBuilderRuntimeCaller::<HostFunctions>::new(code_bytes);
	log::info!("Using genesis preset to populate genesis state: \"{}\"", preset);
	let mut preset_json = genesis_config_caller
		.get_named_preset(Some(&preset))
		.map_err(|e| format!("Unable to build genesis block builder: {:?}", e))?;

	if let Parachain(para_id) = chain_type {
		log::info!(
			"Patching parachain id {} into genesis config for \"ParachainInfo\" pallet.",
			para_id
		);
		if let Some(parachain_info) = preset_json.get_mut("parachainInfo") {
			if let Some(parachain_id) = parachain_info.get_mut("parachainId") {
				*parachain_id = json!(para_id);
			}
		}
	}
	let mut storage = genesis_config_caller.get_storage_for_patch(preset_json.clone())?;
	storage.top.insert(CODE.into(), code_bytes.to_vec());

	Ok(storage)
}

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

impl OverheadCmd {
	fn storage(
		&self,
		code_bytes: &Vec<u8>,
		chain_spec: Option<&GenericChainSpec<ParachainExtension, HostFunctions>>,
		chain_type: &ChainType,
	) -> Result<Storage> {
		let preset_name =
			self.params.genesis_builder_preset.clone().unwrap_or("development".to_string());
		match (self.params.genesis_builder, chain_spec) {
			(Some(GenesisBuilder::Runtime), _) =>
				Ok(get_storage_from_code_bytes(code_bytes, chain_type, preset_name)?),
			// Get the genesis state from the chain spec
			(Some(GenesisBuilder::Spec), Some(chain_spec)) => {
				let storage = chain_spec
					.as_storage_builder()
					.build_storage()
					.map_err(|e| format!("Can not transform chain-spec to storage: {}", e))?;
				Ok(storage)
			},
			(Some(GenesisBuilder::SpecRuntime), Some(chain_spec)) => {
				let storage = chain_spec
					.build_storage()
					.map_err(|_| "Unable to build storage from chain spec")?;
				let code_bytes =
					storage.top.get(CODE).ok_or("chain spec genesis does not contain code")?;
				Ok(get_storage_from_code_bytes(code_bytes, chain_type, preset_name)?)
			},
			(_, _) => {
				todo!()
			},
		}
	}

	fn get_code_bytes(
		&self,
		chain_spec: Option<&GenericChainSpec<ParachainExtension, HostFunctions>>,
	) -> Result<Vec<u8>> {
		match (chain_spec, &self.params.runtime) {
			(_, Some(runtime_code_path)) => {
				let code_bytes = fs::read(runtime_code_path)
					.map_err(|e| format!("Unable to read runtime file: {:?}", e))?;

				Ok(code_bytes)
			},
			// Get the genesis state from the chain spec
			(Some(chain_spec), _) => {
				let storage = chain_spec
					.as_storage_builder()
					.build_storage()
					.map_err(|e| format!("Can not transform chain-spec to storage {}", e))?;
				let code_bytes = storage
					.top
					.get(CODE)
					.ok_or("chain spec genesis does not contain code")?
					.clone();
				Ok(code_bytes)
			},
			(_, _) => Err("Please provide either a runtime or a chain spec.".into()),
		}
	}

	fn identify_chain(
		&self,
		executor: &WasmExecutor<HostFunctions>,
		code_bytes: &Vec<u8>,
		chain_spec: Option<&GenericChainSpec<ParachainExtension, HostFunctions>>,
	) -> ChainType {
		let mut ext = BasicExternalities::default();
		let fetcher = Box::new(BasicCodeFetcher(code_bytes.clone())) as Box<dyn FetchRuntimeCode>;
		let hash = sp_crypto_hashing::blake2_256(&code_bytes).to_vec();
		let test = 15u32;
		let result = executor
			.call(
				&mut ext,
				&RuntimeCode { heap_pages: None, code_fetcher: &*fetcher, hash },
				"Metadata_metadata_at_version",
				&test.encode(),
				CallContext::Offchain,
			)
			.0
			.expect("Able to call this");

		let metadata: Option<OpaqueMetadata> =
			Decode::decode(&mut &result[..]).expect("Able to decode metadata");

		let Some(metadata) = metadata else {
			panic!("metadata not available");
		};
		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())
			.map_err(|e| tracing::error!("Error {e}"))
			.unwrap();

		let parachain_info_exists = metadata.pallet_by_name("ParachainInfo").is_some();
		let parachain_system_exists = metadata.pallet_by_name("ParachainSystem").is_some();
		let para_inherent_exists = metadata.pallet_by_name("ParaInherent").is_some();

		log::info!("Identifying pallets:");
		log::info!("{} ParachainSystem", if parachain_system_exists { "✅" } else { "❌" });
		log::info!("{} ParachainInfo", if parachain_info_exists { "✅" } else { "❌" });
		log::info!("{} ParaInherent", if para_inherent_exists { "✅" } else { "❌" });

		if parachain_system_exists && parachain_info_exists {
			log::info!("Parachain Identified");
			// Para id from spec takes precedence.
			let para_id = chain_spec
				.map(|spec| spec.extensions().para_id)
				.flatten()
				.or(self.params.bench.para_id)
				.unwrap_or(DEFAULT_PARA_ID);
			return Parachain(para_id)
		} else if para_inherent_exists {
			log::info!("Relaychain Identified");
			return Relaychain
		} else {
			return Unknown
		}
	}

	/// Run the benchmark overhead command.
	pub fn run_with_extrinsic_builder(
		&self,
		ext_builder: Option<Box<dyn ExtrinsicBuilder>>,
	) -> Result<()> {
		let chain_spec = self
			.shared_params
			.chain
			.clone()
			.map(|path| {
				GenericChainSpec::<ParachainExtension, HostFunctions>::from_json_file(path.into())
					.map_err(|e| format!("Unable to load chain spec: {:?}", e))
			})
			.transpose()?;

		let code_bytes = self.get_code_bytes(chain_spec.as_ref())?;

		let executor = WasmExecutor::<HostFunctions>::builder()
			.with_allow_missing_host_functions(true)
			.build();

		let chain_type = self.identify_chain(&executor, &code_bytes, chain_spec.as_ref());

		let client =
			self.build_client_components(chain_spec.as_ref(), &code_bytes, executor, &chain_type)?;

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
		chain_spec: Option<&GenericChainSpec<ParachainExtension, HostFunctions>>,
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

		let storage = self.storage(&code_bytes, chain_spec, &chain_type)?;
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

struct BasicCodeFetcher(pub Vec<u8>);
impl FetchRuntimeCode for BasicCodeFetcher {
	fn fetch_runtime_code(&self) -> Option<Cow<[u8]>> {
		Some(Cow::from(&self.0))
	}
}

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
