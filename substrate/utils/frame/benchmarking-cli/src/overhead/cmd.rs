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
use polkadot_parachain_primitives::primitives::{Id as ParaId, Id};
use polkadot_primitives::v8::PersistedValidationData;
use sc_block_builder::BlockBuilderApi;
use sc_chain_spec::{
	ChainSpec, ChainSpecExtension, GenericChainSpec, GenesisBlockBuilder,
	GenesisConfigBuilderRuntimeCaller, NoExtension,
};
use sc_cli::{CliConfiguration, ImportParams, Result, SharedParams};
use sc_client_api::{execution_extensions::ExecutionExtensions, UsageProvider};
use sc_client_db::{BlocksPruning, DatabaseSettings, DatabaseSource};
use sc_executor::WasmExecutor;
use sc_service::{
	new_client, new_db_backend, BasePath, ClientConfig, TFullBackend, TFullClient, TaskManager,
};
use serde::Serialize;
use serde_json::json;
use sp_api::{ApiExt, CallApiAt, Core, Metadata, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{
	crypto::AccountId32,
	traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode},
	OpaqueMetadata, Pair, H256,
};
use sp_externalities::Externalities;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{traits::Block as BlockT, DigestItem, MultiSignature, OpaqueExtrinsic};
use sp_state_machine::BasicExternalities;
use sp_storage::{well_known_keys::CODE, Storage};
use std::{borrow::Cow, fmt::Debug, fs, path::PathBuf, sync::Arc};
use subxt::{
	client::RuntimeVersion,
	config::{
		substrate::{BlakeTwo256, SubstrateExtrinsicParamsBuilder, SubstrateHeader},
		SubstrateExtrinsicParams,
	},
	ext::futures,
	tx::Signer,
	utils::MultiAddress,
	Config, OfflineClient,
};

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
	code_bytes: Vec<u8>,
	para_id: ParaId,
	preset: String,
) -> Result<Storage> {
	let genesis_config_caller =
		GenesisConfigBuilderRuntimeCaller::<HostFunctions>::new(code_bytes.as_ref());
	log::info!("Using genesis preset to populate state: \"{}\"", preset);
	let mut res = genesis_config_caller
		.get_named_preset(Some(&preset))
		.map_err(|e| format!("Unable to build genesis block builder: {:?}", e))?;
	log::info!("Setting parachain id in genesis to {}", para_id);
	if let Some(parachain_info) = res.get_mut("parachainInfo") {
		if let Some(parachain_id) = parachain_info.get_mut("parachainId") {
			*parachain_id = json!(para_id);
		}
	}
	let mut storage = genesis_config_caller.get_storage_for_patch(res.clone())?;
	storage.top.insert(CODE.into(), code_bytes.to_vec());

	log::info!("Using runtime to initialize genesis storage.");
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
	para_id: u32,
) -> InherentData {
	let genesis = client.usage_info().chain.best_hash;
	let header = client.header(genesis).unwrap().unwrap();

	// Data for parachain system inherent. Required for all FRAME-based parachains.
	let mut relay_state = cumulus_test_relay_sproof_builder::RelayStateSproofBuilder::default();
	relay_state.included_para_head = Some(header.encode().into());
	relay_state.para_id = ParaId::from(para_id);

	let mut vfp = PersistedValidationData::default();
	let (root, proof) = relay_state.into_state_root_and_proof();
	vfp.relay_parent_storage_root = root;
	let para_data = cumulus_primitives_parachain_inherent::ParachainInherentData {
		validation_data: vfp,
		relay_chain_state: proof,
		downward_messages: Default::default(),
		horizontal_messages: Default::default(),
	};

	// Parachain inherent that is used on relay chains to perform parachain validation.
	let para_inherent = polkadot_primitives::InherentData {
		bitfields: Vec::new(),
		backed_candidates: Vec::new(),
		disputes: Vec::new(),
		parent_header: header,
	};

	// Timestamp inherent that is very common in substrate chains.
	let timestamp = sp_timestamp::InherentDataProvider::new(std::time::Duration::default().into());

	let mut inherent_data = sp_inherents::InherentData::new();
	let _ = futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data));
	let _ = futures::executor::block_on(para_data.provide_inherent_data(&mut inherent_data));
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
		chain_spec: Option<&Box<dyn ChainSpec>>,
		para_id: ParaId,
	) -> Result<(Storage, Vec<u8>)> {
		let preset_name =
			self.params.genesis_builder_preset.clone().unwrap_or("development".to_string());
		match (self.params.genesis_builder, chain_spec, &self.params.runtime) {
			(Some(GenesisBuilder::Runtime), _, Some(runtime_code_path)) => {
				let code_bytes = fs::read(runtime_code_path)
					.map_err(|e| format!("Unable to read runtime file: {:?}", e))?;

				Ok((
					get_storage_from_code_bytes(code_bytes.clone(), para_id, preset_name)?,
					code_bytes,
				))
			},
			// Get the genesis state from the chain spec
			(Some(GenesisBuilder::Spec), Some(chain_spec), _) => {
				let storage = chain_spec
					.as_storage_builder()
					.build_storage()
					.map_err(|e| format!("Can not transform chain-spec to storage"))?;
				let code_bytes = storage
					.top
					.get(CODE)
					.ok_or("chain spec genesis does not contain code")?
					.clone();
				Ok((storage, code_bytes))
			},
			(Some(GenesisBuilder::SpecRuntime), Some(chain_spec), _) => {
				let Ok(storage) = chain_spec.build_storage() else {
					return Err("Unable to build storage from chain spec".into());
				};
				let Some(code_bytes) = storage.top.get(CODE) else {
					return Err("chain spec genesis does not contain code".into());
				};
				Ok((
					get_storage_from_code_bytes(code_bytes.clone(), para_id, preset_name)?,
					code_bytes.clone(),
				))
			},
			(_, _, _) => {
				todo!()
			},
		}
	}

	pub fn run_with_spec(
		&self,
		chain_spec: Option<Box<dyn ChainSpec>>,
		ext_builder: Option<Box<dyn ExtrinsicBuilder>>,
	) -> Result<()> {
		let runtime = sc_cli::build_runtime().expect("Can build tokio runtime");
		let mut para_id = self.params.bench.para_id.unwrap_or(DEFAULT_PARA_ID);
		let executor = WasmExecutor::<HostFunctions>::builder()
			.with_allow_missing_host_functions(true)
			.build();

		let base_path = BasePath::new_temp_dir()?;
		let backend = new_db_backend(DatabaseSettings {
			trie_cache_maximum_size: Some(1024),
			state_pruning: None,
			blocks_pruning: BlocksPruning::KeepAll,
			source: DatabaseSource::RocksDb { cache_size: 1024, path: base_path.path().into() },
		})?;

		let chain_spec = match (chain_spec, self.shared_params.chain.clone()) {
			(Some(chain_spec), _) => Some(chain_spec),
			(None, Some(path)) => {
				let spec = GenericChainSpec::<ParachainExtension, HostFunctions>::from_json_file(
					path.into(),
				)
				.map_err(|e| format!("Unable to load chain spec: {:?}", e))?;
				para_id = spec.extensions().para_id.unwrap_or(DEFAULT_PARA_ID);
				log::info!("Para id from chain_spec: {:?}", para_id);
				Some(Box::new(spec) as Box<_>)
			},
			(_, _) => None,
		};

		let (storage, code_bytes) = self.storage(chain_spec.as_ref(), ParaId::from(para_id))?;

		let chain_type = identify_chain(executor.clone(), code_bytes);
		let genesis_block_builder =
			GenesisBlockBuilder::new_with_storage(storage, true, backend.clone(), executor.clone())
				.map_err(|e| format!("Unable to build genesis block builder: {:?}", e))?;

		let Ok(task_manager) = TaskManager::new(runtime.handle().clone(), None) else {
			return Err("Unable to build task manager".into());
		};

		let extensions = ExecutionExtensions::new(None, Arc::new(executor.clone()));

		let enable_import_proof_recording = match chain_type {
			Parachain => true,
			Relaychain => false,
			Unknown => false,
		};

		let client: Arc<OverheadClient> = Arc::new(
			new_client(
				backend.clone(),
				executor.clone(),
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
					enable_import_proof_recording,
				},
			)
			.expect("Can build client"),
		);

		let inherent_data = create_inherent_data(&client, para_id);
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
			enable_import_proof_recording,
		)
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
		info!("Recording proof: {}", should_record_proof);
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
	Parachain,
	Relaychain,
	Unknown,
}
fn identify_chain(executor: WasmExecutor<HostFunctions>, code_bytes: Vec<u8>) -> ChainType {
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
		return Parachain
	} else if para_inherent_exists {
		log::info!("Relaychain Identified");
		return Relaychain
	} else {
		return Unknown
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

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum EthConfig {}

impl Config for EthConfig {
	type Hash = H256;
	type AccountId = AccountId20;
	// type Address = MultiAddress<Self::AccountId, u32>;
	type Address = Self::AccountId;
	type Signature = subxt_signer::eth::Signature;
	type Hasher = BlakeTwo256;
	type Header = SubstrateHeader<u32, BlakeTwo256>;
	type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
	type AssetId = u32;
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum AddressAccountIdConfig {}

impl Config for AddressAccountIdConfig {
	type Hash = H256;
	type AccountId = AccountId32;
	// type Address = MultiAddress<Self::AccountId, u32>;
	type Address = Self::AccountId;
	type Signature = MultiSignature;
	type Hasher = BlakeTwo256;
	type Header = SubstrateHeader<u32, BlakeTwo256>;
	type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
	type AssetId = u32;
}

pub enum MultiAddressAccountIdConfig {}

impl Config for MultiAddressAccountIdConfig {
	type Hash = H256;
	type AccountId = AccountId32;
	type Address = MultiAddress<Self::AccountId, u32>;
	type Signature = MultiSignature;
	type Hasher = BlakeTwo256;
	type Header = SubstrateHeader<u32, BlakeTwo256>;
	type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
	type AssetId = u32;
}

struct MySigner(pub sp_core::sr25519::Pair);

impl<C: Config<Hash = H256, AccountId = AccountId32, Signature = MultiSignature>> Signer<C>
	for MySigner
{
	fn account_id(&self) -> C::AccountId {
		self.0.public().0.into()
	}

	fn address(&self) -> C::Address {
		C::Address::from(<MySigner as subxt::tx::Signer<C>>::account_id(self))
	}

	fn sign(&self, signer_payload: &[u8]) -> C::Signature {
		self.0.sign(signer_payload).into()
	}
}

struct DynamicRemarkBuilder<C: Config<Hash = H256>> {
	offline_client: OfflineClient<C>,
}

impl<C: Config<Hash = H256>> DynamicRemarkBuilder<C> {
	fn new<Client>(client: Arc<Client>) -> Self
	where
		Client: UsageProvider<opaque::Block> + HeaderBackend<opaque::Block>,
		Client: ProvideRuntimeApi<opaque::Block>,
		Client::Api: Metadata<opaque::Block> + Core<opaque::Block>,
	{
		let genesis = client.usage_info().chain.best_hash;
		let api = client.runtime_api();
		let mut supported_metadata_versions = api.metadata_versions(genesis).unwrap();
		let Some(latest) = supported_metadata_versions.pop() else {
			panic!("No metadata version is supported");
		};
		let Some(metadata) = api.metadata_at_version(genesis, latest).unwrap() else {
			panic!("Unable to fetch metadata");
		};
		let version = api.version(genesis).unwrap();
		let runtime_version = RuntimeVersion {
			spec_version: version.spec_version,
			transaction_version: version.transaction_version,
		};
		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())
			.map_err(|e| tracing::error!("Error {e}"))
			.unwrap();

		let offline_client: OfflineClient<C> =
			OfflineClient::new(genesis, runtime_version, metadata);
		Self { offline_client }
	}
}

impl<
		C: Config<
			Hash = H256,
			AccountId = AccountId32,
			Signature = MultiSignature,
			ExtrinsicParams = SubstrateExtrinsicParams<C>,
		>,
	> ExtrinsicBuilder for DynamicRemarkBuilder<C>
{
	fn pallet(&self) -> &str {
		"system"
	}

	fn extrinsic(&self) -> &str {
		"remark"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		let signer = MySigner(sp_keyring::Sr25519Keyring::Bob.pair());
		let dynamic_tx = subxt::dynamic::tx("System", "remark", vec![vec!['a', 'b', 'b']]);

		let params = SubstrateExtrinsicParamsBuilder::<C>::new().nonce(nonce.into()).build();

		// Default transaction parameters assume a nonce of 0.
		let transaction = self
			.offline_client
			.tx()
			.create_signed_offline(&dynamic_tx, &signer, params)
			.unwrap();
		let mut encoded = transaction.into_encoded();

		OpaqueExtrinsic::from_bytes(&mut encoded).map_err(|_| "Unable to construct OpaqueExtrinsic")
	}
}

struct EthRemarkBuilder<C: Config<Hash = H256>> {
	offline_client: OfflineClient<C>,
}

impl<C: Config<Hash = H256>> crate::overhead::cmd::EthRemarkBuilder<C> {
	fn new<Client>(client: Arc<Client>) -> Self
	where
		Client: UsageProvider<opaque::Block> + HeaderBackend<opaque::Block>,
		Client: ProvideRuntimeApi<opaque::Block>,
		Client::Api: Metadata<opaque::Block> + Core<opaque::Block>,
	{
		let genesis = client.usage_info().chain.best_hash;
		let api = client.runtime_api();
		let mut supported_metadata_versions = api.metadata_versions(genesis).unwrap();
		let Some(latest) = supported_metadata_versions.pop() else {
			panic!("No metadata version is supported");
		};
		let Some(metadata) = api.metadata_at_version(genesis, latest).unwrap() else {
			panic!("Unable to fetch metadata");
		};
		let version = api.version(genesis).unwrap();
		let runtime_version = RuntimeVersion {
			spec_version: version.spec_version,
			transaction_version: version.transaction_version,
		};
		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())
			.map_err(|e| tracing::error!("Error {e}"))
			.unwrap();

		let offline_client: OfflineClient<C> =
			OfflineClient::new(genesis, runtime_version, metadata);
		Self { offline_client }
	}
}

use subxt_signer::eth::AccountId20;
impl<
		C: Config<
			Hash = H256,
			AccountId = AccountId20,
			Signature = subxt_signer::eth::Signature,
			ExtrinsicParams = SubstrateExtrinsicParams<C>,
		>,
	> ExtrinsicBuilder for EthRemarkBuilder<C>
{
	fn pallet(&self) -> &str {
		"system"
	}

	fn extrinsic(&self) -> &str {
		"remark"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		// let signer = MySigner(sp_keyring::Sr25519Keyring::Bob.pair());
		let signer = subxt_signer::eth::dev::alith();
		let dynamic_tx = subxt::dynamic::tx("System", "remark", vec![vec!['a', 'b', 'b']]);

		let params = SubstrateExtrinsicParamsBuilder::<C>::new().nonce(nonce.into()).build();

		// Default transaction parameters assume a nonce of 0.
		let transaction = self
			.offline_client
			.tx()
			.create_signed_offline(&dynamic_tx, &signer, params)
			.unwrap();
		let mut encoded = transaction.into_encoded();

		OpaqueExtrinsic::from_bytes(&mut encoded).map_err(|_| "Unable to construct OpaqueExtrinsic")
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
