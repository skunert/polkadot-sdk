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
	overhead::{fake_runtime_api, template::TemplateData},
	shared::{GenesisBuilder, HostInfoParams, WeightParams},
};
use clap::{Args, Parser};
use codec::{Decode, Encode};
use fake_runtime_api::RuntimeApi as FakeRuntimeApi;
use frame_support::__private::sp_tracing::tracing;
use log::info;
use polkadot_parachain_primitives::primitives::Id as ParaId;
use polkadot_primitives::v8::PersistedValidationData;
use sc_block_builder::BlockBuilderApi;
use sc_chain_spec::{ChainSpec, GenesisBlockBuilder, GenesisConfigBuilderRuntimeCaller};
use sc_cli::{CliConfiguration, ImportParams, Result, SharedParams};
use sc_client_api::{Backend, UsageProvider};
use sc_executor::WasmExecutor;
use sc_service::{
	new_db_backend, new_full_parts_with_genesis_builder, Configuration, TFullBackend, TFullClient,
};
use serde::Serialize;
use serde_json::{json, Value};
use sp_api::{ApiExt, CallApiAt, Core, Metadata, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::AccountId32, Pair, H256};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{traits::Block as BlockT, DigestItem, MultiSignature, OpaqueExtrinsic};
use sp_storage::well_known_keys::CODE;
use std::{fmt::Debug, fs, path::PathBuf, sync::Arc};
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

	/// How to construct the genesis state.
	///
	/// Uses `GenesisBuilder::Spec` by default and  `GenesisBuilder::Runtime` if `runtime` is set.
	#[arg(long, value_enum)]
	pub genesis_builder: Option<GenesisBuilder>,

	#[arg(long)]
	pub address_type: Option<AddressType>,
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Serialize)]
pub enum AddressType {
	MultiAddress,
	AccountId,
}
/// Type of a benchmark.
#[derive(Serialize, Clone, PartialEq, Copy)]
pub(crate) enum BenchmarkType {
	/// Measure the per-extrinsic execution overhead.
	Extrinsic,
	/// Measure the per-block execution overhead.
	Block,
}

fn create_parachain_inherent_data<
	Client: UsageProvider<Block> + HeaderBackend<Block>,
	Block: BlockT,
>(
	client: &Client,
	para_id: u32,
) -> InherentData {
	let genesis = client.usage_info().chain.best_hash;
	let header = client.header(genesis).unwrap().unwrap();
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

	let mut inherent_data = sp_inherents::InherentData::new();
	let timestamp = sp_timestamp::InherentDataProvider::new(std::time::Duration::default().into());
	let _ = futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data));
	let _ = futures::executor::block_on(para_data.provide_inherent_data(&mut inherent_data));
	inherent_data
}

impl OverheadCmd {
	fn build_genesis_block_builder(
		&self,
		chain_spec: &Box<dyn ChainSpec>,
		backend: Arc<TFullBackend<opaque::Block>>,
		executor: WasmExecutor<HostFunctions>,
	) -> Result<
		GenesisBlockBuilder<
			opaque::Block,
			TFullBackend<opaque::Block>,
			WasmExecutor<HostFunctions>,
		>,
	> {
		match self.params.genesis_builder {
			None => {
				todo!()
			},
			Some(GenesisBuilder::None) => {
				todo!()
			},
			Some(GenesisBuilder::Runtime) => {
				// TODO In fact should be supported for chain specs
				if self.params.runtime.is_none() {
					return Err("Runtime path is required for `GenesisBuilder::Runtime`".into());
				}
				let code_bytes = fs::read(self.params.runtime.as_ref().unwrap())
					.map_err(|e| format!("Unable to read runtime file: {:?}", e))?;

				let genesis_config_caller =
					GenesisConfigBuilderRuntimeCaller::<(HostFunctions)>::new(code_bytes.as_ref());
				let preset = "development".to_string();
				let mut res = genesis_config_caller
					.get_named_preset(Some(&preset))
					.map_err(|e| format!("Unable to build genesis block builder: {:?}", e))?;
				dbg!(&res);
				let parachain_id_from_preset = res
					.get("parachainInfo")
					.and_then(|info| info.get("parachainId"))
					.and_then(|id| id.as_u64());
				dbg!(parachain_id_from_preset);
				if let Some(parachain_info) = res.get_mut("parachainInfo") {
					if let Some(parachain_id) = parachain_info.get_mut("parachainId") {
						log::info!("Setting parachain id");
						*parachain_id = json!(100);
					}
				}
				let mut storage = genesis_config_caller.get_storage_for_patch(res.clone())?;
				storage.top.insert(CODE.into(), code_bytes.to_vec());

				log::info!("Using runtime to initialize genesis storage.");
				dbg!(&res);
				GenesisBlockBuilder::new_with_storage(
					storage,
					true,
					backend.clone(),
					executor.clone(),
				)
				.map_err(|e| format!("Unable to build genesis block builder: {:?}", e).into())
			},
			// TODO See if we can clean this up. Maybe remove config and use the chain spec
			// directly.
			Some(GenesisBuilder::Spec) => GenesisBlockBuilder::new(
				chain_spec.as_storage_builder(),
				true,
				backend.clone(),
				executor.clone(),
			)
			.map_err(|e| format!("Unable to build genesis block builder: {:?}", e).into()),
		}
	}

	pub fn run_with_spec(
		&self,
		config: Configuration,
		ext_builder: Option<Box<dyn ExtrinsicBuilder>>,
	) -> Result<()> {
		let executor = WasmExecutor::<HostFunctions>::builder().build();

		let backend = new_db_backend(config.db_config())?;

		let Ok(genesis_block_builder) =
			self.build_genesis_block_builder(&config.chain_spec, backend.clone(), executor.clone())
		else {
			return Err("Unable to build genesis block builder".into());
		};

		let (client, _backend, _keystore_container, _task_manager) =
			new_full_parts_with_genesis_builder(
				&config,
				None,
				executor,
				backend,
				genesis_block_builder,
				// TODO: Change this depending on parachain or not
				true,
			)
			.expect("Can build");

		let client: Arc<OverheadClient> = Arc::new(client);
		let ext_builder: Box<dyn ExtrinsicBuilder> = match (ext_builder, &self.params.address_type)
		{
			(Some(ext_builder), _) => ext_builder,
			(None, Some(AddressType::AccountId)) =>
				Box::new(DynamicRemarkBuilder::<AddressAccountIdConfig>::new(client.clone())),
			(None, Some(AddressType::MultiAddress)) | (None, None) =>
				Box::new(DynamicRemarkBuilder::<MultiAddressAccountIdConfig>::new(client.clone())),
		};

		let digest_items = Default::default();

		let inherent_data =
			create_parachain_inherent_data(&*client, dbg!(self.params.bench.para_id));

		self.run(config, client, inherent_data, digest_items, &*ext_builder)
	}
	/// Measure the per-block and per-extrinsic execution overhead.
	///
	/// Writes the results to console and into two instances of the
	/// `weights.hbs` template, one for each benchmark.
	pub fn run<Block, C>(
		&self,
		cfg: Configuration,
		client: Arc<C>,
		inherent_data: sp_inherents::InherentData,
		digest_items: Vec<DigestItem>,
		ext_builder: &dyn ExtrinsicBuilder,
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
		let bench = Benchmark::new(client, self.params.bench.clone(), inherent_data, digest_items);

		// per-block execution overhead
		{
			let (stats, proof_size) = bench.bench_block()?;
			info!("Per-block execution overhead [ns]:\n{:?}", stats);
			let template =
				TemplateData::new(BenchmarkType::Block, &cfg, &self.params, &stats, proof_size)?;
			template.write(&self.params.weight.weight_path)?;
		}
		// per-extrinsic execution overhead
		{
			let (stats, proof_size) = bench.bench_extrinsic(ext_builder)?;
			info!("Per-extrinsic execution overhead [ns]:\n{:?}", stats);
			let template = TemplateData::new(
				BenchmarkType::Extrinsic,
				&cfg,
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
}
