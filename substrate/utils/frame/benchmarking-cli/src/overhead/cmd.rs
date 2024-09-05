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

use codec::Decode;
use sc_block_builder::BlockBuilderApi;
use sc_cli::{CliConfiguration, ImportParams, Result, SharedParams};
use sc_client_api::UsageProvider;
use sc_service::{Configuration, TFullClient};
use sp_api::{ApiExt, CallApiAt, Core, Metadata, ProvideRuntimeApi};
use sp_runtime::{traits::Block as BlockT, DigestItem, OpaqueExtrinsic};
use subxt::{
	config::substrate::SubstrateExtrinsicParamsBuilder,
	ext::frame_metadata::RuntimeMetadataPrefixed, tx::PairSigner, OfflineClient, SubstrateConfig,
};

use crate::{
	extrinsic::{
		bench::{Benchmark, BenchmarkParams as ExtrinsicBenchmarkParams},
		ExtrinsicBuilder,
	},
	overhead::template::TemplateData,
	shared::{HostInfoParams, WeightParams},
};
use clap::{Args, Parser};
use frame_support::__private::sp_tracing::tracing;
use log::info;
use sc_executor::WasmExecutor;
use serde::Serialize;
use std::{fmt::Debug, path::PathBuf, sync::Arc};

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
}

/// Type of a benchmark.
#[derive(Serialize, Clone, PartialEq, Copy)]
pub(crate) enum BenchmarkType {
	/// Measure the per-extrinsic execution overhead.
	Extrinsic,
	/// Measure the per-block execution overhead.
	Block,
}

impl OverheadCmd {
	pub fn run_with_spec(&self, config: Configuration, p0: Option<()>) -> Result<()> {
		let executor = WasmExecutor::<HostFunctions>::builder().build();

		let (client, backend, keystore_container, task_manager) = sc_service::new_full_parts::<
			opaque::Block,
			super::fake_runtime_api::aura::RuntimeApi,
			_,
		>(&config, None, executor)
		.expect("We are able to build the client; qed");
		Ok(())
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
	use super::*;
	use sp_runtime::{generic, traits::BlakeTwo256, OpaqueExtrinsic};

	/// Block number
	pub type BlockNumber = u32;
	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, OpaqueExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;
}

pub type HostFunctions = (
	cumulus_primitives_proof_size_hostfunction::storage_proof_size::HostFunctions,
	sp_io::SubstrateHostFunctions,
);
pub type ParachainClient<RuntimeApi> =
	TFullClient<opaque::Block, RuntimeApi, WasmExecutor<HostFunctions>>;
struct DynamicRemarkBuilder<Client> {
	client: Arc<Client>,
}

impl<Client> ExtrinsicBuilder for DynamicRemarkBuilder<Client>
where
	Client: UsageProvider<opaque::Block>,
	Client: ProvideRuntimeApi<opaque::Block>,
	Client::Api: Metadata<opaque::Block> + Core<opaque::Block>,
{
	fn pallet(&self) -> &str {
		"system"
	}

	fn extrinsic(&self) -> &str {
		"remark"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		// We apply the extrinsic directly, so let's take some random period.
		let genesis = self.client.usage_info().chain.best_hash;

		let api = self.client.runtime_api();
		let mut supported_metadata_versions = api.metadata_versions(genesis).unwrap();

		let Some(latest) = supported_metadata_versions.pop() else {
			return Err("No metadata version is supported");
		};

		let Some(metadata) = api.metadata_at_version(genesis, latest).unwrap() else {
			return Err("Unable to fetch metadata");
		};

		let version = api.version(genesis).unwrap();

		let runtime_version = subxt::client::RuntimeVersion {
			spec_version: version.spec_version,
			transaction_version: version.transaction_version,
		};

		let signer = subxt_signer::sr25519::dev::bob();
		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())
			.map_err(|e| tracing::error!("Error {e}"))
			.unwrap();

		let dynamic_tx = subxt::dynamic::tx("System", "remark", vec![vec!['a', 'b', 'b']]);
		let offline: OfflineClient<SubstrateConfig> =
			OfflineClient::new(genesis, runtime_version, metadata);

		let params = SubstrateExtrinsicParamsBuilder::new().nonce(nonce.into()).build();
		// Default transaction parameters assume a nonce of 0.
		let transaction = offline.tx().create_signed_offline(&dynamic_tx, &signer, params).unwrap();
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
