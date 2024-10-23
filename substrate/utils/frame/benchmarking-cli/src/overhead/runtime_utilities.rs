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

use crate::extrinsic::ExtrinsicBuilder;
use codec::{Decode, Encode};
use sc_client_api::UsageProvider;
use sc_executor::WasmExecutor;
use sp_api::{ApiExt, Core, Metadata, ProvideRuntimeApi};
use sp_core::{
	traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode},
	OpaqueMetadata,
};
use sp_runtime::{traits::Block as BlockT, OpaqueExtrinsic};
use sp_state_machine::BasicExternalities;
use sp_wasm_interface::HostFunctions;
use std::{borrow::Cow, sync::Arc};
use subxt::{
	client::RuntimeVersion as SubxtRuntimeVersion,
	config::substrate::SubstrateExtrinsicParamsBuilder, Config, OfflineClient, SubstrateConfig,
};

pub type SubstrateRemarkBuilder = DynamicRemarkBuilder<SubstrateConfig>;

/// Remark builder that can be used to build simple extrinsics for
/// FRAME-based runtimes.
pub struct DynamicRemarkBuilder<C: Config> {
	offline_client: OfflineClient<C>,
}

impl<C: Config<Hash = subxt::utils::H256>> DynamicRemarkBuilder<C> {
	/// Initializes a new remark builder from a client.
	///
	/// This will first fetch metadata and runtime version from the runtime and then
	/// construct an offline client that provides the extrinsics.
	pub fn new_from_client<Client, Block>(client: Arc<Client>) -> sc_cli::Result<Self>
	where
		Block: BlockT<Hash = sp_core::H256>,
		Client: UsageProvider<Block> + ProvideRuntimeApi<Block>,
		Client::Api: Metadata<Block> + Core<Block>,
	{
		let genesis = client.usage_info().chain.best_hash;
		let api = client.runtime_api();

		let Ok(Some(metadata_api_version)) = api.api_version::<dyn Metadata<Block>>(genesis) else {
			return Err("Unable to fetch metadata runtime API version.".to_string().into());
		};

		if metadata_api_version > 1 {
			let Ok(mut supported_metadata_versions) = api.metadata_versions(genesis) else {
				return Err("Unable to fetch metadata versions".to_string().into());
			};

			let latest = supported_metadata_versions
				.pop()
				.ok_or("No metadata version supported".to_string())?;

			let version =
				api.version(genesis).map_err(|_| "No runtime version supported".to_string())?;

			let runtime_version = SubxtRuntimeVersion {
				spec_version: version.spec_version,
				transaction_version: version.transaction_version,
			};

			let metadata = api
				.metadata_at_version(genesis, latest)
				.map_err(|e| format!("Unable to fetch metadata: {:?}", e))?
				.ok_or("Unable to decode metadata".to_string())?;

			let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())?;

			let genesis = subxt::utils::H256::from(genesis.to_fixed_bytes());

			return Ok(Self {
				offline_client: OfflineClient::new(genesis, runtime_version, metadata),
			})
		}

		log::debug!("Found metadata version {}.", metadata_api_version);

		// Fall back to using the non-versioned metadata API.
		let metadata = api
			.metadata(genesis)
			.map_err(|e| format!("Unable to fetch metadata: {:?}", e))?;
		let version = api.version(genesis).unwrap();
		let runtime_version = SubxtRuntimeVersion {
			spec_version: version.spec_version,
			transaction_version: version.transaction_version,
		};

		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())?;

		let genesis = subxt::utils::H256::from(genesis.to_fixed_bytes());
		Ok(Self { offline_client: OfflineClient::new(genesis, runtime_version, metadata) })
	}
}

impl<C: Config> DynamicRemarkBuilder<C> {
	/// Constructs a new remark builder.
	pub fn new(
		metadata: subxt::Metadata,
		genesis_hash: C::Hash,
		runtime_version: SubxtRuntimeVersion,
	) -> Self {
		Self { offline_client: OfflineClient::new(genesis_hash, runtime_version, metadata) }
	}
}

impl ExtrinsicBuilder for DynamicRemarkBuilder<SubstrateConfig> {
	fn pallet(&self) -> &str {
		"system"
	}

	fn extrinsic(&self) -> &str {
		"remark"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		let signer = subxt_signer::sr25519::dev::alice();
		let dynamic_tx = subxt::dynamic::tx("System", "remark", vec![Vec::<u8>::new()]);

		let params = SubstrateExtrinsicParamsBuilder::new().nonce(nonce.into()).build();

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

/// Fetches the latest metadata from the given runtime blob.
pub fn fetch_latest_metadata_from_blob<HF: HostFunctions>(
	executor: &WasmExecutor<HF>,
	code_bytes: &Vec<u8>,
) -> sc_cli::Result<subxt::Metadata> {
	let runtime_caller = RuntimeCaller::new(executor, code_bytes.into());
	let version_result = runtime_caller.call("Metadata_metadata_versions", ());

	let opaque_metadata: OpaqueMetadata = match version_result {
		Ok(supported_versions) => {
			let latest_version = Vec::<u32>::decode(&mut supported_versions.as_slice())
				.map_err(|e| format!("Unable to decode version list: {e}"))?
				.pop()
				.ok_or("No metadata versions supported".to_string())?;

			let encoded = runtime_caller
				.call("Metadata_metadata_at_version", latest_version)
				.map_err(|_| "Unable to fetch metadata from blob".to_string())?;
			Option::<OpaqueMetadata>::decode(&mut encoded.as_slice())?
				.ok_or_else(|| "Metadata not found".to_string())?
		},
		Err(_) => {
			let encoded = runtime_caller
				.call("Metadata_metadata", ())
				.map_err(|_| "Unable to fetch metadata from blob".to_string())?;
			Decode::decode(&mut encoded.as_slice())?
		},
	};

	Ok(subxt::Metadata::decode(&mut (*opaque_metadata).as_slice())?)
}

struct BasicCodeFetcher<'a> {
	code: Cow<'a, [u8]>,
	hash: Vec<u8>,
}

impl<'a> FetchRuntimeCode for BasicCodeFetcher<'a> {
	fn fetch_runtime_code(&self) -> Option<Cow<[u8]>> {
		Some(self.code.as_ref().into())
	}
}

impl<'a> BasicCodeFetcher<'a> {
	pub fn new(code: Cow<'a, [u8]>) -> Self {
		Self { hash: sp_crypto_hashing::blake2_256(&code).to_vec(), code }
	}

	pub fn runtime_code(&'a self) -> RuntimeCode<'a> {
		RuntimeCode {
			code_fetcher: self as &'a dyn FetchRuntimeCode,
			heap_pages: None,
			hash: self.hash.clone(),
		}
	}
}

/// Simple utility that is used to call into the runtime.
struct RuntimeCaller<'a, 'b, HF: HostFunctions> {
	executor: &'b WasmExecutor<HF>,
	code_fetcher: BasicCodeFetcher<'a>,
}

impl<'a, 'b, HF: HostFunctions> RuntimeCaller<'a, 'b, HF> {
	pub fn new(executor: &'b WasmExecutor<HF>, code_bytes: Cow<'a, [u8]>) -> Self {
		Self { executor, code_fetcher: BasicCodeFetcher::new(code_bytes) }
	}

	fn call(&self, method: &str, data: impl Encode) -> sc_executor_common::error::Result<Vec<u8>> {
		let mut ext = BasicExternalities::default();
		self.executor
			.call(
				&mut ext,
				&self.code_fetcher.runtime_code(),
				method,
				&data.encode(),
				CallContext::Offchain,
			)
			.0
	}
}

#[cfg(test)]
mod tests {
	use crate::overhead::cmd::ParachainHostFunctions;
	use codec::Decode;
	use sc_executor::WasmExecutor;
	use sp_version::RuntimeVersion;

	#[test]
	fn test_fetch_latest_metadata_from_blob_fetches_metadata() {
		let executor: WasmExecutor<ParachainHostFunctions> = WasmExecutor::builder().build();
		let code_bytes = cumulus_test_runtime::WASM_BINARY
			.expect("To run this test, build the wasm binary of cumulus-test-runtime")
			.to_vec();
		let metadata = super::fetch_latest_metadata_from_blob(&executor, &code_bytes).unwrap();
		assert!(metadata.pallet_by_name("ParachainInfo").is_some());
	}

	#[test]
	fn test_runtime_caller_can_call_into_runtime() {
		let executor: WasmExecutor<ParachainHostFunctions> = WasmExecutor::builder().build();
		let code_bytes = cumulus_test_runtime::WASM_BINARY
			.expect("To run this test, build the wasm binary of cumulus-test-runtime")
			.to_vec();
		let runtime_caller = super::RuntimeCaller::new(&executor, code_bytes.into());
		let runtime_version = runtime_caller
			.call("Core_version", ())
			.expect("Should be able to call runtime_version");
		let runtime_version: RuntimeVersion = Decode::decode(&mut runtime_version.as_slice())
			.expect("Should be able to decode runtime version");
	}
}