use crate::{extrinsic::ExtrinsicBuilder, overhead::cmd::opaque};
use codec::Decode;
use frame_support::__private::sp_tracing::tracing;
use sc_client_api::UsageProvider;
use sp_api::{Core, Metadata, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::AccountId32, Pair, H256};
use sp_runtime::{MultiSignature, OpaqueExtrinsic};
use std::{fmt::Debug, sync::Arc};
use subxt::{
	client::RuntimeVersion,
	config::{
		substrate::{BlakeTwo256, SubstrateExtrinsicParamsBuilder, SubstrateHeader},
		SubstrateExtrinsicParams,
	},
	tx::Signer,
	utils::MultiAddress,
	Config, OfflineClient,
};
use subxt_signer::eth::AccountId20;

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

pub struct DynamicRemarkBuilder<C: Config<Hash = H256>> {
	offline_client: OfflineClient<C>,
}

impl<C: Config<Hash = H256>> DynamicRemarkBuilder<C> {
	pub fn new<Client>(client: Arc<Client>) -> Self
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

pub struct EthRemarkBuilder<C: Config<Hash = H256>> {
	offline_client: OfflineClient<C>,
}

impl<C: Config<Hash = H256>> EthRemarkBuilder<C> {
	pub fn new<Client>(client: Arc<Client>) -> Self
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
