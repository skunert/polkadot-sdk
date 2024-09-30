use crate::extrinsic::ExtrinsicBuilder;
use codec::Decode;
use sc_client_api::UsageProvider;
use sp_api::{Core, Metadata, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::AccountId32, Pair, H256};
use sp_runtime::{traits::Block as BlockT, MultiSignature, OpaqueExtrinsic};
use std::sync::Arc;
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

pub struct MySigner(pub sp_core::sr25519::Pair);

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

pub type SubstrateRemarkBuilder = DynamicRemarkBuilder<MultiAddressAccountIdConfig>;

pub struct DynamicRemarkBuilder<C: Config> {
	offline_client: OfflineClient<C>,
}

impl<C: Config> DynamicRemarkBuilder<C> {
	pub fn new_from_client<Client, Block>(client: Arc<Client>) -> sc_cli::Result<Self>
	where
		Block: BlockT<Hash = C::Hash>,
		Client: UsageProvider<Block> + HeaderBackend<Block>,
		Client: ProvideRuntimeApi<Block>,
		Client::Api: Metadata<Block> + Core<Block>,
	{
		let genesis = client.usage_info().chain.best_hash;
		let api = client.runtime_api();
		let mut supported_metadata_versions = api.metadata_versions(genesis).unwrap();
		let latest = supported_metadata_versions
			.pop()
			.ok_or("No runtime version supported".to_string())?;
		let version = api.version(genesis).unwrap();
		let runtime_version = RuntimeVersion {
			spec_version: version.spec_version,
			transaction_version: version.transaction_version,
		};
		let metadata = api
			.metadata_at_version(genesis, latest)
			.map_err(|e| format!("Unable to fetch metadata: {:?}", e))?
			.ok_or("Unable to decode metadata".to_string())?;
		let metadata = subxt::Metadata::decode(&mut (*metadata).as_slice())?;

		Ok(Self { offline_client: OfflineClient::new(genesis, runtime_version, metadata) })
	}
}

impl<C: Config> DynamicRemarkBuilder<C> {
	pub fn new(
		metadata: subxt::Metadata,
		genesis_hash: C::Hash,
		runtime_version: RuntimeVersion,
	) -> Self {
		Self { offline_client: OfflineClient::new(genesis_hash, runtime_version, metadata) }
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
		let signer = MySigner(sp_keyring::Sr25519Keyring::Alice.pair());
		let dynamic_tx = subxt::dynamic::tx("System", "remark", vec![Vec::<u8>::new()]);

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
