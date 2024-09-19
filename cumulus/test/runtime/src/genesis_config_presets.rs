use super::{
	AccountId, AuraConfig, AuraId, BalancesConfig, ParachainInfoConfig, RuntimeGenesisConfig,
	SudoConfig,
};
use alloc::{format, vec, vec::Vec};

use cumulus_primitives_core::{relay_chain::AccountPublic, ParaId};
use sp_core::{sp_std, sr25519, Pair, Public};
use sp_genesis_builder::PresetId;
use sp_runtime::traits::IdentifyAccount;

fn cumulus_test_runtime(
	invulnerables: Vec<AuraId>,
	endowed_accounts: Vec<AccountId>,
	id: ParaId,
) -> serde_json::Value {
	let config = RuntimeGenesisConfig {
		system: Default::default(),
		balances: BalancesConfig {
			balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
		},
		sudo: SudoConfig { key: Some(get_account_id_from_seed::<sr25519::Public>("Alice")) },
		transaction_payment: Default::default(),
		test_pallet: Default::default(),
		parachain_info: ParachainInfoConfig { parachain_id: id, ..Default::default() },
		// no need to pass anything to aura, in fact it will panic if we do. Session will take care
		// of this. `aura: Default::default()`
		aura: AuraConfig { authorities: invulnerables },
		aura_ext: Default::default(),
		parachain_system: Default::default(),
		glutton: Default::default(),
	};

	serde_json::to_value(config).expect("Could not build genesis config.")
}

pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub fn get_collator_keys_from_seed<AuraId: Public>(seed: &str) -> <AuraId::Pair as Pair>::Public {
	get_from_seed::<AuraId>(seed)
}

pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}
pub fn testnet_genesis_with_default_endowed(self_para_id: Option<ParaId>) -> serde_json::Value {
	let endowed = vec![
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		get_account_id_from_seed::<sr25519::Public>("Bob"),
		get_account_id_from_seed::<sr25519::Public>("Charlie"),
		get_account_id_from_seed::<sr25519::Public>("Dave"),
		get_account_id_from_seed::<sr25519::Public>("Eve"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie"),
		get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
		get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
		get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
		get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
		get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
	];
	let invulnerables = vec![
		get_collator_keys_from_seed::<AuraId>("Alice"),
		get_collator_keys_from_seed::<AuraId>("Bob"),
		get_collator_keys_from_seed::<AuraId>("Charlie"),
		get_collator_keys_from_seed::<AuraId>("Dave"),
		get_collator_keys_from_seed::<AuraId>("Eve"),
		get_collator_keys_from_seed::<AuraId>("Ferdie"),
	];
	cumulus_test_runtime(invulnerables, endowed, self_para_id.unwrap_or(1000.into()))
}

pub fn preset_names() -> Vec<PresetId> {
	vec![PresetId::from("development"), PresetId::from("local_testnet")]
}
pub fn get_preset(id: &sp_genesis_builder::PresetId) -> Option<sp_std::vec::Vec<u8>> {
	let patch = match id.try_into() {
		Ok("development") => testnet_genesis_with_default_endowed(Some(100.into())),
		Ok("local_testnet") => testnet_genesis_with_default_endowed(Some(100.into())),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}
