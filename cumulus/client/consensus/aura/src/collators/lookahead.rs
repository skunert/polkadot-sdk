// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! A collator for Aura that looks ahead of the most recently included parachain block
//! when determining what to build upon.
//!
//! This collator also builds additional blocks when the maximum backlog is not saturated.
//! The size of the backlog is determined by invoking a runtime API. If that runtime API
//! is not supported, this assumes a maximum backlog size of 1.
//!
//! This takes more advantage of asynchronous backing, though not complete advantage.
//! When the backlog is not saturated, this approach lets the backlog temporarily 'catch up'
//! with periods of higher throughput. When the backlog is saturated, we typically
//! fall back to the limited cadence of a single parachain block per relay-chain block.
//!
//! Despite this, the fact that there is a backlog at all allows us to spend more time
//! building the block, as there is some buffer before it can get posted to the relay-chain.
//! The main limitation is block propagation time - i.e. the new blocks created by an author
//! must be propagated to the next author before their turn.

use codec::{Codec, Encode};
use cumulus_client_collator::service::ServiceInterface as CollatorServiceInterface;
use cumulus_client_consensus_common::{
	self as consensus_common, load_abridged_host_configuration, ParachainBlockImportMarker,
	ParentSearchParams,
};
use cumulus_client_consensus_proposer::ProposerInterface;
use cumulus_primitives_aura::AuraUnincludedSegmentApi;
use cumulus_primitives_core::{
	relay_chain::Hash as PHash, CollectCollationInfo, PersistedValidationData,
};
use cumulus_relay_chain_interface::RelayChainInterface;

use polkadot_node_primitives::SubmitCollationParams;
use polkadot_node_subsystem::messages::{
	CollationGenerationMessage, RuntimeApiMessage, RuntimeApiRequest,
};
use polkadot_overseer::Handle as OverseerHandle;
use polkadot_primitives::{CollatorPair, Id as ParaId, OccupiedCoreAssumption};

use futures::{channel::oneshot, prelude::*};
use sc_client_api::{backend::AuxStore, BlockBackend, BlockOf};
use sc_consensus::BlockImport;
use sc_consensus_aura::standalone as aura_internal;
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::AppPublic;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_aura::{AuraApi, Slot, SlotDuration};
use sp_core::crypto::Pair;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Member};
use sp_timestamp::Timestamp;
use std::{convert::TryFrom, sync::Arc, time::Duration};

use crate::collator::{self as collator_util, SlotClaim};

use super::slot_based_builder::CollatorMessage;

/// Parameters for [`run`].
pub struct Params<Block: BlockT, BI, CIDP, Client, Backend, RClient, CHP, SO, Proposer, CS> {
	/// Inherent data providers. Only non-consensus inherent data should be provided, i.e.
	/// the timestamp, slot, and paras inherents should be omitted, as they are set by this
	/// collator.
	pub create_inherent_data_providers: CIDP,
	/// Used to actually import blocks.
	pub block_import: BI,
	/// The underlying para client.
	pub para_client: Arc<Client>,
	/// The para client's backend, used to access the database.
	pub para_backend: Arc<Backend>,
	/// A handle to the relay-chain client.
	pub relay_client: RClient,
	/// A validation code hash provider, used to get the current validation code hash.
	pub code_hash_provider: CHP,
	/// A chain synchronization oracle.
	pub sync_oracle: SO,
	/// The underlying keystore, which should contain Aura consensus keys.
	pub keystore: KeystorePtr,
	/// The collator key used to sign collations before submitting to validators.
	pub collator_key: CollatorPair,
	/// The para's ID.
	pub para_id: ParaId,
	/// A handle to the relay-chain client's "Overseer" or task orchestrator.
	pub overseer_handle: OverseerHandle,
	/// The length of slots in this chain.
	pub slot_duration: SlotDuration,
	/// The length of slots in the relay chain.
	pub relay_chain_slot_duration: Duration,
	/// The underlying block proposer this should call into.
	pub proposer: Proposer,
	/// The generic collator service used to plug into this consensus engine.
	pub collator_service: CS,
	/// The amount of time to spend authoring each block.
	pub authoring_duration: Duration,
	/// Whether we should reinitialize the collator config (i.e. we are transitioning to aura).
	pub reinitialize: bool,
	pub collator_receiver: tokio::sync::mpsc::Receiver<CollatorMessage<Block>>,
}

/// Run async-backing-friendly Aura.
pub fn run<Block, P, BI, CIDP, Client, Backend, RClient, CHP, SO, Proposer, CS>(
	mut params: Params<Block, BI, CIDP, Client, Backend, RClient, CHP, SO, Proposer, CS>,
) -> impl Future<Output = ()> + Send + 'static
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block>
		+ BlockOf
		+ AuxStore
		+ HeaderBackend<Block>
		+ BlockBackend<Block>
		+ Send
		+ Sync
		+ 'static,
	Client::Api:
		AuraApi<Block, P::Public> + CollectCollationInfo<Block> + AuraUnincludedSegmentApi<Block>,
	Backend: sc_client_api::Backend<Block> + 'static,
	RClient: RelayChainInterface + Clone + 'static,
	CIDP: CreateInherentDataProviders<Block, ()> + 'static,
	CIDP::InherentDataProviders: Send,
	BI: BlockImport<Block> + ParachainBlockImportMarker + Send + Sync + 'static,
	SO: SyncOracle + Send + Sync + Clone + 'static,
	Proposer: ProposerInterface<Block> + Send + Sync + 'static,
	CS: CollatorServiceInterface<Block> + Send + Sync + 'static,
	CHP: consensus_common::ValidationCodeHashProvider<Block::Hash> + Send + 'static,
	P: Pair,
	P::Public: AppPublic + Member + Codec,
	P::Signature: TryFrom<Vec<u8>> + Member + Codec,
{
	async move {
		cumulus_client_collator::initialize_collator_subsystems(
			&mut params.overseer_handle,
			params.collator_key,
			params.para_id,
			params.reinitialize,
		)
		.await;

		let mut import_notifications = match params.relay_client.import_notification_stream().await
		{
			Ok(s) => s,
			Err(err) => {
				tracing::error!(
					target: crate::LOG_TARGET,
					?err,
					"Failed to initialize consensus: no relay chain import notification stream"
				);

				return
			},
		};

		while let Some(relay_parent_header) = import_notifications.next().await {
			let relay_parent = relay_parent_header.hash();

			if !is_para_scheduled(relay_parent, params.para_id, &mut params.overseer_handle).await {
				tracing::info!(
					target: crate::LOG_TARGET,
					?relay_parent,
					?params.para_id,
					"Para is not scheduled on any core, skipping import notification",
				);

				continue
			}

			while let Some(collator_message) = params.collator_receiver.recv().await {
				// Send a submit-collation message to the collation generation subsystem,
				// which then distributes this to validators.
				//
				// Here we are assuming that the leaf is imported, as we've gotten an
				// import notification.
				tracing::info!(target: "skunert", "Received collation, submitting to collator subsystem.");
				params
					.overseer_handle
					.send_msg(
						CollationGenerationMessage::SubmitCollation(SubmitCollationParams {
							relay_parent: collator_message.relay_parent,
							collation: collator_message.collation,
							parent_head: collator_message.parent_header.encode().into(),
							validation_code_hash: collator_message.validation_code_hash,
							result_sender: None,
						}),
						"SubmitCollation",
					)
					.await;
			}
		}
	}
}

// Checks if we own the slot at the given block and whether there
// is space in the unincluded segment.
async fn can_build_upon<Block: BlockT, Client, P>(
	slot: Slot,
	timestamp: Timestamp,
	parent_hash: Block::Hash,
	included_block: Block::Hash,
	client: &Client,
	keystore: &KeystorePtr,
) -> Option<SlotClaim<P::Public>>
where
	Client: ProvideRuntimeApi<Block>,
	Client::Api: AuraApi<Block, P::Public> + AuraUnincludedSegmentApi<Block>,
	P: Pair,
	P::Public: Codec,
	P::Signature: Codec,
{
	let runtime_api = client.runtime_api();
	let authorities = runtime_api.authorities(parent_hash).ok()?;
	let author_pub = aura_internal::claim_slot::<P>(slot, &authorities, keystore).await?;

	// Here we lean on the property that building on an empty unincluded segment must always
	// be legal. Skipping the runtime API query here allows us to seamlessly run this
	// collator against chains which have not yet upgraded their runtime.
	if parent_hash != included_block {
		if !runtime_api.can_build_upon(parent_hash, included_block, slot).ok()? {
			return None
		}
	}

	Some(SlotClaim::unchecked::<P>(author_pub, slot, timestamp))
}

/// Reads allowed ancestry length parameter from the relay chain storage at the given relay parent.
///
/// Falls back to 0 in case of an error.
async fn max_ancestry_lookback(
	relay_parent: PHash,
	relay_client: &impl RelayChainInterface,
) -> usize {
	match load_abridged_host_configuration(relay_parent, relay_client).await {
		Ok(Some(config)) => config.async_backing_params.allowed_ancestry_len as usize,
		Ok(None) => {
			tracing::error!(
				target: crate::LOG_TARGET,
				"Active config is missing in relay chain storage",
			);
			0
		},
		Err(err) => {
			tracing::error!(
				target: crate::LOG_TARGET,
				?err,
				?relay_parent,
				"Failed to read active config from relay chain client",
			);
			0
		},
	}
}

// Checks if there exists a scheduled core for the para at the provided relay parent.
//
// Falls back to `false` in case of an error.
async fn is_para_scheduled(
	relay_parent: PHash,
	para_id: ParaId,
	overseer_handle: &mut OverseerHandle,
) -> bool {
	let (tx, rx) = oneshot::channel();
	let request = RuntimeApiRequest::AvailabilityCores(tx);
	overseer_handle
		.send_msg(RuntimeApiMessage::Request(relay_parent, request), "LookaheadCollator")
		.await;

	let cores = match rx.await {
		Ok(Ok(cores)) => cores,
		Ok(Err(error)) => {
			tracing::error!(
				target: crate::LOG_TARGET,
				?error,
				?relay_parent,
				"Failed to query availability cores runtime API",
			);
			return false
		},
		Err(oneshot::Canceled) => {
			tracing::error!(
				target: crate::LOG_TARGET,
				?relay_parent,
				"Sender for availability cores runtime request dropped",
			);
			return false
		},
	};

	cores.iter().any(|core| core.para_id() == Some(para_id))
}
