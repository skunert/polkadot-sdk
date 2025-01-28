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

use codec::Codec;

use cumulus_primitives_aura::AuraUnincludedSegmentApi;
use cumulus_primitives_core::GetCoreSelectorApi;
use cumulus_relay_chain_interface::RelayChainInterface;

use polkadot_primitives::{CoreIndex, Header as RelayHeader, Id as ParaId, OccupiedCoreAssumption};

use crate::{collator::SlotClaim, collators::slot_based::SignalingTaskMessage, LOG_TARGET};
use cumulus_client_collator::service::ServiceInterface as CollatorServiceInterface;
use futures::prelude::*;
use polkadot_primitives::vstaging::{ClaimQueueOffset, DEFAULT_CLAIM_QUEUE_OFFSET};
use sc_client_api::{BlockBackend, UsageProvider};
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::AppPublic;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::{AuraApi, Slot};
use sp_core::crypto::Pair;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Member};
use std::{sync::Arc, time::Duration};

/// Parameters for [`run_block_builder`].
pub struct SignalingTaskParams<Block: BlockT, Client, Backend, RelayClient, Pub, CS> {
	/// The underlying para client.
	pub para_client: Arc<Client>,
	/// The para client's backend, used to access the database.
	pub para_backend: Arc<Backend>,
	/// A handle to the relay-chain client.
	pub relay_client: RelayClient,
	/// The underlying keystore, which should contain Aura consensus keys.
	pub keystore: KeystorePtr,
	/// The para's ID.
	pub para_id: ParaId,
	/// The amount of time to spend authoring each block.
	pub authoring_duration: Duration,
	pub building_task_sender:
		sc_utils::mpsc::TracingUnboundedSender<SignalingTaskMessage<Pub, Block>>,
	pub collator_service: CS,
	/// Relay chain slot duration.
	pub relay_slot_duration: Duration,
}

async fn handle_new_relay_parent<Block, P, Client, CS, RelayClient>(
	relay_parent_header: RelayHeader,
	para_id: ParaId,
	relay_client: RelayClient,
	para_client: &Client,
	para_backend: &Arc<impl sc_client_api::Backend<Block>>,
	keystore: &KeystorePtr,
	collator_service: &CS,
	relay_slot_duration: Duration,
) -> Option<(SlotClaim<P::Public>, Block::Header, CoreIndex, RelayHeader, u32)>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block>
		+ UsageProvider<Block>
		+ HeaderBackend<Block>
		+ BlockBackend<Block>
		+ Send
		+ Sync
		+ 'static,
	Client::Api:
		AuraApi<Block, P::Public> + GetCoreSelectorApi<Block> + AuraUnincludedSegmentApi<Block>,
	RelayClient: RelayChainInterface + Clone + 'static,
	CS: CollatorServiceInterface<Block> + Send + Sync + 'static,
	P: Pair,
	P::Public: AppPublic + Member + Codec,
	P::Signature: TryFrom<Vec<u8>> + Member + Codec,
{
	let relay_parent_hash = relay_parent_header.hash();
	tracing::debug!(target: crate::LOG_TARGET, ?relay_parent_hash, "Observed new relay parent in signaling task.");

	let core_index = crate::collators::cores_scheduled_for_para(
		relay_parent_hash,
		para_id,
		&relay_client,
		ClaimQueueOffset(DEFAULT_CLAIM_QUEUE_OFFSET),
	)
	.await
	.get(0)
	.copied()?;

	let pvd = relay_client
		.persisted_validation_data(relay_parent_hash, para_id, OccupiedCoreAssumption::Included)
		.await
		.ok()??;
	let max_pov_size = pvd.max_pov_size;

	let (included_block, parent) =
		crate::collators::find_parent(relay_parent_hash, para_id, &**para_backend, &relay_client)
			.await?;

	let (relay_slot, timestamp) = cumulus_client_consensus_common::relay_slot_and_timestamp(
		&relay_parent_header,
		relay_slot_duration,
	)?;

	let parent_hash = parent.hash;
	let parent_header = parent.header;

	let slot_duration =
		sc_consensus_aura::standalone::slot_duration_at(&*para_client, parent_hash).ok()?;

	let slot_now = Slot::from_timestamp(timestamp, slot_duration);

	tracing::debug!(
		target: crate::LOG_TARGET,
		?core_index,
		slot_info = ?slot_now,
		?timestamp,
		unincluded_segment_len = parent.depth,
		relay_parent = %relay_parent_hash,
		included = %included_block,
		parent = %parent_hash,
		"Building block."
	);

	let slot_claim = crate::collators::can_build_upon::<_, _, P>(
		slot_now,
		relay_slot,
		timestamp,
		parent_hash,
		included_block,
		&*para_client,
		&keystore,
	)
	.await?;

	// Do not try to build upon an unknown, pruned or bad block
	if !collator_service.check_block_status(parent_hash, &parent_header) {
		return None;
	}

	Some((slot_claim, parent_header, core_index, relay_parent_header, max_pov_size))
}

/// Run block-builder.
pub fn run_signaling_task<Block, P, Client, CS, Backend, RelayClient>(
	params: SignalingTaskParams<Block, Client, Backend, RelayClient, P::Public, CS>,
) -> impl Future<Output = ()> + Send + 'static
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block>
		+ UsageProvider<Block>
		+ HeaderBackend<Block>
		+ BlockBackend<Block>
		+ Send
		+ Sync
		+ 'static,
	Client::Api:
		AuraApi<Block, P::Public> + GetCoreSelectorApi<Block> + AuraUnincludedSegmentApi<Block>,
	Backend: sc_client_api::Backend<Block> + 'static,
	RelayClient: RelayChainInterface + Clone + 'static,
	CS: CollatorServiceInterface<Block> + Send + Sync + 'static,
	P: Pair,
	P::Public: AppPublic + Member + Codec,
	P::Signature: TryFrom<Vec<u8>> + Member + Codec,
{
	async move {
		tracing::info!(target: LOG_TARGET, "Starting lookahead slot-based block-builder task.");

		let mut import_notifications = match params.relay_client.import_notification_stream().await
		{
			Ok(s) => s,
			Err(err) => {
				tracing::error!(
					target: crate::LOG_TARGET,
					?err,
					"Failed to initialize consensus: no relay chain import notification stream"
				);
				return;
			},
		};

		while let Some(relay_parent_header) = import_notifications.next().await {
			let Some((slot_claim, parent_header, core_index, relay_parent_header, max_pov_size)) =
				handle_new_relay_parent::<Block, P, Client, CS, RelayClient>(
					relay_parent_header,
					params.para_id,
					params.relay_client.clone(),
					&params.para_client,
					&params.para_backend,
					&params.keystore,
					&params.collator_service,
					params.relay_slot_duration,
				)
				.await
			else {
				continue;
			};

			let build_signal = SignalingTaskMessage {
				slot_claim,
				parent_header,
				authoring_duration: params.authoring_duration,
				core_index,
				relay_parent_header: relay_parent_header.clone(),
				max_pov_size,
			};

			let _ = params.building_task_sender.unbounded_send(build_signal).inspect_err(|e| {
				tracing::error!(
					target: crate::LOG_TARGET,
					%e,
					"Unable to send message to block building task. This slot will be skipped.",
				)
			});
		}
	}
}
