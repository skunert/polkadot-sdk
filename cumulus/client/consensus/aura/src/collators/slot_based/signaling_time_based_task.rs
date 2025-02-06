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

use polkadot_primitives::{Block as RelayBlock, Id as ParaId};

use crate::{
	collators::{
		cores_scheduled_for_para,
		slot_based::{
			core_selector,
			relay_chain_data_cache::{RelayChainData, RelayChainDataCache},
			SignalingTaskMessage,
		},
	},
	LOG_TARGET,
};
use cumulus_client_collator::service::ServiceInterface as CollatorServiceInterface;
use futures::prelude::*;
use polkadot_primitives::vstaging::ClaimQueueOffset;
use sc_client_api::{BlockBackend, UsageProvider};
use sc_consensus_aura::SlotDuration;
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::AppPublic;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::{AuraApi, Slot};
use sp_core::crypto::Pair;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Member};
use sp_timestamp::Timestamp;
use std::{sync::Arc, time::Duration};
use tracing::log;

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
	/// Drift every slot by this duration.
	/// This is a time quantity that is subtracted from the actual timestamp when computing
	/// the time left to enter a new slot. In practice, this *left-shifts* the clock time with the
	/// intent to keep our "clock" slightly behind the relay chain one and thus reducing the
	/// likelihood of encountering unfavorable notification arrival timings (i.e. we don't want to
	/// wait for relay chain notifications because we woke up too early).
	pub slot_drift: Duration,
	pub building_task_sender:
		sc_utils::mpsc::TracingUnboundedSender<SignalingTaskMessage<Pub, Block>>,
	pub collator_service: CS,
}

#[derive(Debug)]
struct SlotInfo {
	pub timestamp: Timestamp,
	pub slot: Slot,
}

#[derive(Debug)]
struct SlotTimer<Block, Client, P> {
	client: Arc<Client>,
	drift: Duration,
	block_production_interval: Option<Duration>,
	last_reported_core_num: Option<u32>,
	_marker: std::marker::PhantomData<(Block, Box<dyn Fn(P) + Send + Sync + 'static>)>,
}

/// Returns current duration since Unix epoch.
fn duration_now() -> Duration {
	use std::time::SystemTime;
	let now = SystemTime::now();
	now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
		panic!("Current time {:?} is before Unix epoch. Something is wrong: {:?}", now, e)
	})
}

/// Returns the duration until the next slot from now.
fn time_until_next_slot(slot_duration: Duration, drift: Duration) -> (Duration, Slot) {
	let now = duration_now().as_millis() - drift.as_millis();

	let next_slot = (now + slot_duration.as_millis()) / slot_duration.as_millis();
	let remaining_millis = next_slot * slot_duration.as_millis() - now;
	(Duration::from_millis(remaining_millis as u64), Slot::from(next_slot as u64))
}

const RELAY_SLOT_DURATION: Duration = Duration::from_millis(6000);
impl<Block, Client, P> SlotTimer<Block, Client, P>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static + UsageProvider<Block>,
	Client::Api: AuraApi<Block, P::Public>,
	P: Pair,
	P::Public: AppPublic + Member + Codec,
	P::Signature: TryFrom<Vec<u8>> + Member + Codec,
{
	pub fn new_with_drift(client: Arc<Client>, drift: Duration) -> Self {
		Self {
			client,
			drift,
			block_production_interval: None,
			last_reported_core_num: None,
			_marker: Default::default(),
		}
	}

	pub fn update_scheduling(&mut self, num_cores_next_block: u32) {
		self.last_reported_core_num = Some(num_cores_next_block);
	}
	/// Returns a future that resolves when the next slot arrives.
	pub async fn wait_until_next_slot(&self) -> Result<SlotInfo, ()> {
		let Ok(slot_duration) = crate::slot_duration(&*self.client) else {
			tracing::error!(target: crate::LOG_TARGET, "Failed to fetch slot duration from runtime.");
			return Err(())
		};
		let para_slots_per_relay_block =
			(RELAY_SLOT_DURATION.as_millis() / slot_duration.as_millis() as u128) as u32;
		let expected_cores_next_relay = self.last_reported_core_num.unwrap_or(1);

		let mut block_production_interval = slot_duration.as_duration();
		if expected_cores_next_relay == para_slots_per_relay_block {
			tracing::info!(
				expected_cores_next_relay,
				para_slots_per_relay_block,
				"Expected cores match para slots."
			);
		} else if expected_cores_next_relay > para_slots_per_relay_block &&
			slot_duration.as_duration() == RELAY_SLOT_DURATION
		{
			block_production_interval = slot_duration.as_duration() / expected_cores_next_relay;
			tracing::info!(
				?block_production_interval,
				"We expect to produce for {expected_cores_next_relay} cores but only have {para_slots_per_relay_block} slots. Attempting to produce multiple blocks per slot."
			);
		}

		let (time_until_next_slot, next_slot) =
			time_until_next_slot(block_production_interval, self.drift);
		tokio::time::sleep(time_until_next_slot).await;
		let timestamp = sp_timestamp::Timestamp::from(
			*next_slot * block_production_interval.as_millis() as u64,
		);
		let aura_slot = Slot::from_timestamp(timestamp, slot_duration);
		let timestamp = sp_timestamp::Timestamp::from(
			*aura_slot * slot_duration.as_duration().as_millis() as u64,
		);
		tracing::info!(
			?slot_duration,
			?para_slots_per_relay_block,
			?next_slot,
			?timestamp,
			?aura_slot,
			"Emitting from slot timer"
		);
		Ok(SlotInfo { slot: aura_slot, timestamp })
	}
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
		tracing::info!(target: LOG_TARGET, "Starting slot-based block-builder task.");
		let SignalingTaskParams {
			relay_client,
			para_client,
			keystore,
			para_id,
			authoring_duration,
			para_backend,
			slot_drift,
			building_task_sender,
			collator_service,
		} = params;

		let mut scheduled_cores_preview = vec![];
		let mut slot_timer = SlotTimer::<_, _, P>::new_with_drift(para_client.clone(), slot_drift);

		let mut relay_chain_data_cache = RelayChainDataCache::new(relay_client.clone(), para_id);

		loop {
			// We wait here until the next slot arrives.
			let Ok(para_slot) = slot_timer.wait_until_next_slot().await else {
				return;
			};

			tracing::warn!(target: crate::LOG_TARGET, "New round in signaling task.");
			let Ok(relay_parent) = relay_client.best_block_hash().await else {
				tracing::warn!(target: crate::LOG_TARGET, "Unable to fetch latest relay chain block hash.");
				continue
			};

			let core_outlook =
				cores_scheduled_for_para(relay_parent, para_id, &relay_client, ClaimQueueOffset(1))
					.await;
			tracing::info!(num_cores = core_outlook.len(), "Corecount on the next relay.");

			let Some((included_block, parent)) =
				crate::collators::find_parent(relay_parent, para_id, &*para_backend, &relay_client)
					.await
			else {
				continue
			};

			let parent_hash = parent.hash;

			// Retrieve the core selector.
			let (core_selector, claim_queue_offset) =
				match core_selector(&*para_client, parent.hash, *parent.header.number()) {
					Ok(core_selector) => core_selector,
					Err(err) => {
						tracing::trace!(
							target: crate::LOG_TARGET,
							"Unable to retrieve the core selector from the runtime API: {}",
							err
						);
						continue
					},
				};

			let Ok(RelayChainData {
				relay_parent_header,
				max_pov_size,
				scheduled_cores,
				claimed_cores,
			}) = relay_chain_data_cache
				.get_mut_relay_chain_data(relay_parent, claim_queue_offset)
				.await
			else {
				continue;
			};

			// Fetch the scheduled cores for the next relay block.
			scheduled_cores_preview =
				cores_scheduled_for_para(relay_parent, para_id, &relay_client, ClaimQueueOffset(1))
					.await;

			slot_timer.update_scheduling(scheduled_cores.len() as u32);

			if scheduled_cores.is_empty() {
				tracing::debug!(target: LOG_TARGET, "Parachain not scheduled, skipping slot.");
				continue;
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					?relay_parent,
					"Parachain is scheduled on cores: {:?}",
					scheduled_cores
				);
			}

			let core_selector = core_selector.0 as usize % scheduled_cores.len();
			let Some(core_index) = scheduled_cores.get(core_selector) else {
				// This cannot really happen, as we modulo the core selector with the
				// scheduled_cores length and we check that the scheduled_cores is not empty.
				continue;
			};

			if !claimed_cores.insert(*core_index) {
				tracing::debug!(
					target: LOG_TARGET,
					"Core {:?} was already claimed at this relay chain slot",
					core_index
				);
				continue
			}

			let parent_header = parent.header;

			// We mainly call this to inform users at genesis if there is a mismatch with the
			// on-chain data.
			collator_service.check_block_status(parent_hash, &parent_header);

			let Ok(relay_slot) =
				sc_consensus_babe::find_pre_digest::<RelayBlock>(relay_parent_header)
					.map(|babe_pre_digest| babe_pre_digest.slot())
			else {
				tracing::error!(target: crate::LOG_TARGET, "Relay chain does not contain babe slot. This should never happen.");
				continue;
			};

			let slot_claim = match crate::collators::can_build_upon::<_, _, P>(
				para_slot.slot,
				relay_slot,
				para_slot.timestamp,
				parent_hash,
				included_block,
				&*para_client,
				&keystore,
			)
			.await
			{
				Some(slot) => slot,
				None => {
					tracing::debug!(
						target: crate::LOG_TARGET,
						?core_index,
						slot_info = ?para_slot,
						unincluded_segment_len = parent.depth,
						relay_parent = %relay_parent,
						included = %included_block,
						parent = %parent_hash,
						"Not building block."
					);
					continue
				},
			};

			tracing::debug!(
				target: crate::LOG_TARGET,
				?core_index,
				slot_info = ?para_slot,
				timestamp = ?slot_claim.timestamp(),
				unincluded_segment_len = parent.depth,
				relay_parent = %relay_parent,
				included = %included_block,
				parent = %parent_hash,
				"Building block."
			);
			let build_signal = SignalingTaskMessage {
				slot_claim,
				parent_header,
				authoring_duration,
				core_index: *core_index,
				relay_parent_header: relay_parent_header.clone(),
				max_pov_size: *max_pov_size,
			};
			building_task_sender
				.unbounded_send(build_signal)
				.expect("Should be able to send.")
		}
	}
}
