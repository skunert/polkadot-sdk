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

use codec::Encode;

use cumulus_primitives_core::relay_chain::Hash as PHash;
use cumulus_relay_chain_interface::RelayChainInterface;

use polkadot_node_primitives::SubmitCollationParams;
use polkadot_node_subsystem::messages::{
	CollationGenerationMessage, RuntimeApiMessage, RuntimeApiRequest,
};
use polkadot_overseer::Handle as OverseerHandle;
use polkadot_primitives::{CollatorPair, Id as ParaId};

use futures::{channel::oneshot, prelude::*};

use sp_blockchain::HeaderBackend;

use sp_consensus_aura::SlotDuration;

use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

use super::slot_based_builder::CollatorMessage;

/// Parameters for [`run`].
pub struct Params<Block: BlockT, RClient> {
	/// A handle to the relay-chain client.
	pub relay_client: RClient,
	/// The collator key used to sign collations before submitting to validators.
	pub collator_key: CollatorPair,
	/// The para's ID.
	pub para_id: ParaId,
	/// A handle to the relay-chain client's "Overseer" or task orchestrator.
	pub overseer_handle: OverseerHandle,
	/// The length of slots in this chain.
	pub slot_duration: SlotDuration,
	/// Whether we should reinitialize the collator config (i.e. we are transitioning to aura).
	pub reinitialize: bool,
	pub collator_receiver: tokio::sync::mpsc::Receiver<CollatorMessage<Block>>,
}

/// Run async-backing-friendly Aura.
pub fn run<Block, RClient>(
	mut params: Params<Block, RClient>,
) -> impl Future<Output = ()> + Send + 'static
where
	Block: BlockT,
	RClient: RelayChainInterface + Clone + 'static,
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

			tracing::info!(
				target: crate::LOG_TARGET,
				?relay_parent,
				?params.para_id,
				"Another round in lookahead collator",
			);

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
