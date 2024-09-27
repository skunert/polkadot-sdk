// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

use crate::shared::GenesisBuilderPolicy;
use sc_chain_spec::{ChainSpec, GenericChainSpec, GenesisConfigBuilderRuntimeCaller};
use sc_cli::Result;
use sp_storage::{well_known_keys::CODE, Storage};
use sp_wasm_interface::HostFunctions;
use std::{fs, path::PathBuf};
use serde_json::Value;

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
/// Build the genesis storage by either the Genesis Builder API, chain spec or nothing.
///
/// Behaviour can be controlled by the `genesis_builder` parameter.

/// When the runtime could not build the genesis storage.
const ERROR_CANNOT_BUILD_GENESIS: &str = "The runtime returned \
an error when trying to build the genesis storage. Please ensure that all pallets \
define a genesis config that can be built. This can be tested with: \
https://github.com/paritytech/polkadot-sdk/pull/3412";

/// Warn when using the chain spec to generate the genesis state.
const WARN_SPEC_GENESIS_CTOR: &'static str = "Using the chain spec instead of the runtime to \
generate the genesis state is deprecated. Please remove the `--chain`/`--dev`/`--local` argument, \
point `--runtime` to your runtime blob and set `--genesis-builder=runtime`. This warning may \
become a hard error any time after December 2024.";

pub fn get_code_bytes<F: HostFunctions>(
	chain_spec: &Option<Box<dyn ChainSpec>>,
	runtime: &Option<PathBuf>,
) -> Result<Vec<u8>> {
	match (chain_spec, runtime) {
		(None, Some(runtime_code_path)) => {
			let code_bytes = fs::read(runtime_code_path)
				.map_err(|e| format!("Unable to read runtime file: {:?}", e))?;

			Ok(code_bytes)
		},
		// Get the genesis state from the chain spec
		(Some(chain_spec), None) => {
			let storage = chain_spec
				.as_storage_builder()
				.build_storage()
				.map_err(|e| format!("Can not transform chain-spec to storage {}", e))?;
			let code_bytes =
				storage.top.get(CODE).ok_or("chain spec genesis does not contain code")?.clone();
			Ok(code_bytes)
		},
		(Some(_), Some(_)) =>
			Err("Both runtime and chain spec provided, please only provide one of both.".into()),
		(_, _) => Err("Please provide either a runtime or a chain spec.".into()),
	}
}
pub fn genesis_storage<F: HostFunctions>(
	genesis_builder: Option<GenesisBuilderPolicy>,
	runtime: &Option<PathBuf>,
	code_bytes: Option<&Vec<u8>>,
	genesis_builder_preset: &String,
	chain_spec: &Option<Box<dyn ChainSpec>>,
	storage_patcher: Option<Box<dyn Fn(Value) -> Value + 'static>>
) -> Result<Storage> {
	Ok(match (genesis_builder, runtime) {
        (Some(GenesisBuilderPolicy::None), Some(_)) => return Err("Cannot use `--genesis-builder=none` with `--runtime` since the runtime would be ignored.".into()),
        (Some(GenesisBuilderPolicy::None), None) => Storage::default(),
        (Some(GenesisBuilderPolicy::SpecGenesis | GenesisBuilderPolicy::Spec), Some(_)) =>
            return Err("Cannot use `--genesis-builder=spec-genesis` with `--runtime` since the runtime would be ignored.".into()),
        (Some(GenesisBuilderPolicy::SpecGenesis | GenesisBuilderPolicy::Spec), None) | (None, None) => {
            log::warn!("{WARN_SPEC_GENESIS_CTOR}");
            let Some(chain_spec) = chain_spec else {
                return Err("No chain spec specified to generate the genesis state".into());
            };

            let storage = chain_spec
                .build_storage()
                .map_err(|e| format!("{ERROR_CANNOT_BUILD_GENESIS}\nError: {e}"))?;

            storage
        },
        (Some(GenesisBuilderPolicy::SpecRuntime), Some(_)) =>
            return Err("Cannot use `--genesis-builder=spec` with `--runtime` since the runtime would be ignored.".into()),
        (Some(GenesisBuilderPolicy::SpecRuntime), None) => {
			let Some(code) = code_bytes else {
				return Err("Can not build genesis from runtime. Please provide a runtime.".into());
			};

			genesis_from_code::<F>(code.as_slice(), genesis_builder_preset)?
        },
        (Some(GenesisBuilderPolicy::Runtime), None) => return Err("Cannot use `--genesis-builder=runtime` without `--runtime`".into()),
        (Some(GenesisBuilderPolicy::Runtime), Some(_)) | (None, Some(_)) => {
            let Some(code) = code_bytes else {
				return Err("Can not build genesis from runtime. Please provide a runtime.".into());
			};

            genesis_from_code::<F>(code.as_slice(), genesis_builder_preset)?
        }
    })
}

/// Setup the genesis state by calling the runtime APIs of the chain-specs genesis runtime.
fn genesis_from_spec_runtime<EHF: HostFunctions>(
	chain_spec: &dyn ChainSpec,
	genesis_builder_preset: &String,
) -> Result<Storage> {
	log::info!("Building genesis state from chain spec runtime");
	let storage = chain_spec
		.build_storage()
		.map_err(|e| format!("{ERROR_CANNOT_BUILD_GENESIS}\nError: {e}"))?;

	let code: &Vec<u8> = storage.top.get(CODE).ok_or("No runtime code in the genesis storage")?;

	genesis_from_code::<EHF>(code, genesis_builder_preset)
}

fn genesis_from_code<EHF: HostFunctions>(
	code: &[u8],
	genesis_builder_preset: &String,
) -> Result<Storage> {
	let genesis_config_caller = GenesisConfigBuilderRuntimeCaller::<(
		sp_io::SubstrateHostFunctions,
		frame_benchmarking::benchmarking::HostFunctions,
		EHF,
	)>::new(code);
	let preset = Some(genesis_builder_preset.to_string());

	let mut storage = genesis_config_caller
		.get_storage_for_named_preset(preset.as_ref())
		.inspect_err(|e| {
			let presets = genesis_config_caller.preset_names().unwrap_or_default();
			log::error!(
				"Please pick one of the available presets with \
        `--genesis-builder-preset=<PRESET>`. Available presets ({}): {:?}. Error: {:?}",
				presets.len(),
				presets,
				e
			);
		})?;

	storage.top.insert(CODE.into(), code.into());

	Ok(storage)
}
