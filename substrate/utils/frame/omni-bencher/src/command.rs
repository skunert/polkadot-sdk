// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::Parser;
use frame_benchmarking_cli::BenchmarkCmd;
use sc_cli::{ChainSpec, CliConfiguration, Result, SubstrateCli};
use sc_service::NoExtension;
use sp_runtime::traits::BlakeTwo256;

/// # Polkadot Omni Benchmarking CLI
///
/// The Polkadot Omni benchmarker allows to benchmark the extrinsics of any Polkadot runtime. It is
/// meant to replace the current manual integration of the `benchmark pallet` into every parachain
/// node. This reduces duplicate code and makes maintenance for builders easier. The CLI is
/// currently only able to benchmark extrinsics. In the future it is planned to extend this to some
/// other areas.
///
/// General FRAME runtimes could also be used with this benchmarker, as long as they don't utilize
/// any host functions that are not part of the Polkadot host specification.
///
/// ## Installation
///
/// Directly via crates.io:
///
/// ```sh
/// cargo install frame-omni-bencher --profile=production
/// ```
///
/// from GitHub:
///
/// ```sh
/// cargo install --git https://github.com/paritytech/polkadot-sdk frame-omni-bencher --profile=production
/// ```
///
/// or locally from the sources:
///
/// ```sh
/// cargo install --path substrate/utils/frame/omni-bencher --profile=production
/// ```
///
/// Check the installed version and print the docs:
///
/// ```sh
/// frame-omni-bencher --help
/// ```
///
/// ## Usage
///
/// First we need to ensure that there is a runtime available. As example we will build the Westend
/// runtime:
///
/// ```sh
/// cargo build -p westend-runtime --profile production --features runtime-benchmarks
/// ```
///
/// Now as an example, we benchmark the `balances` pallet:
///
/// ```sh
/// frame-omni-bencher v1 benchmark pallet \
///     --runtime target/release/wbuild/westend-runtime/westend-runtime.compact.compressed.wasm \
///     --pallet "pallet_balances" --extrinsic ""
/// ```
///
/// For the exact arguments of the `pallet` command, please refer to the `pallet` sub-module.
///
/// ## Backwards Compatibility
///
/// The exposed pallet sub-command is identical as the node-integrated CLI. The only difference is
/// that it needs to be prefixed with a `v1` to ensure drop-in compatibility.
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
pub struct Command {
	#[command(subcommand)]
	sub: SubCommand,
}

impl SubstrateCli for Command {
	fn impl_name() -> String {
		"Omni-Bencher".to_string()
	}

	fn impl_version() -> String {
		"Omni-Bencher".to_string()
	}

	fn description() -> String {
		"Omni-Bencher".to_string()
	}

	fn author() -> String {
		"Omni-Bencher".to_string()
	}

	fn support_url() -> String {
		"Omni-Bencher".to_string()
	}

	fn copyright_start_year() -> i32 {
		10
	}

	fn load_spec(&self, path: &str) -> std::result::Result<Box<dyn ChainSpec>, String> {
		let path = std::path::PathBuf::from(path);

		Ok(Box::new(sc_service::GenericChainSpec::<NoExtension, ()>::from_json_file(path.clone())?)
			as Box<dyn sc_service::ChainSpec>)
	}
}

/// Root-level subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum SubCommand {
	/// Compatibility syntax with the old benchmark runner.
	V1(V1Command),
	// NOTE: Here we can add new commands in a forward-compatible way. For example when
	// transforming the CLI from a monolithic design to a data driven pipeline, there could be
	// commands like `measure`, `analyze` and `render`.
}

/// A command that conforms to the legacy `benchmark` argument syntax.
#[derive(Parser, Debug)]
pub struct V1Command {
	#[command(subcommand)]
	sub: V1SubCommand,
}

/// The `v1 benchmark` subcommand.
#[derive(Debug, clap::Subcommand)]
pub enum V1SubCommand {
	Benchmark(V1BenchmarkCommand),
}

/// Subcommands for `v1 benchmark`.
#[derive(Parser, Debug)]
pub struct V1BenchmarkCommand {
	#[command(subcommand)]
	sub: BenchmarkCmd,
}

type HostFunctions = (
	sp_statement_store::runtime_api::HostFunctions,
	cumulus_primitives_proof_size_hostfunction::storage_proof_size::HostFunctions,
);

impl Command {
	pub fn run(&self) -> Result<()> {
		match &self.sub {
			SubCommand::V1(V1Command { sub }) => match sub {
				V1SubCommand::Benchmark(V1BenchmarkCommand { sub }) => match sub {
					BenchmarkCmd::Pallet(pallet) => {
						if let Some(spec) = &pallet.shared_params.chain {
							return Err(format!(
									"Chain specs are not supported. Please remove `--chain={spec}` and use \
				`--runtime=<PATH>` instead"
								)
							.into())
						}

						pallet.run_with_spec::<BlakeTwo256, HostFunctions>(None)
					},
					BenchmarkCmd::Overhead(overhead_cmd) => {
						let runtime = sc_cli::build_runtime().expect("Can build tokio runtime");
						let config = overhead_cmd
							.create_configuration(self, runtime.handle().clone())
							.expect("Can build config");
						overhead_cmd.run_with_spec(config, None)
					},
					_ =>
						return Err(
							"Only the `v1 benchmark pallet` command is currently supported".into()
						),
				},
			},
		}
	}
}
//
// impl V1SubCommand {
// 	pub fn run(self) -> Result<()> {
// 		match self {
// 			V1SubCommand::Benchmark(V1BenchmarkCommand { sub }) => match sub {
// 				BenchmarkCmd::Pallet(pallet) => {
// 					if let Some(spec) = pallet.shared_params.chain {
// 						return Err(format!(
// 							"Chain specs are not supported. Please remove `--chain={spec}` and use \
// 				`--runtime=<PATH>` instead"
// 						)
// 						.into())
// 					}
//
// 					pallet.run_with_spec::<BlakeTwo256, HostFunctions>(None)
// 				},
// 				BenchmarkCmd::Overhead(overhead_cmd) => overhead_cmd.run_with_spec(None),
// 				_ =>
// 					return Err(
// 						"Only the `v1 benchmark pallet` command is currently supported".into()
// 					),
// 			},
// 		}
// 	}
// }
