use crate::error_exit;

use std::sync::OnceLock;

use clap::Parser;

/// Address at which the fuzzer attempts to create a snapshot once reached
pub static SNAPSHOT_ADDR: OnceLock<Option<usize>> = OnceLock::new();

/// Number of cores to run the fuzzer with
pub static NUM_THREADS: OnceLock<usize> = OnceLock::new();

/// Input provided as argument to the target being fuzzed
pub static FUZZ_INPUT: OnceLock<String> = OnceLock::new();

/// Additional information is printed out, alongside rolling statistics. Some parts of this only
/// work while running single-threaded
pub static DEBUG_PRINT: OnceLock<bool> = OnceLock::new();

/// Used by clap to parse command-line arguments
#[derive(Debug, Parser)]
#[clap(author = "seal9055", version, about = "tmp")]
#[clap(override_usage = "zfuzz [OPTION] -- /path/to/fuzzed_app [ ... ] (use `@@` to specify \
    position of fuzz-input in target-argv)\n\n    ex: zfuzz -- ./test_cases/test @@")]
pub struct Cli {
    #[clap(short = 'V', takes_value = false)]
    /// - Print version information
    pub version: bool,

    #[clap(short = 'h', takes_value = false)]
    /// - Print help information
    pub help: bool,

    #[clap(short = 'D', help_heading = "CONFIG", takes_value = false)]
    /// - Enable a rolling debug-print and information on which functions are lifted instead of the
    /// default print-window
    pub debug_print: bool,

    #[clap(short = 'e', help_heading = "CONFIG")]
    /// - File extension for the fuzz test input file if the target requires it
    pub extension: Option<String>,

    #[clap(short = 's', help_heading = "CONFIG")]
    /// - Take a snapshot of the target at specified address and launch future fuzz-cases off of this
    /// snapshot
    pub snapshot: Option<String>,

    #[clap(last = true)]
    /// The target to be fuzzed alongside its arguments
    pub fuzzed_app: Vec<String>,
}

/// Initialize configuration variables based on passed in commandline arguments, and verify that
/// the user properly setup their fuzz-case
pub fn handle_cli(args: &mut Cli) {
    DEBUG_PRINT.set(args.debug_print).unwrap();

    if args.fuzzed_app.is_empty() {
        error_exit("You need to specify the target to be fuzzed");
    }

    // Set the fuzz-input. If the user specified an extension, add that too
    FUZZ_INPUT.set(
        if let Some(ext) = &args.extension {
            format!("fuzz_input.{}\0", ext)
        } else {
            "fuzz_input\0".to_string()
        }
    ).unwrap();

    // Verify that the user supplied `@@` and use it to setup the fuzz-input's argv
    let index = args.fuzzed_app.iter().position(|e| e == "@@").unwrap_or_else(|| {
        error_exit("You need to specify how the fuzz-case input files should be passed in. This \
                   can be done using the `@@` flag as shown in the example under `Usage`.");
    });
    args.fuzzed_app[index] = FUZZ_INPUT.get().unwrap().to_string();
}
