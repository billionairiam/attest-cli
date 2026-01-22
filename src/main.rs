use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use crypto::HashAlgorithm;
use env_logger::Env;
use log::{debug, info, warn};
use serde::Deserialize;
use serde_json::to_string_pretty;
use std::fs;
use std::sync::Arc;

use attest_cli::eventlog::*;
use attest_cli::tdx::*;
use attest_cli::{BoxedAttester, detect_tee_type};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a TEE quote and evidence.
    Generate(QuoteArgs),
    /// Parse a quote from a file and print its contents.
    Parse(ParseArgs),
    /// Replay cc eventlog to rebuild RTMR and perform integrity check.
    Replay(ReplayArgs),
}

#[derive(Args, Debug)]
struct QuoteArgs {
    /// Save the generated quote (base64) to a file. Defaults to 'quote.bin'.
    #[arg(short, long, value_name = "FILE_PATH", num_args(0..=1), default_missing_value = "quote.bin")]
    save: Option<String>,

    /// Extend the RTMR with a custom event (JSON string) before generating the quote.
    #[arg(short, long, value_name = "JSON_STRING")]
    extend: Option<String>,
}

#[derive(Args, Debug)]
struct ParseArgs {
    /// Path to the base64 encoded quote file.
    #[arg(value_name = "QUOTE_FILE_PATH")]
    path: String,
}

#[derive(Args, Debug)]
struct ReplayArgs {
    /// Print the parsed CC EventLog details to stdout.
    #[arg(short, long, default_value_t = false)]
    print: bool,
}

#[derive(Deserialize, Debug)]
struct EventInput {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => handle_generate(args).await,
        Commands::Parse(args) => handle_parse(args),
        Commands::Replay(args) => handle_replay(args).await,
    }
}

async fn handle_generate(args: QuoteArgs) -> Result<()> {
    let attester = create_attester()?;

    if let Some(json_str) = args.extend {
        extend_rtmr(&attester, &json_str).await?;
    }

    let evidence = get_tdx_evidence(&attester).await?;

    if let Some(path) = args.save {
        fs::write(&path, &evidence.quote).context("Failed to write quote to file")?;
        info!("Quote saved to {}", path);
    } else {
        println!("{}", to_string_pretty(&evidence.quote)?);
    }

    Ok(())
}

fn handle_parse(args: ParseArgs) -> Result<()> {
    info!("Parsing quote from file: {}", &args.path);

    let quote_b64 = fs::read_to_string(&args.path)
        .with_context(|| format!("Failed to read quote file from '{}'", &args.path))?;

    let quote_bytes = decode_base64(quote_b64.trim())?;
    let quote = parse_tdx_quote(&quote_bytes)?;

    // parse_tdx_quote usually returns a struct, we wrap it for the claim generator
    let claims = generate_parsed_claim(Some(quote), None, None)?;

    println!("{}", to_string_pretty(&claims)?);
    Ok(())
}

async fn handle_replay(args: ReplayArgs) -> Result<()> {
    let attester = create_attester()?;

    let evidence = get_tdx_evidence(&attester).await?;

    let quote_bytes = decode_base64(&evidence.quote)?;
    let quote = parse_tdx_quote(&quote_bytes)?;

    let ccel_option = if let Some(el_b64) = &evidence.cc_eventlog {
        if el_b64.is_empty() {
            warn!("CC Eventlog field is present but empty.");
            None
        } else {
            let ccel_data = decode_base64(el_b64)?;
            let ccel = CcEventLog::try_from(ccel_data)
                .map_err(|e| anyhow!("Failed to parse CC Eventlog: {:?}", e))?;

            debug!("Detailed CC Events:\n{}", &ccel.cc_events);

            // Perform Integrity Check
            perform_integrity_check(&quote, &ccel)?;

            Some(ccel)
        }
    } else {
        warn!("No CC Eventlog included inside the TDX evidence.");
        None
    };

    if args.print {
        let claims = generate_parsed_claim(None, ccel_option, None)?;
        info!(
            "Parsed CC eventlog details:\n{}",
            to_string_pretty(&claims)?
        );
    }

    Ok(())
}

/// Detects TEE type and creates a boxed attester instance.
fn create_attester() -> Result<Arc<BoxedAttester>> {
    let tee = detect_tee_type();
    let attester: BoxedAttester = tee.try_into().context("Failed to initialize Attester")?;
    Ok(Arc::new(attester))
}

/// Helper to extend the RTMR log based on JSON input.
async fn extend_rtmr(attester: &Arc<BoxedAttester>, json_str: &str) -> Result<()> {
    info!("Extending event log...");

    let event_input: EventInput = serde_json::from_str(json_str)
        .context("Invalid JSON for --extend. Expected {domain, operation, content}")?;

    let mut el = EventLog::new(attester.clone(), HashAlgorithm::Sha384, 17)
        .await
        .context("Failed to create event log interface")?;

    let ev = LogEntry::Event {
        domain: event_input.domain.as_str(),
        operation: event_input.operation.as_str(),
        content: event_input.content.as_str().try_into()?,
    };

    el.extend_entry(ev, 17)
        .await
        .context("Failed to extend entry")?;
    info!("Event log extended successfully.");
    Ok(())
}

/// Retrieves TDX evidence (Quote + EventLog) using a default zero report data.
async fn get_tdx_evidence(attester: &Arc<BoxedAttester>) -> Result<TdxEvidence> {
    let report_data = vec![0u8; 48];
    let evidence_str = attester
        .get_evidence(report_data)
        .await
        .context("Failed to get evidence from TEE")?;
    let evidence: TdxEvidence =
        serde_json::from_str(&evidence_str).context("Failed to deserialize TDX Evidence JSON")?;

    if evidence.quote.is_empty() {
        bail!("Retrieved TDX Quote is empty.");
    }
    Ok(evidence)
}

/// Decodes standard Base64 string to bytes.
fn decode_base64(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("Failed to decode base64 string")
}

/// Compares RTMRs from the Quote against the replayed EventLog.
fn perform_integrity_check(quote: &Quote, ccel: &CcEventLog) -> Result<()> {
    // Extract RTMRs from Quote (assuming quote accessors return &[u8])
    let rtmr_quote = Rtmr {
        rtmr0: to_array48(quote.rtmr_0())?,
        rtmr1: to_array48(quote.rtmr_1())?,
        rtmr2: to_array48(quote.rtmr_2())?,
        rtmr3: to_array48(quote.rtmr_3())?,
    };

    // Replay EventLog
    let mr_map = ccel.cc_events.replay_measurement_registry();

    // Helper to extract from map or use zero
    let get_rtmr = |idx: u32| -> Result<[u8; 48]> {
        let default = [0u8; 48];
        let slice = mr_map.get(&idx).map(|v| v.as_slice()).unwrap_or(&default);
        to_array48(slice) // Takes first 48 bytes safely
    };

    let rtmr_eventlog = Rtmr {
        rtmr0: get_rtmr(1)?,
        rtmr1: get_rtmr(2)?,
        rtmr2: get_rtmr(3)?,
        rtmr3: get_rtmr(4)?,
    };

    let rtmr_to_json = |label: &str, r: &Rtmr| {
        serde_json::json!({
            "source": label,
            "rtmr0": hex::encode(r.rtmr0),
            "rtmr1": hex::encode(r.rtmr1),
            "rtmr2": hex::encode(r.rtmr2),
            "rtmr3": hex::encode(r.rtmr3),
        })
    };

    let comparison_json = serde_json::json!({
        "rtmr_from_quote": rtmr_to_json("TD Quote", &rtmr_quote),
        "rtmr_from_eventlog": rtmr_to_json("CC EventLog Replay", &rtmr_eventlog),
        "status": "verifying..."
    });

    info!(
        "RTMR Integrity Check Details:\n{}",
        serde_json::to_string_pretty(&comparison_json)?
    );

    // Call the library's internal integrity check
    ccel.integrity_check(rtmr_quote)
        .context("Integrity check verification failed")?;

    info!("CC EventLog integrity check succeeded.");
    Ok(())
}

/// Helper to convert slice to fixed size array.
fn to_array48(slice: &[u8]) -> Result<[u8; 48]> {
    slice
        .get(0..48)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| anyhow!("Data length insufficient, expected 48 bytes"))
}
