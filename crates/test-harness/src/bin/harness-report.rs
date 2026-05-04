use std::error::Error;
use std::path::PathBuf;

use test_harness::{generate_send_leave_family, run_generated_case_report};

#[derive(Debug)]
struct Args {
    family: String,
    seed: u64,
    cases: usize,
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    std::fs::create_dir_all(&args.out)?;

    let cases = match args.family.as_str() {
        "send-leave/v1" => generate_send_leave_family(args.seed, args.cases),
        other => return Err(format!("unsupported family {other}").into()),
    };

    for case in cases {
        let report = run_generated_case_report(&case, None).await?;
        let path = args.out.join(format!(
            "{}-seed-{}-case-{}.json",
            case.family_name.replace('/', "-"),
            case.seed,
            case.case_index
        ));
        std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    }

    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, Box<dyn Error>> {
    let mut family = "send-leave/v1".to_string();
    let mut seed = 0u64;
    let mut cases = 1usize;
    let mut out = PathBuf::from("target/harness-reports");

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => family = next_value(&mut args, "--family")?,
            "--seed" => seed = next_value(&mut args, "--seed")?.parse()?,
            "--cases" => cases = next_value(&mut args, "--cases")?.parse()?,
            "--out" => out = PathBuf::from(next_value(&mut args, "--out")?),
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    Ok(Args {
        family,
        seed,
        cases,
        out,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}

fn print_usage() {
    println!("Usage: harness-report [--family send-leave/v1] [--seed N] [--cases N] [--out DIR]");
}
