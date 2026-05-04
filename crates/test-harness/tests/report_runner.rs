use std::fs;
use std::process::Command;

#[test]
fn report_runner_writes_send_leave_json_reports() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-harness-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "run",
            "-p",
            "test-harness",
            "--bin",
            "harness-report",
            "--quiet",
            "--",
            "--family",
            "send-leave/v1",
            "--seed",
            "42",
            "--cases",
            "2",
            "--out",
            out_dir.to_str().expect("utf8 temp path"),
        ])
        .status()
        .expect("runner starts");

    assert!(status.success(), "runner failed with {status}");

    let case0 = out_dir.join("send-leave-v1-seed-42-case-0.json");
    let case1 = out_dir.join("send-leave-v1-seed-42-case-1.json");
    assert!(case0.exists(), "case 0 report should exist");
    assert!(case1.exists(), "case 1 report should exist");

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&case0).expect("read report"))
            .expect("report JSON parses");
    assert_eq!(
        report["metadata"]["generated"]["family_name"],
        "send-leave/v1"
    );
    assert_eq!(report["metadata"]["generated"]["seed"], 42);
    assert_eq!(report["metadata"]["generated"]["case_index"], 0);
    assert!(
        report["observed_trace"]["observations"]
            .as_array()
            .is_some_and(|observations| !observations.is_empty())
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}
