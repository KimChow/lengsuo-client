use agent_mcp::client::StdioServerCommand;
use agent_mcp::{ClientConfig, Framing};
#[test]
fn command_and_config_debug_do_not_expose_launch_secrets() {
    let secret = "fake-mcp-key-for-test-only";
    let command = StdioServerCommand::new("test-server")
        .with_args(["--token", secret])
        .with_env("API_KEY", secret);
    assert!(
        !format!("{command:?}").contains(secret),
        "command debug must redact arguments and environment values"
    );
    let config = ClientConfig::stdio(command, Framing::default());
    assert!(
        !format!("{config:?}").contains(secret),
        "config debug must redact launch secrets"
    );
}
