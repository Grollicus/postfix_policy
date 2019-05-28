A Postfix SMTP access policy delegation handler written in Rust. It handles protocol parsing and response sending to talk to Postfix.

[examples/request_dump.rs](examples/request_dump.rs) contains a small example that spawns a policy server listening on `/tmp/policy_example`, that dumps all incoming policy requests to stdout. Postfix can be configured to use it by using `check_policy_service { unix:/tmp/policy_example, default_action=DUNNO }`.

See [recipientfilter](https://github.com/Grollicus/recipientfilter) for a complete example how to use it.
