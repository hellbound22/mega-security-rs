# mega-security-rs

An implementation of [Mega's security whitepaper](https://mega.nz/SecurityWhitepaper.pdf)

Note: This implementation is for educational and research purposes only. No copyright infrigment was intended.

for usage example check `tests/auth.rs`

### Some notes
- Mega does check for password security, this crate does not. I leave for whomever implements this crate to define what is a 'good password' or not.
- Mega uses 'mega.nz' to generate salt. As noted in the whitepaper, ideally this value would be an user identifier, so thats whats being used in this code. You can provide a 'domain' when creating the client though;
- The server uses a `HashMap<String, Client>` to store registered users. Ideally you would code your own Server, or send a PR making the server be a trait of sorts.
- This crate does not YET implement file or data encryption of any kind.
- The whitepaper does not elaborate on how sessions are stored or managed, The implementation seen on `Server` is just one of mine
- The obfuscation process given by the whitepaper is a bit skecthy, but it should be implemented correctly


### TODOs
- [ ] Ephemeral Accounts
- [ ] More tests

