# Contributing to Relics

Welcome to Relics, the blockchain-killer digital money system! We’re building a lean, secure, offline-first currency, and we need *you*—C++ coders, security nerds, UI wizards, and crypto rebels—to make it legendary. Whether you’re optimizing crypto, adding post-quantum signatures, or designing the Relic Vault app, your contributions will shape the future of money.

## How to Contribute
1. **Fork the Repo**: Clone [relic-money](https://github.com/your-username/relic-money) and create a branch for your work.
2. **Pick an Issue**: Check the [Issues](https://github.com/your-username/relic-money/issues) tab for tasks like:
   - Optimize `.rlx` files with CBOR (Phase 2).
   - Add post-quantum Dilithium signatures (Phase 3).
   - Build P2P gossip protocol with libtorrent DHT (Phase 4).
   - Design Relic Vault app UI (Phase 5).
3. **Code**: Follow the style in `relic.cpp` (consistent naming, comments, secure practices).
4. **Test**: Run `make test` to ensure no regressions. Add new tests in `test_relic.cpp` for your changes.
5. **Submit a PR**: Write a clear PR description (e.g., “Added CBOR parsing, reduces .rlx size by 30%”). Link to the Issue.
6. **Discuss**: Join GitHub Discussions or ping us on X @RelicMoney for feedback.

## Code of Conduct
- **Be Respectful**: No toxicity, no gatekeeping. We’re all here to build.
- **Test Your Code**: PRs without tests won’t be merged.
- **Keep It Secure**: No hardcoded secrets, use `secure_wipe` for sensitive data.
- **Have Fun**: You’re forging a legend—enjoy the ride!
