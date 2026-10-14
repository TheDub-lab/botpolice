# Licensing

botpolice follows an **open-core** model: a fully open, self-hostable core, plus
a separately licensed enterprise layer.

## 1. Open core — MIT

Everything needed to run botpolice yourself is open source under the
[MIT License](LICENSE):

- the `botpolice/` Python package (event log, canaries, alerting, all decoy
  services including the ADB decoy);
- the CLI, the optional dashboard, and the test suite;
- `Dockerfile`, `docker-compose.yml`, `botpolice.service`, and the example
  configuration.

You may use, modify, and redistribute the core, including for commercial
purposes and inside a company.

## 2. Proprietary enterprise layer

The [`enterprise/`](enterprise/) directory — and any hosted, managed, or cloud
offering — is **proprietary** and is **not** covered by the MIT License. It
requires a separate written commercial agreement. See
[`enterprise/LICENSE`](enterprise/LICENSE).

Keeping this boundary explicit is what lets the core stay genuinely open while
the paid layer funds the project.

## 3. Contributions

All contributions require a [Contributor License Agreement](CLA.md) that grants
the project the right to relicense contributions. This is deliberate: it is what
allows the same code to ship in both the open core and the proprietary
enterprise edition. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 4. Trademarks

The **"botpolice"** name and logo are trademarks of TheDub-lab. The software
license grants no trademark rights. See [`TRADEMARKS.md`](TRADEMARKS.md) for what
is and is not permitted, including the rules for forks.

## 5. Your data

botpolice is local-first and defensive. Event logs, canary secrets, captured
shell commands, and pushed files belong to the **operator** — they stay on the
operator's own machine. The tool makes no outbound connection except the alert
webhook/Telegram endpoint the operator explicitly configures, and captured file
pushes are hashed and discarded, never stored. See the README for details.

## FAQ

**Can I use the core in a commercial product?**
Yes — the core is MIT. You may build on it, including commercially.

**Can I offer a hosted botpolice service?**
The MIT core permits it, but you may not use the "botpolice" name or branding
for your service (see TRADEMARKS.md), and you may not use any `enterprise/`
components without a commercial license.

**Can I fork it and sell it?**
Yes, under the MIT License, provided you remove/rename the botpolice branding
and keep the MIT notice. See TRADEMARKS.md.

**Why do you require a CLA?**
So the project can keep dual-licensing the core and the enterprise layer without
hunting down every contributor for permission later.

**Is this legal advice?**
No. These documents are templates. Have qualified counsel review them before
relying on them.
