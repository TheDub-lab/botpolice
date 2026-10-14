# Contributing to botpolice

Thanks for your interest. botpolice is an open-core project and **detection and
logging only** — contributions must preserve that. Nothing in this project may
scan, attack, proxy, or contact any outside system, and no received byte may
ever be executed, evaluated, or written to disk.

## Ground rules

1. **Safety first.** Decoys stay low-interaction and passive. No outbound
   connections except the operator-configured alert webhook. Never add code that
   executes, evals, or persists attacker input.
2. **Local-first.** Keep the default bind on loopback and keep decoy ports out of
   documentation that encourages exposing them to the internet.
3. **No friction tests.** Tests must not require network access, root, or real
   external services.
4. **Licensing.** Contributions go to the open core under the MIT License, and
   you must sign the [CLA](CLA.md) (see below). We do not accept contributions to
   `enterprise/` through the open process — contact the maintainers.

## Contributor License Agreement (required)

Before a pull request can be merged you must agree to the
[Contributor License Agreement](CLA.md). It grants the project the right to
relicense your contribution so the same code can ship in both the open core and
the proprietary enterprise edition.

**How to sign:** add this exact statement as a comment on your pull request:

> I have read the CLA Document and I hereby sign the CLA.

If you are contributing on behalf of an employer, the Corporate CLA section must
be confirmed by an authorized signatory — contact the maintainers.

## Development setup

```bash
git clone https://github.com/TheDub-lab/botpolice
cd botpolice
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -e .                 # core is standard-library only
pip install ruff==0.6.9          # lint (optional)
```

The optional dashboard needs `pip install -r requirements.txt`.

## Tests and lint (must pass)

```bash
python -m unittest discover -s tests -v
ruff check botpolice tests
```

- Tests use `unittest` (no pytest, no network).
- Match the existing style: `from __future__ import annotations`, type hints,
  small focused functions, bounded reads, and explicit resource caps.
- Add tests for new behavior. For a new decoy service, follow
  `botpolice/services/adb.py` and `tests/test_adb.py`.

## Adding a decoy service

1. Add `botpolice/services/<name>.py` exposing
   `start_<name>(ctx, host, port) -> asyncio.AbstractServer`.
2. Register it in `botpolice/services/common.py:start_all`.
3. Add the default port to `DEFAULT_PORTS` in `botpolice/config.py`.
4. Emit events through the existing `EventSink` — never write logs directly.
5. Cap message size, session length, and concurrency; add an idle timeout.
6. Add tests and update the README.

## Branching model

- **`production`** is the integration branch. All work (including contributions)
  lands here first.
- **`main`** is the release branch and the repository default. It only receives
  reviewed changes merged from `production`.
- Open a pull request from `production` into `main` when a release is ready.
  Because the branches are typically identical right after a release, a PR is
  only meaningful once `production` has new commits ahead of `main`.

```bash
git switch production
# ... commit your work ...
git push origin production
# then open a PR: production -> main
```

## Commit and PR style

- Keep commits focused and messages in the imperative mood.
- Describe the safety implications of a change in the PR description.
- Do not include secrets, credentials, event logs, or canary stores in a commit.

## Trademarks

The "botpolice" name and logo are trademarks of TheDub-lab. Forks must remove or
rename the branding. See [TRADEMARKS.md](TRADEMARKS.md).
