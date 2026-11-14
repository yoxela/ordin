# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 The Ordin Authors

# Release commands (ORD-004). The logic lives in `cargo xtask`; these targets
# only supply the maintainer's local paths.
#
#   make pre-release              check main is ready and print the tag commands
#   make release-sign TAG=vX.Y.Z  verify CI's draft, rebuild, sign and publish
#
# ALLOWED_SIGNERS is the maintainer's own reviewed copy of
# release/allowed_signers, kept outside the repository. RELEASE_KEY is the
# release signing key (or its .pub, when the key is loaded in an agent).

ALLOWED_SIGNERS ?= $(HOME)/.config/ordin/allowed_signers
RELEASE_KEY ?= $(HOME)/.ssh/ordin_release_ed25519

.PHONY: pre-release release-sign

pre-release:
	cargo xtask pre-release

release-sign:
	@test -n "$(TAG)" || { echo "usage: make release-sign TAG=vX.Y.Z" >&2; exit 2; }
	cargo xtask release-sign "$(TAG)" --allowed-signers "$(ALLOWED_SIGNERS)" --key "$(RELEASE_KEY)"
