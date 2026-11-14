// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! End-to-end tests of the release flows (ORD-004): `dist`, `pre-release`
//! and `release-sign`. git and ssh-keygen run for real; GitHub, the
//! container build and `cargo build` are faked.

mod dist;
mod fake;
mod pre_release;
mod repo;
mod sign;
