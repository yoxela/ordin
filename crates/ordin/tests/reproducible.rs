// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Packing is reproducible (ORD-150).
//!
//! Each sample is packed twice, by the `ordin` binary, under everything
//! that mustn't matter made different: the directory and the working
//! directory, the order its entries were made in (which changes the order
//! a directory lists them on tmpfs, where the second copy goes when
//! `/dev/shm` is one), the files' timestamps, how many
//! threads compress, and the time zone and locale. Both packages must have
//! the same identity and be the same bytes.
//!
//! Each sample's chunk index is also built again from the sample's own
//! files with `ordin-tree` alone, with the chunking the package records,
//! and must have the same digest: the chunking depends on nothing but the
//! files.

#[cfg(test)]
mod reproducible {
    use std::collections::BTreeMap;
    use std::fs::{self, FileTimes, Permissions};
    use std::io::{BufReader, Cursor};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, SystemTime};

    use ordin_archive::Reader;
    use ordin_core::Digest;
    use ordin_tree::chunk::{ChunkIndex, chunk_file};
    use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};
    use serde_json::Value;
    use tempfile::TempDir;

    /// What a sample holds at a path.
    #[derive(Clone)]
    enum Node {
        File(Vec<u8>, u32),
        Dir(u32),
        Symlink(&'static str),
        HardLink(&'static str),
    }

    /// A sample install root, and how it is packed.
    struct Sample {
        name: &'static str,
        nodes: Vec<(&'static str, Node)>,
        args: Vec<&'static str>,
    }

    /// Bytes that don't repeat, from a fixed seed.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect()
    }

    /// Text that compresses well, from a fixed seed.
    fn text(seed: u64, len: usize) -> Vec<u8> {
        let words = [
            "alpha", "beta", "gamma", "delta", "server", "package", "ordin",
        ];
        let mut out = Vec::with_capacity(len + 8);
        for (i, b) in noise(seed, len).iter().enumerate() {
            if out.len() >= len {
                break;
            }
            out.extend_from_slice(words[usize::from(*b) % words.len()].as_bytes());
            out.push(if i % 12 == 11 { b'\n' } else { b' ' });
        }
        out.truncate(len);
        out
    }

    fn samples() -> Vec<Sample> {
        let script = b"#!/bin/sh\nexec cat /usr/lib/tool/data.txt\n".to_vec();
        // The second file shares 6 MiB with the first: room for whole
        // chunks of the 1 MiB average to be the same in both.
        let big = noise(1, 8 << 20);
        let mut shared = big[2 << 20..].to_vec();
        shared.extend(noise(2, 1 << 20));
        vec![
            Sample {
                name: "tool",
                nodes: vec![
                    ("usr/bin/tool", Node::File(script, 0o755)),
                    ("usr/bin/t", Node::Symlink("tool")),
                    ("usr/bin/tool2", Node::HardLink("usr/bin/tool")),
                    (
                        "usr/lib/tool/data.txt",
                        Node::File(text(3, 200 << 10), 0o644),
                    ),
                    (
                        "usr/share/doc/tool/README",
                        Node::File(b"Prints its data.\n".to_vec(), 0o644),
                    ),
                    (
                        "usr/share/man/man1/tool.1",
                        Node::File(b".TH TOOL 1\n.SH NAME\ntool\n".to_vec(), 0o644),
                    ),
                    ("usr/share/tool/empty", Node::Dir(0o755)),
                    (
                        "usr/include/tool.h",
                        Node::File(b"int tool(void);\n".to_vec(), 0o644),
                    ),
                    (
                        "usr/share/locale/de/LC_MESSAGES/tool.mo",
                        Node::File(text(5, 4 << 10), 0o644),
                    ),
                ],
                args: vec!["--license", "MIT", "--license-file", "MIT=COPYING"],
            },
            Sample {
                name: "chunked",
                nodes: vec![
                    ("usr/lib/big/a", Node::File(big, 0o644)),
                    ("usr/lib/big/b", Node::File(shared, 0o644)),
                    // Exactly at the whole-file threshold.
                    ("usr/lib/big/edge", Node::File(noise(4, 1 << 20), 0o644)),
                ],
                args: vec!["--license", "NONE"],
            },
            Sample {
                name: "layout",
                nodes: vec![
                    (
                        "etc/tool/tool.conf",
                        Node::File(b"key = value\n".to_vec(), 0o644),
                    ),
                    ("var/lib/tool/seed", Node::File(b"0\n".to_vec(), 0o644)),
                    (
                        "opt/tool/bin/tool",
                        Node::File(b"#!/bin/sh\necho tool\n".to_vec(), 0o755),
                    ),
                    (
                        "opt/tool/share/doc/tool/README",
                        Node::File(b"A tool.\n".to_vec(), 0o644),
                    ),
                ],
                args: vec!["--license", "NONE", "--prefix", "opt/tool"],
            },
        ]
    }

    /// Makes `sample` at `root`, its entries in path order or the reverse,
    /// every file and directory stamped with `time`.
    fn build(sample: &Sample, root: &Path, reverse: bool, time: SystemTime) {
        let mut nodes = sample.nodes.clone();
        nodes.sort_by_key(|(path, _)| *path);
        if reverse {
            nodes.reverse();
        }
        fs::create_dir_all(root).unwrap();
        for (path, node) in &nodes {
            let at = root.join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            match node {
                Node::File(bytes, mode) => {
                    fs::write(&at, bytes).unwrap();
                    fs::set_permissions(&at, Permissions::from_mode(*mode)).unwrap();
                }
                Node::Dir(mode) => {
                    fs::create_dir_all(&at).unwrap();
                    fs::set_permissions(&at, Permissions::from_mode(*mode)).unwrap();
                }
                Node::Symlink(target) => std::os::unix::fs::symlink(target, &at).unwrap(),
                Node::HardLink(_) => {}
            }
        }
        // Hard links once what they name exists.
        for (path, node) in &nodes {
            if let Node::HardLink(target) = node {
                fs::hard_link(root.join(target), root.join(path)).unwrap();
            }
        }
        stamp(root, time);
    }

    /// Stamps every file and directory under `dir`, and `dir`, with `time`.
    fn stamp(dir: &Path, time: SystemTime) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stamp(&entry.path(), time);
            } else if kind.is_file() {
                set_times(&entry.path(), time);
            }
        }
        set_times(dir, time);
    }

    fn set_times(path: &Path, time: SystemTime) {
        fs::File::open(path)
            .unwrap()
            .set_times(FileTimes::new().set_accessed(time).set_modified(time))
            .unwrap();
    }

    /// One way of running `ordin pack`.
    struct Run<'a> {
        /// The working directory.
        cwd: &'a Path,
        /// The install root, as given on the command line.
        dir: String,
        /// The license file, as given.
        license: String,
        /// The output, as given.
        out: String,
        /// Compress on one thread.
        one_thread: bool,
        /// Extra environment.
        env: &'a [(&'a str, &'a str)],
    }

    /// Packs `sample` as `run` says and returns `--json`'s output.
    fn pack(sample: &Sample, run: &Run<'_>) -> Value {
        let mut args = vec![
            "pack".to_owned(),
            run.dir.clone(),
            "--name".to_owned(),
            sample.name.to_owned(),
            "--version".to_owned(),
            "1.0".to_owned(),
            "--summary".to_owned(),
            "A sample".to_owned(),
            "-o".to_owned(),
            run.out.clone(),
            "--json".to_owned(),
        ];
        args.extend(
            sample
                .args
                .iter()
                .map(|a| a.replace("COPYING", &run.license)),
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_ordin"));
        command.current_dir(run.cwd).args(&args);
        for (k, v) in run.env {
            command.env(k, v);
        }
        let one_thread = run.one_thread;
        // A process takes the CPUs the thread that starts it may use, and
        // `ordin pack` compresses on as many threads as it may use.
        let output = std::thread::spawn(move || {
            if one_thread {
                let allowed = sched_getaffinity(None).unwrap();
                let cpu = (0..CpuSet::MAX_CPU).find(|&c| allowed.is_set(c)).unwrap();
                let mut one = CpuSet::new();
                one.set(cpu);
                sched_setaffinity(None, &one).unwrap();
                assert_eq!(sched_getaffinity(None).unwrap().count(), 1);
            }
            command.output().unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// The chunk index built again from the files under `root` with
    /// `ordin-tree` alone, with `index`'s chunking.
    fn rechunked(root: &Path, index: &ChunkIndex) -> ChunkIndex {
        let mut listed = BTreeMap::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    dirs.push(entry.path());
                } else if kind.is_file() {
                    let file = fs::File::open(entry.path()).unwrap();
                    let cut =
                        chunk_file(BufReader::new(file), index.chunking(), |_, _| Ok(())).unwrap();
                    if let Some(listing) = cut.index_entry() {
                        listed.insert(listing.content(), listing);
                    }
                }
            }
        }
        ChunkIndex::new(*index.chunking(), listed.into_values().collect()).unwrap()
    }

    /// `statfs`'s type for tmpfs.
    const TMPFS: u64 = 0x0102_1994;

    /// Where the second copy goes: on tmpfs if `/dev/shm` is a directory
    /// that can be written to, where the order entries were made in is
    /// the order a directory lists them, and in the target directory
    /// otherwise.
    fn second_place() -> TempDir {
        TempDir::new_in("/dev/shm")
            .or_else(|_| TempDir::new_in(env!("CARGO_TARGET_TMPDIR")))
            .unwrap()
    }

    /// The names in `dir`, in the order it lists them.
    fn listed(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn packing_twice_differently_gives_the_same_package() {
        let temp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let t = temp.path();
        let elsewhere = second_place();
        let on_tmpfs = rustix::fs::statfs(elsewhere.path()).unwrap().f_type as u64 == TMPFS;
        let early = SystemTime::UNIX_EPOCH + Duration::from_secs(978_307_200);
        let late = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        for sample in samples() {
            let name = sample.name;
            // Run A: the entries made in path order, stamped 2001, packed
            // from inside, on every thread the machine offers.
            let a = t.join(name).join("a");
            build(&sample, &a.join("root"), false, early);
            fs::write(a.join("COPYING"), b"MIT License\n").unwrap();
            // Run B: elsewhere, made in reverse order, stamped 2033, packed
            // by absolute paths from another directory, on one thread, in
            // another time zone and locale.
            let b = elsewhere.path().join(name).join("elsewhere/deeper");
            build(&sample, &b.join("root"), true, late);
            fs::write(b.join("COPYING"), b"MIT License\n").unwrap();
            if on_tmpfs && name == "tool" {
                // The order really differs, so the walk's sorting is what
                // keeps the packages the same.
                assert_ne!(
                    listed(&a.join("root/usr/bin")),
                    listed(&b.join("root/usr/bin"))
                );
            }
            let first = pack(
                &sample,
                &Run {
                    cwd: &a,
                    dir: "root".to_owned(),
                    license: "COPYING".to_owned(),
                    out: "p.ordin".to_owned(),
                    one_thread: false,
                    env: &[],
                },
            );
            let absolute = |p: &str| b.join(p).display().to_string();
            let second = pack(
                &sample,
                &Run {
                    cwd: t,
                    dir: absolute("root"),
                    license: absolute("COPYING"),
                    out: absolute("p.ordin"),
                    one_thread: true,
                    env: &[
                        ("TZ", "Pacific/Kiritimati"),
                        ("LC_ALL", "tr_TR.UTF-8"),
                        ("LANG", "tr_TR.UTF-8"),
                    ],
                },
            );
            assert_eq!(first["package"], second["package"], "{name}");
            assert_eq!(first["image"], second["image"], "{name}");
            let (one, two) = (
                fs::read(a.join("p.ordin")).unwrap(),
                fs::read(b.join("p.ordin")).unwrap(),
            );
            assert!(
                one == two,
                "{name}: the files differ: {} bytes, BLAKE3 {}, and {} bytes, BLAKE3 {}",
                one.len(),
                Digest::blake3(&one),
                two.len(),
                Digest::blake3(&two)
            );

            // The chunk index, from the files alone.
            let mut reader = Reader::open(Cursor::new(one)).unwrap();
            let index = reader.chunk_index().unwrap();
            assert_eq!(
                rechunked(&a.join("root"), &index).digest().unwrap(),
                index.digest().unwrap(),
                "{name}"
            );
            // What each sample is there to exercise.
            let facets: Vec<&String> = first["facets"].as_object().unwrap().keys().collect();
            match name {
                "tool" => {
                    assert_eq!(facets, ["dev", "doc", "locale:de", "runtime"]);
                    assert!(index.files().is_empty());
                }
                "chunked" => {
                    // All three are listed: the threshold is inclusive.
                    assert_eq!(index.files().len(), 3);
                    // The two large ones are cut, and share chunks.
                    let cut: Vec<_> = index
                        .files()
                        .iter()
                        .filter(|f| f.chunks().len() > 1)
                        .collect();
                    assert_eq!(cut.len(), 2);
                    assert!(
                        cut[0].chunks().iter().any(|c| cut[1].chunks().contains(c)),
                        "the two files share no chunk"
                    );
                }
                _ => assert!(index.files().is_empty()),
            }
        }
    }
}
