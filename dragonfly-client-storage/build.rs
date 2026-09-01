/*
 * Copyright 2026 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#[cfg(feature = "urma")]
use std::env;
#[cfg(feature = "urma")]
use std::path::{Path, PathBuf};

fn main() {
    #[cfg(feature = "urma")]
    build_urma();
}

#[cfg(feature = "urma")]
fn build_urma() {
    println!("cargo:rerun-if-env-changed=UMDK_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=UMDK_LIB_DIR");
    println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");
    println!("cargo:rerun-if-changed=src/urma/ffi/shim.h");
    println!("cargo:rerun-if-changed=src/urma/ffi/shim.c");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS is set by cargo");
    assert_eq!(target_os, "linux", "feature `urma` requires a Linux target");

    let include_dir = locate_urma_include();
    let lib_dir = locate_urma_lib();
    track_urma_headers(&include_dir);

    let mut bindings = bindgen::Builder::default()
        .header("src/urma/ffi/shim.h")
        .allowlist_function("^dfurma_.*")
        .allowlist_type("^dfurma_.*")
        .allowlist_var("^DFURMA_.*$")
        .derive_debug(false)
        .derive_default(false)
        .layout_tests(true)
        .generate_comments(true);
    if let Ok(extra) = env::var("BINDGEN_EXTRA_CLANG_ARGS") {
        for arg in extra.split_whitespace() {
            bindings = bindings.clang_arg(arg);
        }
    }
    let generated = bindings
        .generate()
        .unwrap_or_else(|error| panic!("failed to generate URMA shim bindings: {error}"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    generated
        .write_to_file(out_dir.join("urma_bindings.rs"))
        .expect("failed to write generated URMA bindings");

    cc::Build::new()
        .file("src/urma/ffi/shim.c")
        .include(&include_dir)
        .warnings(true)
        .extra_warnings(true)
        .compile("dragonfly_urma_shim");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=urma");
}

#[cfg(feature = "urma")]
fn locate_urma_include() -> PathBuf {
    if let Some(configured) = env::var_os("UMDK_INCLUDE_DIR") {
        let configured = PathBuf::from(configured);
        for candidate in [configured.clone(), configured.join("ub/umdk/urma")] {
            if candidate.join("urma_api.h").is_file() {
                return candidate;
            }
        }
        panic!(
            "UMDK_INCLUDE_DIR={} does not contain urma_api.h",
            configured.display()
        );
    }
    for candidate in [
        PathBuf::from("/usr/include/ub/umdk/urma"),
        PathBuf::from("/usr/local/include/ub/umdk/urma"),
    ] {
        if candidate.join("urma_api.h").is_file() {
            return candidate;
        }
    }
    panic!("feature `urma` requires UMDK headers; set UMDK_INCLUDE_DIR")
}

#[cfg(feature = "urma")]
fn locate_urma_lib() -> PathBuf {
    if let Some(configured) = env::var_os("UMDK_LIB_DIR") {
        let configured = PathBuf::from(configured);
        assert!(
            configured.join("liburma.so").is_file(),
            "UMDK_LIB_DIR={} does not contain liburma.so",
            configured.display()
        );
        return configured;
    }
    for candidate in [
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib64"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu"),
        PathBuf::from("/usr/lib/aarch64-linux-gnu"),
    ] {
        if candidate.join("liburma.so").is_file() {
            return candidate;
        }
    }
    panic!("feature `urma` requires liburma; set UMDK_LIB_DIR")
}

#[cfg(feature = "urma")]
fn track_urma_headers(include_dir: &Path) {
    let Ok(entries) = include_dir.read_dir() else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "h") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
