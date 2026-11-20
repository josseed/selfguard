/**
 * This machine (kind "host"): persistence and credential exposure that infostealers and
 * supply-chain payloads abuse. Launch items, shell startup files, package manager and git
 * config, plaintext credentials, Python startup hooks (see src/sources/host/ and
 * docs/host.md). Warnings only: no references, no network. sources/builtin.ts registers every
 * entry; the order is the order files are listed in (the per-record file cap cuts the last).
 */
import { PACKAGE_CONFIG } from "../host/config.ts";
import { PLAINTEXT_CREDENTIALS } from "../host/credentials.ts";
import { LAUNCH_ITEMS } from "../host/launch.ts";
import { PYTHON_STARTUP_HOOKS } from "../host/python.ts";
import { SHELL_STARTUP } from "../host/shell.ts";
import type { SourceExtractor } from "../types.ts";

export const HOST_EXTRACTORS: SourceExtractor[] = [SHELL_STARTUP, PACKAGE_CONFIG, PLAINTEXT_CREDENTIALS, LAUNCH_ITEMS, PYTHON_STARTUP_HOOKS];
