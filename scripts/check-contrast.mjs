#!/usr/bin/env node
/*
 * Contrast check — SPEC §8.8, DESIGN_SYSTEM.md §2.2.
 *
 * Parses the semantic text tokens out of tokens.css and recomputes the WCAG
 * ratio for each against every surface it can legitimately appear on. Fails
 * the build on a regression.
 *
 * The point is that the numbers written in the design system are *derived*,
 * not asserted. A designer nudging a hex value for aesthetic reasons finds out
 * here, not from a user who cannot read the amber state.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const cssPath = join(here, "..", "clients", "desktop", "src", "styles", "tokens.css");

const AA_BODY = 4.5;
const AA_NON_TEXT = 3.0;

function channel(v) {
  const c = v / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function luminance(hex) {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? [...h].map((c) => c + c).join("") : h;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function ratio(a, b) {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const css = stripComments(readFileSync(cssPath, "utf8"));

function stripComments(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, "");
}

/**
 * Collect the custom properties declared in the first rule whose selector list
 * contains `selector`. Brace-matched rather than split on the first `}`, so a
 * nested rule cannot truncate the block.
 */
function block(selector) {
  const at = css.indexOf(selector);
  if (at === -1) throw new Error(`selector ${selector} not found`);
  const open = css.indexOf("{", at);
  let depth = 0;
  let close = open;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) {
      close = i;
      break;
    }
  }
  const body = css.slice(open + 1, close);
  const out = new Map();
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    out.set(m[1], m[2].trim());
  }
  return out;
}

// The brand block is the bare `:root {`. The light theme is declared on
// `:root, :root[data-theme="light"]`, so matching on the comma would pick up
// the wrong rule.
const rootTokens = block(":root {");
const lightTokens = new Map([...rootTokens, ...block(':root[data-theme="light"]')]);
const darkTokens = new Map([...rootTokens, ...block(':root[data-theme="dark"]')]);

/**
 * Resolve a token to a literal hex value, following `var()` indirection. A
 * semantic token is usually an alias for a brand token, and the alias is the
 * thing that has to be checked — following it is the whole point.
 */
function resolve(tokens, name, seen = new Set()) {
  if (seen.has(name)) throw new Error(`circular token reference at --${name}`);
  seen.add(name);
  const raw = tokens.get(name);
  if (raw === undefined) throw new Error(`token --${name} not declared`);
  if (raw.startsWith("#")) return raw;
  const ref = raw.match(/^var\(\s*--([\w-]+)\s*\)$/);
  if (ref) return resolve(tokens, ref[1], seen);
  throw new Error(`token --${name} is "${raw}", which is not a hex colour`);
}

const paper = resolve(rootTokens, "paper");
const ink = resolve(rootTokens, "ink");
const slate = resolve(rootTokens, "slate");
const white = "#FFFFFF";

const token = (tokens, name) => resolve(tokens, name);

const checks = [];

// Light theme: every text token must clear AA on both light surfaces.
for (const name of ["fg-body", "fg-mute", "fg-verified", "fg-pending", "fg-alarm"]) {
  const value = token(lightTokens, name);
  checks.push([`light --${name} on --paper`, value, paper, AA_BODY]);
  checks.push([`light --${name} on white`, value, white, AA_BODY]);
}

// Dark theme: --ink is the base surface, --slate the elevated one. Elevated is
// the tighter constraint, so both are checked rather than assuming.
for (const name of ["fg-body", "fg-mute", "fg-verified", "fg-pending", "fg-alarm"]) {
  const value = token(darkTokens, name);
  checks.push([`dark  --${name} on --ink`, value, ink, AA_BODY]);
  checks.push([`dark  --${name} on --slate`, value, slate, AA_BODY]);
}

// Focus rings are non-text but must remain visible, or the keyboard-navigation
// floor in DESIGN_SYSTEM.md §8 is not actually met.
checks.push(["light --focus-ring on --paper", token(lightTokens, "focus-ring"), paper, AA_NON_TEXT]);
checks.push(["dark  --focus-ring on --ink", token(darkTokens, "focus-ring"), ink, AA_NON_TEXT]);
checks.push(["dark  --focus-ring on --slate", token(darkTokens, "focus-ring"), slate, AA_NON_TEXT]);

let failed = 0;
for (const [label, fg, bg, min] of checks) {
  const r = ratio(fg, bg);
  const ok = r >= min;
  if (!ok) failed++;
  console.log(
    `${ok ? "pass" : "FAIL"}  ${label.padEnd(34)} ${fg} ${r.toFixed(2)}:1 (min ${min})`,
  );
}

if (failed > 0) {
  console.error(`\n${failed} contrast check(s) failed. See docs/DESIGN_SYSTEM.md §2.2.`);
  process.exit(1);
}
console.log(`\nAll ${checks.length} contrast checks passed.`);
