# Design system

**Last revised:** 2026-08-01 (Phase 0)
Implemented in `clients/desktop/src/styles/tokens.css`.

The design goal is **trust through legibility**. The user should feel the app is
telling them the truth about their security state, rather than hiding uncertainty
behind a padlock icon. Every rule below serves that.

---

## 1. Direction

The visual world is **sealed correspondence** — diplomatic pouches, wax seals,
security envelope paper, courier manifests. Careful custody, honest handling, a
visible record of who touched what.

Not cyberpunk. Not hacker-terminal. Not green-on-black. That aesthetic promises
invulnerability, which is precisely the promise this product refuses to make.

Deliberately avoided as templated: high-contrast serif on cream with a terracotta
accent; near-black with an acid-green accent; broadsheet columns with hairline
rules.

## 2. Colour

### 2.1 Brand tokens

```
--ink            #131A24   primary text on light, base surface on dark
--slate          #1F2A36   elevated surface, dark mode
--paper          #E8E9E4   base surface, light mode (security envelope stock)
--paper-fold     #D6D8D1   dividers, inactive surface
--verdigris      #4E8C7D   primary accent: verified, sent, active
--verdigris-deep #2F5F53   pressed and focus states
--amber          #C4913E   pending, unverified, degraded — never alarming, always visible
--seal           #A8443A   identity-change warnings and destructive confirmation only
--mute           #6B7684   secondary text, timestamps, metadata
```

`--seal` is semantic and rare. It is never used for branding, buttons, or
decoration. When a user sees that red it means their trust assumption changed.
Diluting it destroys its meaning.

### 2.2 Accessible text variants — required, not optional

§6.10 of the specification makes WCAG AA non-negotiable and specifically warns
that amber on light is the likely failure. It is. Measured against `--paper`:

| Brand token | Contrast on `--paper` | Verdict |
|---|---|---|
| `--amber` #C4913E | **2.30:1** | fails, badly — below even the 3:1 large-text floor |
| `--mute` #6B7684 | 3.78:1 | fails body text |
| `--verdigris` #4E8C7D | 3.20:1 | fails body text |
| `--seal` #A8443A | 4.84:1 | passes |

So the brand tokens are the *identity* of a colour, and each theme carries a
text-safe variant of it. Anything that renders as text uses the variant. The
brand token is reserved for fills and large decorative areas where it sits
against a surface it contrasts with.

**Light theme text variants** (verified against both `--paper` and white):

```
--fg-verified   #3B6A5F    5.04 : 1 on paper,  6.15 : 1 on white
--fg-pending    #7F5D27    4.92 : 1 on paper,  6.00 : 1 on white
--fg-mute       #5B6470    4.91 : 1 on paper,  6.00 : 1 on white
--fg-alarm      #9C3F35    5.42 : 1 on paper,  6.61 : 1 on white
```

**Dark theme text variants** (verified against both `--ink` and `--slate`):

```
--fg-verified   #5CA492    5.98 : 1 on ink,  4.98 : 1 on slate
--fg-pending    #C99A4B    6.83 : 1 on ink,  5.69 : 1 on slate
--fg-mute       #8B96A2    5.81 : 1 on ink,  4.84 : 1 on slate
--fg-alarm      #D4837A    6.10 : 1 on ink,  5.08 : 1 on slate
```

Every value above clears 4.5:1 with margin, so rounding in a browser's colour
management cannot silently drop one below the line. CI recomputes these on every
build and fails on a regression (`scripts/check-contrast.mjs`).

Hue is preserved across the variants: amber still reads as amber, verdigris still
reads as verdigris. What changes is lightness, and only as much as required.

### 2.3 Non-text contrast

Status dots, borders, and focus rings need 3:1. The theme variants above all
clear that automatically. The brand tokens do not universally — `--amber` is
2.30:1 on paper and `--seal` is 2.46:1 on slate — so **any element that conveys
state uses the theme variant, never the raw brand token.**

### 2.4 Never state through colour alone

Every coloured state is paired with a text label. The Custody Strip exists in
this form for exactly this reason. A user with a colour vision deficiency, or one
looking at a bad monitor in sunlight, reads the same three facts.

## 3. Typography

```
Display / UI      IBM Plex Sans        400, 500, 600
Security data     IBM Plex Mono        400, 500
```

The monospace choice is structural, not decorative. **Every piece of
machine-verifiable truth is set in mono:** safety numbers, key fingerprints,
onion addresses, message IDs, retention timers, manifest values, ciphersuite
names. **Every piece of human content is set in sans:** message bodies, contact
names, explanatory copy, button labels.

The typeface tells the user which register they are reading. Applied
inconsistently, it tells them nothing — so it is applied consistently.

Type scale: 12 / 14 / 16 / 20 / 28 / 40. Body copy at 16 with 1.55 line height.
Safety numbers at 20 mono, generous letter spacing, grouped in blocks of five.

Fonts are bundled locally. No webfont CDN — a font request is a third party
learning that the app is open, which is a §2.2 violation for no benefit.

## 4. The Custody Strip

A persistent band at the top of every conversation showing exactly three facts,
always, in monospace.

```
┌─────────────────────────────────────────────────┐
│  ⬤ VERIFIED        ⬤ TOR         ⬤ 7-DAY        │
│    identity          transport      retention    │
└─────────────────────────────────────────────────┘
```

| Field | States |
|---|---|
| Identity | `VERIFIED` (verified) · `UNVERIFIED` (pending) · `KEY CHANGED` (alarm) |
| Transport | `TOR` (verified) · `DIRECT` (pending) · `OFFLINE` (mute) |
| Retention | `KEEP` · `30-DAY` · `7-DAY` · `24-HOUR` (verified when set, mute at default) |

Rules it must obey:

- It never shows a reassuring state when the underlying state is uncertain.
  Unverified is amber and **stays** amber until the user has actually compared a
  safety number. Not until they dismissed a prompt about comparing one.
- Each field is tappable and opens the relevant explanation and control.
- It never collapses or hides on scroll. Persistent visibility is the point.
- Text labels, never a lone padlock. A padlock means nothing specific and gets
  read as a guarantee.
- It announces all three states as text to screen readers.

This is the one element the product is remembered by. Everything around it stays
quiet.

## 5. The Manifest

Every message carries a visible record of every stage it passed through.

Collapsed, a single mono line beneath the message:

```
⟩ 9 stages · AES-128-GCM · direct · delivered 14:02
```

Expanded, a vertical manifest with stage numbers in the verified colour, labels
in mute, values in body ink. All values in mono.

**Stages not run are shown, never hidden.** A text message shows
`02 METADATA REMOVED — n/a, text message`. A stage from a later phase shows
`not yet implemented`. An absent stage is itself information, and a manifest that
claims a stage it did not perform is worse than no manifest at all — test §8.6
asserts this.

The final row opens **"What the relay could see"**, which lists, for that
specific message, what the operator can observe. It has three blocks, and the
third is required:

```
  inbox id      7f3a…c219  (random, not you)
  blob size     1024 bytes (padded)
  arrival       within a 30-day TTL window

  NOT VISIBLE
  message content · your name · recipient name
  sender identity · filename · file type
  your IP address · exact send time

  STILL INFERABLE BY A NETWORK OBSERVER
  that you connected · roughly when · how often
```

Showing what is protected while omitting what leaks is the reassuring half-truth
Prime Directive 3 forbids.

While sending, the collapsed line animates through the stages rather than showing
a spinner. On failure it stops at the failed stage and names it:
`⟩ failed at stage 07 · routing · no relay connection`. Error reporting becomes
diagnosis for free.

## 6. Motion

Restrained. One orchestrated moment: on send, a brief seal-press — the bubble
compresses 2% and settles as state moves from `sending` to `sent`, 180ms,
ease-out. Everything else is a 120ms opacity or position transition, or nothing.

`prefers-reduced-motion` removes the seal-press, the stage progression animation,
and all transitions, leaving instant state changes. Not optional.

## 7. Copy rules

- Active voice. A control says what happens: "Wipe all data", not "Submit".
- An action keeps the same word through the whole flow. A button that says
  "Verify" produces a confirmation that says "Verified."
- Name things by what people control, never by how the system is built.
  "Keep messages for 7 days", not "Set TTL policy".
- Errors explain what happened and what to do. Never "Something went wrong."
  Instead: "Message not sent — no connection to the relay. It will send
  automatically when you reconnect."
- Errors do not apologise and are never vague.
- Empty states invite an action and include the control to take it.
- No exclamation marks. No emoji.
- Never the words in §2.4: unbreakable, uncrackable, military grade, bank grade,
  NSA proof, quantum proof, hacker proof, absolute, 100% secure. CI greps for
  these and fails the build.

## 8. Accessibility floor

Non-negotiable from Phase 1:

- WCAG AA contrast on all text — verified numerically in §2.2, checked in CI
- Visible keyboard focus on every interactive element; never `outline: none`
  without a replacement
- Full keyboard navigation, logical tab order, Escape closes modals
- Touch targets minimum 44×44px
- Semantic labels on all controls
- `prefers-reduced-motion` respected
- Responsive down to 360px width
- State never conveyed through colour alone
