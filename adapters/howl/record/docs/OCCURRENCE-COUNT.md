# The `occurrence_count` field has no agreed home

**Status: UNRESOLVED. This crate implements the layout both sides currently agree on and
deliberately carries no `occurrence_count`.**

## What both sides agree on

The 246-byte payload inside a 256-byte cell, and every offset in it. This crate is byte-identical
to the counterpart codec on those, proven by the vectors in `tests/vectors/`.

## Where they disagree

A discovery tag identifies an ADDRESS, not a note, so one tag can carry many notes. The agreed
resolution keys rows by `(tag, occurrence)` and returns the total count alongside the first row, so a
cold restore costs two round trips instead of one per note.

That count has to travel somewhere, and the only space in the cell is the ten trailing bytes.

**The retrieval side's design places a 4-byte `occurrence_count` at offset 246**, making the
`occurrence = 0` row 250 bytes.

**The consuming side's committed decoder refuses any non-zero byte from 246 onward**, treating the
tail as frozen contract on the grounds that a non-zero tail means the sender is speaking a dialect it
cannot read. `a_non_zero_tail_is_refused_at_every_pad_byte` in this crate pins that behaviour, because
it is the behaviour that ships today.

**So as specified, every `occurrence = 0` row the retrieval side produces would be rejected by the
consumer.** Not silently - the decode throws - but the two designs cannot both be right.

## Why the count cannot simply go inside the record

The first question any reader asks. The answer is arithmetic, so it is stated rather than left implied:

| field | offset | width |
|---|---|---|
| `layout_version` | 0 | 1 |
| `record_kind` | 1 | 1 |
| `leaf_index` | 2 | 4 |
| `commitment_prefix` | 6 | 16 |
| `ephemeral_pk_x` | 22 | 32 |
| `cek_wrap` | 54 | 32 |
| `ciphertext_kept` | 86 | 5 x 32 = 160 |

**86 + 160 = 246.** The payload is completely full. There is no slack inside the record, which is why
every option below either spends the pad, moves the field out of the cell, or shrinks an existing
field.

## How many bytes are actually needed

The consuming side caps a tag at 100,000 occurrences. That is 17 bits, so **three bytes suffice**: a
widening would be 246 -> 249, not 246 -> 250, leaving seven pad bytes rather than six. Worth knowing
before the width is fixed, since the difference is a byte of future slack.

## Why this crate does not pick

The layout is frozen wire and a wire constant is an owner decision. Guessing here produces a codec
that agrees with one side and not the other, which is worse than one that agrees with the shipped
contract and says plainly where the gap is.

## The shapes available, without recommending one

1. **Widen the pad's contract**: the consumer accepts a 4-byte count at 246 and requires the
   remaining six to be zero. Cheapest, and it spends the layout's only remaining slack.
2. **Carry the count out of band**, in the response envelope rather than the cell. Costs no layout
   bytes; needs a response shape that has somewhere to put it.
3. **Shrink a field to make room inside 246.** The commitment prefix is the only candidate at 16
   bytes; halving it to 8 doubles the local false-hit rate, which is a privacy-adjacent parameter and
   a separate decision.

Option 3 also appears in the retrieval side's own notes as an unsettled question, listed alongside
"truncate the tag" and "store no tag" - so at least one of these is open on that side too.

## What settles it

An owner conversation across both repositories. It is cheap now: no production code on either side
depends on the placement, and this crate has no `occurrence_count` to migrate.
