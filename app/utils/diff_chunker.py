# app/utils/diff_chunker.py

"""Split a unified diff into prompt-sized chunks (P2-07).

The findings prompts hold at most `max_chars` of diff. Before P2-07 the diff was cut
at that size, so the LLM never saw most of a real PR. Now the diff is split into
chunks the LLM reviews one by one:

- whole files are packed together while they fit;
- a file that is too big is split at hunk (`@@`) boundaries, and each piece repeats
  the file's header lines so the model still knows which file it is reading;
- a hunk that is too big is split by lines, and a line that is too big by characters;
  each later piece of a split hunk gets a `@@ ... @@ (continued)` header with the
  right line numbers, so findings there still point at real lines.

`max_chunks` bounds the cost of one review. Whatever does not fit is reported, never
silently dropped: `chars_reviewed` counts the original diff text that went into a
chunk (repeated headers are not counted twice), and `files_not_fully_reviewed` counts
files that are missing all or part of their text.
"""

import re
from dataclasses import dataclass

_FILE_START = "diff --git "
_HUNK_RE = re.compile(r"^@@ -([0-9]+)(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@")
# Room kept in each piece of a split hunk for its continuation header
_CONTINUED_RESERVE = 72


@dataclass(frozen=True)
class DiffChunks:
    """The chunks to review and how much of the diff they cover."""

    chunks: list[str]
    chars_total: int
    chars_reviewed: int
    files_total: int
    files_not_fully_reviewed: int
    # How many chunks the whole diff needs; above len(chunks) when capped
    chunks_needed: int
    # Original diff characters in each chunk (repeated headers not counted)
    chunk_chars: list[int]

    @property
    def capped(self) -> bool:
        return self.chars_reviewed < self.chars_total


@dataclass(frozen=True)
class _Piece:
    """Part of one file: the text to send and how much original text it carries."""

    file_index: int
    text: str
    original_chars: int


def _split_files(diff: str) -> list[str]:
    """Split a diff into per-file sections, keeping every character exactly once."""
    lines = diff.splitlines(keepends=True)
    files: list[list[str]] = []
    for line in lines:
        if line.startswith(_FILE_START) or not files:
            files.append([])
        files[-1].append(line)
    return ["".join(f) for f in files]


def _split_header(section: str) -> tuple[str, list[str]]:
    """Return the file header (before the first hunk) and the hunks, as text."""
    lines = section.splitlines(keepends=True)
    header: list[str] = []
    hunks: list[list[str]] = []
    for line in lines:
        if line.startswith("@@"):
            hunks.append([])
        if hunks:
            hunks[-1].append(line)
        else:
            header.append(line)
    return "".join(header), ["".join(h) for h in hunks]


def _hard_split(text: str, size: int) -> list[str]:
    """Split text into parts of at most `size` chars, at line breaks where possible."""
    parts: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line) > size:  # a single line longer than the budget (minified code)
            if current:
                parts.append(current)
                current = ""
            full = (len(line) - 1) // size  # whole fragments; the rest joins `current`
            parts.extend(line[i * size : (i + 1) * size] for i in range(full))
            line = line[full * size :]
        if len(current) + len(line) > size:
            parts.append(current)
            current = ""
        current += line
    if current:
        parts.append(current)
    return parts


def _split_hunk(hunk: str, budget: int) -> list[tuple[str, int]]:
    """Split an oversized hunk into (text, original chars) parts of at most `budget`.

    Every part after the first starts with a continuation header giving the old and
    new line numbers where it starts, counted from the hunk's own `@@` line (P2-07).
    Without it the model would have no basis for the line numbers it reports.
    """
    match = _HUNK_RE.match(hunk)
    if not match or budget <= 2 * _CONTINUED_RESERVE:
        return [(part, len(part)) for part in _hard_split(hunk, budget)]

    parts = _hard_split(hunk, budget - _CONTINUED_RESERVE)
    old, new = int(match[1]), int(match[2])  # line numbers of the next line to start
    open_kind: str | None = None  # kind of a line cut mid-way by the previous part
    out: list[tuple[str, int]] = []
    for k, part in enumerate(parts):
        start_old, start_new = old, new
        old_count = new_count = 0
        for idx, line in enumerate(part.splitlines(keepends=True)):
            if k == 0 and idx == 0:
                continue  # the hunk's own @@ line
            continues = idx == 0 and open_kind is not None
            kind = open_kind if continues else line[:1]
            in_old = kind not in ("+", "\\")  # "\ No newline at end of file" is no line
            in_new = kind not in ("-", "\\")
            if not continues:
                old_count += in_old
                new_count += in_new
            if line.endswith("\n"):
                old += in_old
                new += in_new
                open_kind = None
            else:
                open_kind = kind
        header = (
            f"@@ -{start_old},{old_count} +{start_new},{new_count} @@ (continued)\n" if k else ""
        )
        if len(header) > _CONTINUED_RESERVE:  # absurd line numbers in a crafted diff
            header = ""
        out.append((header + part, len(part)))
    return out


def _file_pieces(index: int, section: str, max_chars: int) -> list[_Piece]:
    """One piece for a file that fits, else hunk-sized pieces with the header repeated."""
    if len(section) <= max_chars:
        return [_Piece(index, section, len(section))]

    header, hunks = _split_header(section)
    # Keep at least half the budget for code. A header longer than that (a huge path
    # or rename block) is cut in the repeats; the first piece still carries all of it.
    repeat = header if len(header) <= max_chars // 2 else header[: max_chars // 2]
    budget = max_chars - len(repeat)

    bodies: list[tuple[str, int]] = []  # (text to send, original chars it carries)
    for hunk in hunks:
        bodies.extend([(hunk, len(hunk))] if len(hunk) <= budget else _split_hunk(hunk, budget))

    pieces: list[_Piece] = []
    if len(header) > len(repeat):
        # The full header did not fit in a repeat, so send it on its own once
        pieces.extend(_Piece(index, part, len(part)) for part in _hard_split(header, max_chars))
        pieces.extend(_Piece(index, repeat + text, chars) for text, chars in bodies)
        return pieces

    # Pack consecutive hunks of this file under one copy of the header
    current: list[tuple[str, int]] = []
    size = 0
    first = True

    def flush() -> None:
        text = "".join(t for t, _ in current)
        chars = sum(c for _, c in current) + (len(header) if first else 0)
        pieces.append(_Piece(index, repeat + text, chars))

    for body in bodies:
        if current and len(repeat) + size + len(body[0]) > max_chars:
            flush()
            first = False
            current, size = [], 0
        current.append(body)
        size += len(body[0])
    if current or first:
        flush()
    return pieces


def chunk_diff(diff: str, max_chars: int, max_chunks: int) -> DiffChunks:
    """Split `diff` into at most `max_chunks` chunks of at most `max_chars` each."""
    if max_chars < 1 or max_chunks < 1:
        raise ValueError("max_chars and max_chunks must be at least 1")

    sections = _split_files(diff)
    if len(diff) <= max_chars:
        # One prompt holds it all, including an empty diff (reviewed as before)
        return DiffChunks([diff], len(diff), len(diff), len(sections), 0, 1, [len(diff)])

    pieces = [p for i, s in enumerate(sections) for p in _file_pieces(i, s, max_chars)]

    # Pack pieces in order: small files share a chunk, nothing is reordered
    packed: list[list[_Piece]] = []
    for piece in pieces:
        if packed and sum(len(p.text) for p in packed[-1]) + len(piece.text) <= max_chars:
            packed[-1].append(piece)
        else:
            packed.append([piece])

    kept = packed[:max_chunks]
    reviewed = sum(p.original_chars for chunk in kept for p in chunk)
    seen_chars: dict[int, int] = {}
    for chunk in kept:
        for p in chunk:
            seen_chars[p.file_index] = seen_chars.get(p.file_index, 0) + p.original_chars
    not_fully = sum(1 for i, s in enumerate(sections) if seen_chars.get(i, 0) < len(s))
    return DiffChunks(
        chunks=["".join(p.text for p in chunk) for chunk in kept],
        chars_total=len(diff),
        chars_reviewed=reviewed,
        files_total=len(sections),
        files_not_fully_reviewed=not_fully,
        chunks_needed=len(packed),
        chunk_chars=[sum(p.original_chars for p in chunk) for chunk in kept],
    )
