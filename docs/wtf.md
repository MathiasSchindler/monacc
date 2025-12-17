# wtf — Wikipedia Terminal Facts

Date: 2025-12-17

`wtf` prints the plain-text summary of a Wikipedia article to stdout.

It talks to Wikipedia over HTTPS (Wikimedia encryption) and extracts the JSON `extract` field from the REST “page summary” API.

## Usage

```bash
# Basic usage (English)
wtf caffeine

# Query a specific language
wtf -l de Koffein
wtf -l fr Caféine

# First sentence only
wtf -s caffeine

# Combine flags
wtf -l de -s Koffein

# Multi-word queries
wtf "Albert Einstein"
wtf "central nervous system"
wtf central_nervous_system
```

### Output

```
$ wtf caffeine
Caffeine is a central nervous system (CNS) stimulant of the methylxanthine
class and is the most commonly consumed psychoactive substance globally...

$ wtf -s caffeine
Caffeine is a central nervous system (CNS) stimulant of the methylxanthine class and is the most commonly consumed psychoactive substance globally.

$ wtf -l de Koffein
Koffein ist ein Alkaloid aus der Stoffgruppe der Xanthine...
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success; article found and printed |
| 1 | Article not found (even after search fallback) |
| 2 | Usage error (invalid flags, missing query) |

---

## API

`wtf` uses these Wikipedia endpoints:

### Page Summary (primary)

```
https://{lang}.wikipedia.org/api/rest_v1/page/summary/{title}
```

**Response (JSON):**
```json
{
  "title": "Caffeine",
  "extract": "Caffeine is a central nervous system...",
  "description": "chemical compound"
}
```

The `extract` field is printed.

### OpenSearch (fallback)

```
https://{lang}.wikipedia.org/w/api.php?action=opensearch&search={query}&limit=1&format=json
```

**Response (JSON array):**
```json
[
  "caffeine",
  ["Caffeine"],
  ["Caffeine is a central nervous system..."],
  ["https://en.wikipedia.org/wiki/Caffeine"]
]
```

If the direct title lookup fails, `wtf` uses OpenSearch to find a best-match title and retries the summary endpoint.

HTTPS is handled via monacc’s in-tree TLS 1.3 client (Wikimedia encryption).

---

## Testing

### Manual Tests

```bash
# Basic functionality
./bin/wtf caffeine
./bin/wtf "Albert Einstein"
./bin/wtf Linux

# Language support
./bin/wtf -l de Deutschland
./bin/wtf -l fr France

# Short mode
./bin/wtf -s caffeine

# Edge cases
./bin/wtf ""                    # Should exit 2
./bin/wtf xyznonexistent123     # Should exit 1, try search fallback
./bin/wtf "United States"       # Multi-word
```

### Automated Tests

The default test suite stays **deterministic/offline**. `wtf` exposes a `--smoke` mode used by the tooling smoke tests.

If you want a local, networked sanity check, run:
```bash
./bin/wtf caffeine | head
```
