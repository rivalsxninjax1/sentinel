# Local Ollama Reasoning Layer

## Architecture

```
LLMProvider (ABC)               app/llm/provider.py
    └── OllamaProvider          app/llm/ollama_provider.py
```

`LLMProvider.complete_structured(prompt, schema)` either returns a validated Pydantic
instance of `schema`, or `None`. There is no third outcome — callers never see a raw
string or a partially-validated object.

`SecurityReasoningEngine` (`app/intelligence/reasoning.py`) is the only thing allowed
to call an `LLMProvider`. It wraps every call so that:

- a missing/unreachable/misconfigured LLM (`provider=None`, or `check_availability()`
  returning False) always results in `ClassificationOutcome(classification=None,
  source="fallback")` — never an exception, never a blocked scan.
- any exception the provider raises is caught and also turned into a fallback outcome.
- the only way a `ClassificationOutcome` has `source="ai"` is if the provider returned
  a schema-validated `EndpointClassification`.

## Structured output enforcement

`OllamaProvider` uses Ollama's `format: "json"` request mode as a first line of
defense (guarantees parseable JSON), then independently validates the parsed JSON
against the requested Pydantic schema (guarantees it's the *right* JSON). If
validation fails, one repair attempt is made: the model is re-prompted with its
invalid output and the schema, and asked to try again. If that also fails,
`complete_structured()` returns `None`.

## Configuration

```yaml
llm:
  provider: ollama
  model: "llama3"                      # any locally pulled Ollama model
  base_url: "http://localhost:11434"
  temperature: 0
```

`SentinelConfig.llm` accepts this shape from Phase 0 onward; Phase 4 is the first
phase that actually uses it.

## What Ollama is used for (Phase 4)

Only endpoint/parameter classification + test-class recommendation
(`EndpointClassification` — see `app/llm/schemas.py`), via
`sentinel scan classify <scan_id>`. Roles are constrained to a fixed enum
(`ParameterSemantic`) and recommended tests to a fixed enum (`RecommendedTest`) mapped
onto vulnerability classes the deterministic engines (Phase 6+) will actually know how
to test for — the model cannot recommend a test type SENTINEL doesn't understand.

Classification results are persisted (`Classification` table) with `source` set to
either `"ai"` or `"fallback"`, so it's always possible to tell, per scan, how much of
the prioritization was actually AI-assisted versus default/no-opinion.

## What Ollama is NOT used for

- Never issues or approves an actual security test — see docs/architecture.md §44 ("AI
  should not control the whole system"). `scan classify` only writes `Classification`
  rows; nothing currently reads them to trigger a test (that wiring is Phase 5+ once
  tool adapters exist to act on recommendations).
- Never gets shell or network access of its own.
- Never has its raw text output stored or displayed — only the validated
  `EndpointClassification` fields.

## Testing without a running Ollama instance

`OllamaProvider` accepts an injectable `httpx` transport (same pattern as
`SentinelHTTPClient`), so its full request/response/repair/validation logic is unit
tested with `httpx.MockTransport` — no real Ollama process required. The
`check_availability()` unreachable path is also tested by pointing a config at a port
nothing listens on (`http://127.0.0.1:1`), which is exactly what happens automatically
if you run `scan classify` without Ollama installed: it degrades to `source="fallback"`
for everything and still completes.
