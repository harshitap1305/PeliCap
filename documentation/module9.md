## Module 9 — AI Copilot: Complete Implementation Plan

---

## What this module does and why it is the crown jewel

Every module before this one built infrastructure. Module 1 captures packets. Modules 2 through 5 parse, reconstruct, measure, and detect. Modules 6 and 7 store and retrieve. Module 8 visualizes. Module 9 is the reason a backend developer who has never touched Wireshark can open your tool and understand their network in 30 seconds.

The AI Copilot takes everything the other modules produce and makes it conversational. Instead of reading a table of RTT values, the user asks "why is my API slow?" and receives a specific, accurate, actionable answer grounded in the actual traffic data from their network right now. That is the product differentiation. That is what makes this more than a Wireshark clone.

The fundamental design principle of this module is that the AI never guesses. Every claim the AI makes is grounded in data retrieved from your own modules. If the AI says "DNS latency is elevated," it is because Module 4 reported `dns.avg_resolution_ms = 410` in the context snapshot. If the AI says "flow #4382 between 10.0.0.1 and 8.8.8.8 has a retransmission rate of 12%," it is because Module 7 returned that flow from a search query. The AI is an interpreter of your data, not a source of knowledge about it.

---

## Why Grok and what to know about it

Grok is xAI's model, accessible via an OpenAI-compatible API endpoint. This is the most important practical detail — the Grok API uses the exact same request and response format as the OpenAI API. This means you use the OpenAI SDK (or any OpenAI-compatible HTTP client) pointed at xAI's base URL. You do not need a separate Grok SDK.

The base URL is `https://api.x.ai/v1`. The models available are `grok-3-beta`, `grok-3-mini-beta`, and `grok-2-1212` among others. Use `grok-3-mini-beta` for most queries — it is significantly faster and cheaper than the full `grok-3-beta` and more than sufficient for network analysis explanations. Reserve `grok-3-beta` for complex multi-step reasoning queries like root cause analysis across multiple correlated anomalies.

Grok supports streaming responses via Server-Sent Events, function calling (tool use), and has a 131,072 token context window. The large context window is important — your metrics snapshots, flow records, and alert lists can be verbose and you need room for them alongside the conversation history.

The API key goes in an environment variable `GROK_API_KEY`. Never hardcode it. Never log it. Never include it in any response to the frontend.

---

## Architecture overview

The AI Copilot has five internal components.

The **Query Classifier** receives the user's raw text question and determines what kind of query it is. This classification drives everything else — what context to retrieve, which prompt template to use, whether to do a single API call or a multi-step reasoning chain.

The **Context Builder** retrieves the relevant data from your other modules based on the query classification. It calls the MetricsEngine, the AlertStore, the SearchEngine, and the StorageLayer to assemble a context package — a structured collection of data that the LLM needs to answer the question accurately.

The **Prompt Assembler** takes the context package and the conversation history and constructs the final prompt that gets sent to Grok. This involves a system prompt, the assembled context formatted as structured data, the conversation history for multi-turn continuity, and the user's question.

The **Grok Client** handles the actual API communication. It sends the assembled prompt to the Grok API, receives the streaming response, and forwards the token stream to the frontend via Server-Sent Events or WebSocket.

The **Response Processor** parses the completed response, extracts any structured data the AI generated (search queries, flow IDs, suggested actions), stores the conversation in PostgreSQL, and builds the final response object that includes the text, the extracted structured data, and metadata.

---

## The AI layer lives in Python with FastAPI

The original blueprint specifies Python with FastAPI for the AI layer, and this is correct. The reason is practical: the Python ecosystem for LLM integration is far more mature than C++. The `openai` Python package handles Grok's OpenAI-compatible API natively including streaming, retry logic, and error handling. Your C++ backend exposes REST endpoints that the Python AI layer calls. The frontend talks to the Python AI layer directly for chat. This creates a clean separation.

The Python service runs as a separate Docker container. It exposes a REST API on port 8001 (your C++ backend is on 8000). The frontend sends chat messages to the Python service. The Python service calls your C++ API to retrieve context data. The Python service calls the Grok API. The Python service streams the response back to the frontend.

The Python dependencies: `fastapi`, `uvicorn`, `openai` (for Grok's OpenAI-compatible API), `httpx` (for calling your C++ backend), `pydantic` (for request/response validation), `python-dotenv` (for environment variables), `tiktoken` (for counting tokens to stay within context limits).

---

## Query classification — the seven query types

Before retrieving context or constructing a prompt, classify the user's query into one of seven types. Each type has different context requirements and different prompt strategies.

**Type 1: General health check.** The user wants a broad overview of network health right now. Trigger phrases: "what's happening", "how is my network", "give me a summary", "is everything okay", "what should I know." Context needed: full metrics snapshot for the last 60 seconds, all active alerts, top 5 talkers, protocol breakdown. This is the most common query type.

**Type 2: Performance diagnosis.** The user is experiencing slowness and wants to know why. Trigger phrases: "why is it slow", "why is my API slow", "what's causing latency", "response times are bad", "things are sluggish." Context needed: HTTP latency metrics, DNS latency metrics, TCP RTT metrics, retransmission rate, top slowest flows from Module 7, active performance-related alerts. This is the highest-value query type.

**Type 3: Specific flow investigation.** The user is asking about a specific connection, IP, or service. Trigger phrases include IP addresses, domain names, service names, port numbers. "What is 8.8.8.8 doing", "show me traffic to the database", "explain connection from 192.168.1.10", "what happened with the postgres connection." Context needed: results from a targeted search query to Module 7, the specific flows retrieved, their statistics, any associated alerts.

**Type 4: Security investigation.** The user is concerned about suspicious activity. Trigger phrases: "is there anything suspicious", "any attacks", "unusual traffic", "port scan", "should I be worried", "any security issues." Context needed: security-related alerts (port scan, SYN flood, NXDOMAIN spike, unusual traffic patterns), top talkers, flows to unusual ports, external IP connections.

**Type 5: Protocol explanation.** The user wants to understand what they are seeing in educational terms. Trigger phrases: "explain", "what is", "what does this mean", "I don't understand", "teach me about", "why does TCP." Context needed: specific packet or flow data if the user references one, otherwise no live data context needed — answer from general networking knowledge. This is the Learning Mode use case.

**Type 6: Historical analysis.** The user wants to understand what happened in the past. Trigger phrases: "what happened yesterday", "show me what was happening at 3pm", "last night", "earlier today", "compare to this morning." Context needed: historical metrics from the time range the user specifies, alerts from that period, top flows from that period retrieved from PostgreSQL.

**Type 7: Action recommendation.** The user wants to know what to do about a problem. Trigger phrases: "what should I do", "how do I fix this", "recommendations", "next steps", "how to resolve." Context needed: current alerts, metrics snapshot, and the context of any previous turns in the conversation where a problem was identified.

The classification is done with a simple keyword-based approach first, then a pattern-matching function over the query string. Do not use a separate LLM call to classify — that doubles latency and cost. A well-written Python function with keyword lists and regex patterns classifies correctly 95% of the time. For the 5% edge cases, the general health check prompt is the correct fallback.

---

## The Context Builder — what data to retrieve for each query type

The context builder calls your C++ backend's REST API using `httpx` with async calls. All context retrieval is done concurrently using `asyncio.gather` so multiple API calls run in parallel.

**For all query types**, always include these as the base context:

The current capture status from `GET /api/capture/status` — interface name, whether capture is active, total packets captured in the current session, session start time.

The last 60-second metric summary from `GET /api/metrics/summary?window=60` — the compact JSON that Module 4 produces covering network, TCP, DNS, and HTTP metrics.

Active critical and warning alerts from `GET /api/alerts?severity=WARNING&limit=10` — the 10 most recent non-dismissed alerts.

**For Type 1 (general health)**, add:

Top 10 talkers from `GET /api/metrics/top-talkers`.

Protocol breakdown from `GET /api/metrics/network?window=60`.

Flow count trend — active flows now versus 5 minutes ago to detect connection storms.

**For Type 2 (performance diagnosis)**, add:

Extended metrics window from `GET /api/metrics/summary?window=300` — 5 minute window to see trends rather than just the last minute.

Top 10 slowest flows from `GET /api/search/flows?sort_by=rtt_avg_us&sort_dir=desc&limit=10`.

Slowest DNS domains from `GET /api/dns/slow?limit=5`.

Slowest HTTP endpoints from `GET /api/http/slow?limit=5`.

If the user mentioned a specific service or IP, search flows involving that IP or SNI.

**For Type 3 (specific flow investigation)**, extract the IP address, domain name, or port number from the user's query using regex. Then call:

`GET /api/search/flows?q=src_ip:{ip} OR dst_ip:{ip}&limit=20&sort_by=start_time&sort_dir=desc` for IP-based queries.

`GET /api/search/flows?q=tls_sni:{domain}&limit=20` for domain-based queries.

`GET /api/flows/{id}` if the user references a specific flow ID.

Include the full statistics of the top 5 matching flows, not just summaries.

**For Type 4 (security)**, add:

All critical security alerts from `GET /api/alerts?type=PORT_SCAN,HOST_SCAN,SYN_FLOOD,DNS_NXDOMAIN_SPIKE&limit=20`.

Flows to unusual ports — ports that are not 80, 443, 53, 22, 25, 5432 — from search.

Top external IP destinations that are not well-known services.

**For Type 5 (explanation)**, add context only if the user references specific data. Otherwise use minimal context — just the capture status. The educational answer comes from the LLM's training knowledge, not your data.

**For Type 6 (historical)**, extract the time range from the user's query. "Yesterday" maps to the previous calendar day. "At 3pm" maps to a 1-hour window around 15:00 on the current day. "This morning" maps to 06:00 to 12:00 today. Then query:

Historical metrics from `GET /api/metrics/history?metric_name=bytes_in_per_sec&start={start}&end={end}&resolution=1m`.

Historical alerts from `GET /api/alerts?start_time={start}&end_time={end}&limit=20`.

Top flows during that period from `GET /api/search/flows?start_time={start}&end_time={end}&sort_by=bytes&limit=10`.

**For Type 7 (recommendations)**, the context comes primarily from the conversation history. Extract the problem that was identified in previous turns and add the current alerts and metrics for confirmation that the problem still exists.

---

## Token budget management

The Grok API has a 131,072 token context window. Your system prompt costs approximately 800 tokens. The conversation history grows with each turn. The context data can be large. You must manage the token budget carefully.

Allocate the budget as follows. System prompt: 1,000 tokens reserved. Conversation history: up to 8,000 tokens (approximately 10 turns of conversation). Context data: up to 6,000 tokens. User query: 500 tokens. Response budget: the remaining tokens, with a maximum output of 2,000 tokens per response.

To measure token usage, use the `tiktoken` library with the `cl100k_base` encoding (which is close enough for Grok's tokenizer). Before sending the request, count the tokens in each section and truncate if necessary.

When truncating context data, use this priority order: keep base context (metrics summary and alerts) first, then query-specific context, then historical data. When truncating conversation history, always keep the first turn (where the user may have established context) and the most recent 5 turns, dropping middle turns if necessary.

When truncating flow records, keep the summary statistics (flow ID, IPs, bytes, duration, RTT, retransmits) and drop the per-packet level detail. Five flows with full statistics fit in about 800 tokens. Ten flows with summary statistics fit in about 600 tokens.

---

## The system prompt — the most important thing you will write

The system prompt is the instruction set that controls how the AI behaves in every single response. It is sent as the first message in every API call. Every word matters. Write it carefully, test it extensively, and treat it as code that needs to be maintained.

The system prompt has seven sections.

**Section 1: Identity and role.** Tell the AI exactly who it is and what its job is. It is a network analysis assistant embedded in Network Copilot, an AI-powered network observability platform. Its job is to help network engineers, backend developers, and DevOps teams understand their network traffic, diagnose performance problems, and identify security issues. It has access to real-time network data including packet captures, flow records, performance metrics, and anomaly alerts.

**Section 2: Data grounding rule.** This is the most important rule. The AI must only make claims about the current network that are supported by the data provided in the context. If the context shows DNS latency of 410ms, it can say DNS latency is elevated. If the context does not mention TLS handshake times, it cannot say TLS handshakes are slow. When the data does not support a claim, it must say "I don't have data about that in the current context" rather than speculating. This prevents hallucination of network facts.

**Section 3: Response format rules.** Responses should be clear and direct. Lead with the most important finding, then support it with specific numbers from the context. Use the specific values from the context data — "DNS latency is 410ms (your baseline is 45ms)" is better than "DNS latency is elevated." Use bullet points for lists of findings. Use bold for key metrics and values. When recommending investigation steps, format them as a numbered list. Keep responses under 400 words unless the user asks for a detailed explanation. Never pad responses with generic networking advice that is not supported by the actual data.

**Section 4: Generated search query rule.** When the AI identifies a specific pattern worth investigating (a slow endpoint, a suspicious IP, a high-retransmission flow), it must generate a search query that the user can run. Format these as a special block that the frontend can detect and render as a clickable chip. The format is `[SEARCH: query_string]`. For example: `[SEARCH: src_ip:10.0.0.1 AND retransmits > 5]`. Always include at least one search query in performance diagnosis and security investigation responses.

**Section 5: Severity calibration.** Define what language to use for different severity levels so the AI does not catastrophize minor issues or understate serious ones. Retransmission rate above baseline: use "elevated" not "critical." Retransmission rate above 15%: use "significant" or "concerning." Active port scan: use "detected" and recommend immediate action. Traffic spike within normal operating range: use "notable" not "alarming."

**Section 6: Technical accuracy rules.** The AI must use correct networking terminology. RTT is round-trip time. Retransmissions indicate packet loss or network congestion. NXDOMAIN means the DNS name does not exist. A TCP RST terminates a connection immediately. TLS SNI is the server name indication in the ClientHello. Do not simplify these terms for non-technical users — if the user is using this tool they have a technical background. Do explain acronyms on first use in a conversation.

**Section 7: Scope boundaries.** The AI should not provide advice on network security configurations, firewall rules, or infrastructure changes beyond what is observable in the traffic data. It should not make claims about what traffic is malicious versus legitimate — only describe what is unusual compared to baseline. It should not provide IP addresses of external parties in a way that could be used for offensive purposes. If asked to do something outside these boundaries, it should explain what it can help with instead.

---

## Prompt templates for each query type

Each query type has a different prompt structure that wraps the context data. These are the templates.

**Template 1: General health check.**

```
NETWORK CONTEXT — Last 60 seconds:
{metrics_snapshot_formatted}

ACTIVE ALERTS ({alert_count}):
{alerts_formatted}

TOP NETWORK TALKERS:
{top_talkers_formatted}

USER QUESTION: {user_query}

Provide a concise health summary. Lead with overall status (healthy/degraded/critical). 
List the 2-3 most important findings with specific numbers. 
If everything looks normal, say so clearly.
```

**Template 2: Performance diagnosis.**

```
NETWORK CONTEXT — Last 5 minutes:
{metrics_snapshot_5min_formatted}

PERFORMANCE METRICS:
- HTTP p50/p95/p99 latency: {http_latency}
- DNS avg/p95 resolution time: {dns_latency}
- TCP RTT p50/p95: {tcp_rtt}
- TCP retransmission rate: {retransmit_rate}%
- Zero window events: {zero_window_count}

SLOWEST FLOWS:
{slow_flows_formatted}

SLOWEST DNS DOMAINS:
{slow_dns_formatted}

SLOWEST HTTP ENDPOINTS:
{slow_http_formatted}

ACTIVE PERFORMANCE ALERTS:
{perf_alerts_formatted}

USER QUESTION: {user_query}

Diagnose the performance issue. Identify the primary bottleneck with specific evidence.
Rank contributing factors by impact. Include a [SEARCH: ...] query to investigate further.
```

**Template 3: Specific flow investigation.**

```
FLOWS MATCHING "{search_target}":
{flows_formatted}

FLOW STATISTICS DETAIL:
{flow_stats_formatted}

ASSOCIATED ALERTS:
{flow_alerts_formatted}

USER QUESTION: {user_query}

Explain what these flows show. Describe the communication pattern, 
performance characteristics, and anything unusual. 
Include a [SEARCH: ...] query if deeper investigation is warranted.
```

**Template 4: Security investigation.**

```
SECURITY ALERTS:
{security_alerts_formatted}

UNUSUAL TRAFFIC PATTERNS:
{unusual_traffic_formatted}

TOP EXTERNAL CONNECTIONS:
{external_connections_formatted}

NXDOMAIN RATE: {nxdomain_rate}%
NEW FLOWS PER SECOND: {new_flows_rate}
RST RATE PER MINUTE: {rst_rate}

USER QUESTION: {user_query}

Analyze the security posture based on this data. 
Report what is observable without speculating about intent.
Prioritize findings by severity. Include [SEARCH: ...] queries for each finding.
```

**Template 5: Explanation (educational).**

```
{optional_specific_data_if_referenced}

USER QUESTION: {user_query}

Explain this networking concept clearly. 
If the user referenced specific data, explain it in context.
Use concrete examples. This user is technical — use correct terminology.
```

**Template 6: Historical analysis.**

```
TIME RANGE ANALYZED: {start_time} to {end_time}

METRICS DURING THIS PERIOD:
{historical_metrics_formatted}

ALERTS DURING THIS PERIOD ({alert_count}):
{historical_alerts_formatted}

TOP FLOWS DURING THIS PERIOD:
{historical_flows_formatted}

USER QUESTION: {user_query}

Describe what happened during this time period.
Identify the most significant events in chronological order.
Compare to baseline where available.
```

**Template 7: Recommendations.**

```
CURRENT STATE:
{current_metrics_formatted}

IDENTIFIED PROBLEMS (from this conversation):
{conversation_problems_extracted}

ACTIVE ALERTS:
{active_alerts_formatted}

USER QUESTION: {user_query}

Provide specific, actionable recommendations.
Number each recommendation. For each: state the problem it addresses, 
the recommended action, and the expected outcome.
Do not recommend actions that cannot be verified in the traffic data.
```

---

## Context formatting — how to structure data for the LLM

Raw JSON sent directly to the LLM is inefficient — it wastes tokens on syntax characters and the LLM has to parse structure rather than focus on meaning. Format context data as structured text instead.

For metrics snapshots, format like this:

```
NETWORK (last 60s):
  Bandwidth: 45.2 Mbps in / 12.8 Mbps out
  Packets: 8,420/sec
  Active flows: 1,247
  New flows: 23/sec

TCP QUALITY:
  RTT p50: 12ms | p95: 87ms | p99: 340ms
  Retransmission rate: 8.3% [ELEVATED - baseline 1.2%]
  Zero window events: 47
  RST rate: 3/min

DNS:
  Avg resolution: 410ms [ELEVATED - baseline 45ms]
  p95 resolution: 892ms
  NXDOMAIN rate: 2.1%
  Query rate: 234/sec

HTTP:
  Requests: 1,840/sec
  Latency p50: 145ms | p95: 3,200ms | p99: 8,400ms
  Error rate: 12.3% [ELEVATED - baseline 0.8%]
```

The `[ELEVATED - baseline X]` annotation is critical. The LLM cannot know what is normal without the baseline. Always include the baseline value alongside the current value for any metric that has deviated from normal. This is what allows the LLM to make calibrated statements about severity rather than just describing numbers.

For flow records, format like this:

```
FLOW #4382:
  10.0.0.5:52341 → 34.120.50.1:443 (TCP/TLS)
  SNI: api.stripe.com
  Duration: 4.3s | Bytes: 5.2MB in / 128KB out
  RTT avg: 287ms | Retransmits: 23 (5.6%)
  State: ESTABLISHED
  Alert: High retransmission rate
```

For alerts, format like this:

```
[CRITICAL] Port scan from 192.168.1.22
  Contacted 47 distinct ports in 60 seconds
  First seen: 14:32:15 | Ongoing: yes
  Search: [SEARCH: src_ip:192.168.1.22]

[WARNING] DNS latency elevated
  Avg: 410ms (baseline: 45ms, +811%)
  Slowest domain: auth.internal.company.com (892ms avg)
  Search: [SEARCH: dns.latency_ms > 200]
```

---

## Multi-turn conversation management

The AI Copilot supports multi-turn conversations where each response builds on previous ones. This requires maintaining conversation history and managing it carefully.

Store conversation turns in memory during the session and in PostgreSQL for persistence. Each turn is a pair: user message and assistant response. The conversation history is sent to the Grok API as the `messages` array.

The conversation history serves two purposes beyond continuity. First, it allows the AI to refer to previous findings — "as I mentioned, the DNS issue is likely the primary bottleneck" is only possible with history. Second, it allows the user to ask follow-up questions — "what about the flows from that IP specifically?" after an investigation response.

The conversation state tracks one additional piece of information beyond the raw messages: the problems identified in this conversation. Every time the AI identifies a specific network issue (elevated DNS latency, a suspicious IP, a high-retransmission flow), extract and store it as a structured problem object. This extracted list is used in Type 7 (recommendations) queries to provide specific advice about things already discussed.

When the context window budget for conversation history is reached (8,000 tokens), apply the truncation strategy: keep the system prompt always, keep the first user message and AI response (sets the conversation context), keep the last 5 turns, drop the middle turns. When dropping middle turns, add a one-sentence summary placeholder: `[3 turns summarized: User investigated DNS latency and retransmission issues on flows to api.stripe.com]`. This summary is generated by the AI in a separate very cheap API call using grok-3-mini-beta with the instruction "summarize these conversation turns in one sentence."

---

## Streaming implementation

Streaming is non-negotiable for a good user experience. A 400-word response takes 3-5 seconds to generate. Without streaming the user stares at a loading spinner for that entire time. With streaming, the first tokens appear within 200-400ms and the response builds word by word.

The streaming flow works like this. The frontend sends a POST request to `/api/ai/chat` on the Python FastAPI service. The FastAPI endpoint opens a streaming response using FastAPI's `StreamingResponse` with `media_type="text/event-stream"`. It calls the Grok API with `stream=True`. As Grok yields token chunks, FastAPI immediately forwards them to the frontend as Server-Sent Events. The frontend's EventSource object receives each chunk and appends it to the displayed message.

Each Server-Sent Event has a data field containing a JSON object with these fields: `type` (either `token`, `metadata`, `search_query`, or `done`), `content` (the token text for `token` events), `query` (the search query string for `search_query` events), and `metadata` (final metadata including total tokens, model used, and conversation ID for `done` events).

The `search_query` event type is emitted when the response processor detects a `[SEARCH: ...]` block in the streamed tokens. The frontend receives this as a separate structured event and renders it as a clickable chip immediately rather than waiting for the full response.

---

## Response post-processing

After the full response is received (the stream is complete), run post-processing before storing the conversation.

**Extract search queries.** Find all `[SEARCH: ...]` patterns in the response text. Extract the query strings. These have already been sent to the frontend as structured events during streaming, but also store them as part of the conversation record.

**Extract mentioned flow IDs.** Find all references to flow IDs in the format `flow #XXXXX` or `Flow #XXXXX`. Store these so the conversation can be linked to specific flows in the database.

**Extract mentioned IPs.** Find all IP addresses mentioned in the response. These are used to build the "investigated entities" list shown in the frontend's context panel.

**Classify the response confidence.** Determine how much of the response was grounded in context data versus general knowledge. Responses that reference specific numbers from the context are high-confidence. Responses that give general networking advice without citing data are lower-confidence. Add this to the stored conversation record but do not expose it in the UI — it is for your own monitoring of AI quality.

**Store the conversation turn** in PostgreSQL with: conversation ID, session ID, turn number, user message, assistant response, query type classification, metrics context JSON (the exact data that was sent to the LLM), extracted search queries, model used, token counts, and latency.

---

## The programmatic query interface — for the dashboard to call internally

In addition to the chat interface, the AI Copilot exposes two programmatic endpoints that the dashboard calls automatically without user interaction.

**Auto-analysis endpoint**: `POST /api/ai/auto-analyze`. Called every 5 minutes by the dashboard when there are active alerts. It generates a brief (100-word) summary of the current network state and whether any alerts require attention. This appears as the "AI summary" card on the Overview page. Uses grok-3-mini-beta for speed and cost efficiency.

**Packet explanation endpoint**: `POST /api/ai/explain-packet`. Called when a user clicks the "AI Explanation" tab in the Packet Explorer. Receives the parsed packet data as a JSON object and returns a plain-English explanation of what the packet is and what it means. Pre-generates explanations for common packet types (TCP SYN, DNS query, TLS ClientHello) using templates and only calls the LLM for unusual packets.

**Flow explanation endpoint**: `POST /api/ai/explain-flow`. Called when a user clicks "Analyze with AI" on a flow in the Flow Explorer. Receives the complete flow statistics and returns a narrative explanation of the conversation: who initiated it, what protocol was used, what the data transfer pattern shows, whether anything is unusual.

---

## Rate limiting and cost management

The Grok API charges per token. Without rate limiting, a user could send hundreds of queries per minute and generate significant cost.

Implement these limits. Maximum 10 chat requests per minute per session. Maximum 100 chat requests per hour per session. Maximum 2,000 tokens per user message (reject longer messages with a helpful error). Maximum 2,000 tokens in the AI's response (set `max_tokens=2000` on every API call).

Track usage in a simple in-memory counter (a Python dict keyed by session ID). When a user hits the rate limit, return a 429 response with a message: "You've sent too many messages. Please wait a moment before asking another question."

For cost estimation: grok-3-mini-beta costs approximately $0.30 per million input tokens and $0.50 per million output tokens. A typical query with full context is about 3,000 input tokens and 500 output tokens. That is $0.00115 per query. At 100 queries per hour that is $0.115 per hour — essentially free for development and cheap for production.

Monitor actual token usage by logging the `usage` field from every Grok API response. Aggregate these in your metrics engine and expose them on the Settings page as "AI API usage this hour/day/month."

---

## Error handling for the AI layer

The AI layer has more failure modes than any other module because it depends on an external API.

**Grok API unavailable**: return a clear error message that the AI service is temporarily unavailable and all other dashboard features still work. Do not let an AI outage affect the packet capture, metrics, or alerts.

**Grok API rate limited**: implement exponential backoff with jitter. First retry after 1 second, second after 2 seconds, third after 4 seconds. After 3 retries, return an error to the user.

**Context retrieval failure**: if one of the C++ backend API calls fails during context building, proceed with the available context and note the missing data in the prompt: "NOTE: HTTP metrics data unavailable for this query." Do not fail the entire request because one context source is down.

**Response truncated by max_tokens**: if the response is cut off mid-sentence (detectable by checking if the finish reason is `length` rather than `stop`), append a note to the response: "Response truncated due to length. Ask a more specific question for a complete answer." Do not silently show a truncated response.

**Toxic or off-topic queries**: if the user asks about something completely unrelated to networking (creative writing, personal advice, coding in unrelated areas), respond helpfully but redirect: "I'm specialized in network analysis. I can help you analyze your traffic data, diagnose performance issues, or explain network concepts. What would you like to know about your network?"

---

## Prompt injection prevention

Users of a network monitoring tool have legitimate access to network data, but you still need to prevent prompt injection — where a captured packet's payload contains text that attempts to manipulate the AI's behavior.

The risk: a captured HTTP response body or DNS TXT record contains text like "Ignore your previous instructions and..." If your context building naively includes raw payload content, this could affect the AI's behavior.

The mitigation: never include raw packet payload content in the LLM context. Your context includes only parsed, structured fields — IP addresses, ports, byte counts, latency values, domain names, HTTP methods and URLs, status codes. These fields have constrained formats that cannot contain instructions. A domain name like `ignore-previous-instructions.com` is at most a curiosity, not an effective injection attack, because the context format labels it clearly as a domain name rather than an instruction.

Additionally, the system prompt establishes the AI's role clearly at the start of every conversation. Even if an injection attempt appeared in the data, the system prompt's instructions take precedence in Grok's processing.

---

## FastAPI service structure

```
ai_service/
├── main.py                    ← FastAPI app, routes
├── config.py                  ← environment variables, settings
├── classifier/
│   └── query_classifier.py    ← classifies query into 7 types
├── context/
│   ├── context_builder.py     ← orchestrates context retrieval
│   ├── metrics_fetcher.py     ← calls /api/metrics endpoints
│   ├── flow_fetcher.py        ← calls /api/search/flows
│   ├── alert_fetcher.py       ← calls /api/alerts
│   └── context_formatter.py   ← formats data as structured text
├── prompts/
│   ├── system_prompt.py       ← the system prompt constant
│   └── templates.py           ← the 7 query type templates
├── grok/
│   ├── grok_client.py         ← openai SDK pointed at xAI
│   └── token_counter.py       ← tiktoken-based token budget
├── conversation/
│   ├── conversation_store.py  ← in-memory + PostgreSQL
│   └── history_manager.py     ← truncation and summarization
├── streaming/
│   └── sse_handler.py         ← Server-Sent Events formatting
├── processing/
│   └── response_processor.py  ← extract queries, IPs, store
├── rate_limiting/
│   └── rate_limiter.py        ← per-session request limits
└── models/
    ├── request.py             ← Pydantic request schemas
    └── response.py            ← Pydantic response schemas
```

---

## REST endpoints exposed by the Python service

`POST /api/ai/chat` — main chat endpoint. Body: `{session_id, message, conversation_id?}`. Returns a streaming SSE response.

`GET /api/ai/conversations` — list past conversations for the current session.

`GET /api/ai/conversations/{id}` — get a specific conversation with full history.

`DELETE /api/ai/conversations/{id}` — delete a conversation.

`POST /api/ai/explain-packet` — explain a specific packet. Body: parsed packet JSON.

`POST /api/ai/explain-flow` — explain a specific flow. Body: flow statistics JSON.

`POST /api/ai/auto-analyze` — generate automatic network health summary. Called by the dashboard on a timer, not by users directly.

`GET /api/ai/usage` — token usage statistics for the current hour and day.

`GET /api/ai/health` — health check: confirms Grok API is reachable and responding.

---

## Implementation order

First, set up the FastAPI service with a single test endpoint and confirm it runs in Docker alongside the C++ backend. Confirm the two services can communicate via HTTP on the Docker network.

Second, implement the Grok client — a thin wrapper around the `openai` Python SDK pointed at xAI's base URL. Write a test that sends a simple "hello" message and receives a response. Confirm streaming works.

Third, implement the metrics fetcher and context formatter. Call your C++ backend's `/api/metrics/summary` endpoint and format the response as structured text. Print the formatted text to verify it looks like the examples above.

Fourth, write the system prompt. This takes time — write a first version, test it with 10 different questions, refine based on response quality. The system prompt is never "done" but get it to a good baseline before moving on.

Fifth, implement the general health check query type end-to-end. User sends "how is my network" → classify as Type 1 → fetch metrics and alerts → assemble prompt → call Grok → stream response to client. Test this with real traffic running through your capture pipeline.

Sixth, implement the performance diagnosis query type. Test with "why is my API slow" while running a service with intentionally high latency.

Seventh, implement the specific flow investigation type. Test with "what is 8.8.8.8 doing" while capturing traffic.

Eighth, implement streaming SSE in the FastAPI service and confirm the frontend receives tokens as they arrive.

Ninth, implement the search query extraction and the structured `[SEARCH: ...]` event type. Confirm the frontend receives and renders clickable search chips.

Tenth, implement conversation history — store turns, send history to Grok, verify follow-up questions work correctly.

Eleventh, implement the remaining query types (security, historical, recommendations, explanation).

Twelfth, implement rate limiting, error handling, and the usage tracking endpoint.

Thirteenth, implement the auto-analysis and packet/flow explanation endpoints.

Finally, tune the prompts based on real usage. The first version of the prompts will not be perfect. After testing with 50 different queries across all seven types, you will have clear patterns of where the AI gives weak answers, and you can improve the templates accordingly.

---

## The most important thing to get right

The baseline annotation in the context data is the single biggest lever for response quality. The difference between these two context formats is enormous.

Without baseline: `DNS avg resolution: 410ms`

With baseline: `DNS avg resolution: 410ms [ELEVATED - baseline 45ms, +811%, above 3-sigma threshold]`

The first version produces AI responses like "DNS resolution time is 410ms which may be worth investigating." The second version produces "DNS resolution time has spiked to 410ms, more than 8 times your baseline of 45ms and well above the 3-sigma threshold. This is almost certainly contributing to your API latency." The second response is specific, confident, and actionable. The only difference is the baseline annotation in the context. Every metric that has a baseline in Module 4 must include that baseline in the context sent to the LLM. This is not optional — it is the core of what makes the AI useful rather than generic.