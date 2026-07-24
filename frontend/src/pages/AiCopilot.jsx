import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import {
  Send, Bot, User, Sparkles, Search, RotateCcw,
  AlertCircle, Wifi, WifiOff, Zap, Network, Shield,
  BookOpen, Clock, Lightbulb, ChevronRight
} from 'lucide-react';
import { useCaptureStore } from '../store/captureStore';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

// ── Suggested starter questions ───────────────────────────────────────────────
const SUGGESTED_QUESTIONS = [
  { icon: Network,  label: "Network Health",    query: "What's the overall network health right now?" },
  { icon: Zap,      label: "Performance",       query: "Why is my traffic slow? Diagnose the latency." },
  { icon: Shield,   label: "Security",          query: "Is there any suspicious activity or security concerns?" },
  { icon: Search,   label: "Top Consumers",     query: "Which hosts are consuming the most bandwidth?" },
  { icon: BookOpen, label: "Explain TCP",       query: "Explain what TCP retransmissions are and why they matter." },
];

// ── Markdown-lite renderer (bold + bullets only, safe) ────────────────────────
function MarkdownText({ text }) {
  const lines = text.split('\n');
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        // Bold: **text**
        const parts = line.split(/\*\*(.*?)\*\*/g);
        const rendered = parts.map((part, j) =>
          j % 2 === 1 ? <strong key={j} className="font-semibold">{part}</strong> : part
        );
        if (line.startsWith('• ') || line.startsWith('- ')) {
          return <div key={i} className="flex gap-2"><span className="text-indigo-400 mt-0.5">•</span><span>{rendered}</span></div>;
        }
        if (/^\d+\.\s/.test(line)) {
          return <div key={i} className="flex gap-2"><span className="text-indigo-400 font-mono text-xs mt-0.5">{line.match(/^\d+/)[0]}.</span><span>{rendered}</span></div>;
        }
        return line ? <div key={i}>{rendered}</div> : <div key={i} className="h-2" />;
      })}
    </div>
  );
}

// ── Search chip component ────────────────────────────────────────────────────
function SearchChip({ query, onClick }) {
  return (
    <button
      onClick={() => onClick(query)}
      className="inline-flex items-center gap-1.5 mt-2 px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100
                 text-indigo-700 text-xs font-medium rounded-full border border-indigo-200
                 transition-colors cursor-pointer group"
    >
      <Search className="w-3 h-3" />
      <span className="font-mono">{query}</span>
      <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
    </button>
  );
}

// ── Typing dots indicator ─────────────────────────────────────────────────────
function TypingDots() {
  return (
    <div className="flex items-center gap-1 px-1">
      {[0, 150, 300].map(delay => (
        <span
          key={delay}
          className="w-2 h-2 bg-indigo-400 rounded-full animate-bounce"
          style={{ animationDelay: `${delay}ms` }}
        />
      ))}
    </div>
  );
}

// ── Message bubble ────────────────────────────────────────────────────────────
function MessageBubble({ msg, onSearchChip }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`flex gap-3 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}>
      {/* Avatar */}
      <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5
        ${isUser ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-indigo-600 border border-slate-200'}`}>
        {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
      </div>

      {/* Content */}
      <div className={`max-w-[78%] ${isUser ? 'items-end' : 'items-start'} flex flex-col`}>
        <div className={`px-4 py-3 rounded-2xl text-sm leading-relaxed
          ${isUser
            ? 'bg-indigo-600 text-white rounded-tr-sm'
            : 'bg-white text-slate-800 rounded-tl-sm border border-slate-200 shadow-sm'
          }`}>
          {msg.isStreaming && !msg.content
            ? <TypingDots />
            : isUser
              ? <span>{msg.content}</span>
              : <MarkdownText text={msg.content} />
          }
        </div>

        {/* Search chips */}
        {!isUser && msg.searchChips?.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {msg.searchChips.map((q, i) => (
              <SearchChip key={i} query={q} onClick={onSearchChip} />
            ))}
          </div>
        )}

        {/* Query type badge */}
        {!isUser && msg.queryType && (
          <span className="mt-1.5 text-[10px] text-slate-400 capitalize">
            {msg.queryType.replace('_', ' ')} analysis
          </span>
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
const AiCopilot = () => {
  const navigate = useNavigate();
  const { sessionId, sessionName, isCapturing } = useCaptureStore();

  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'assistant',
      content: "Hello! I'm the PeliCap AI Copilot. I can analyze your network traffic, diagnose performance issues, investigate flows, and explain what's happening on your network — all grounded in your actual captured data.\n\nSelect a session from the sidebar, then ask me anything.",
      searchChips: [],
    }
  ]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const [aiStatus, setAiStatus] = useState('unknown'); // 'ok' | 'degraded' | 'unknown'
  const bottomRef = useRef(null);
  const inputRef = useRef(null);
  const abortRef = useRef(null);

  // ── Scroll to bottom on new message ────────────────────────────────────────
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Check AI health on mount ────────────────────────────────────────────────
  useEffect(() => {
    axios.get('/ai/health', { timeout: 3000 })
      .then(r => setAiStatus(r.data?.status === 'ok' ? 'ok' : 'degraded'))
      .catch(() => setAiStatus('degraded'));
  }, []);

  // ── Auto-analysis poll — only for live captures (historical data is static)
  const { data: autoAnalysis } = useQuery({
    queryKey: ['ai-auto-analyze', sessionId, isCapturing],
    queryFn: () =>
      axios.post('/ai/auto-analyze', { session_id: sessionId, is_live: isCapturing }).then(r => r.data),
    enabled: !!sessionId && isCapturing,  // don't poll AI for stopped sessions
    refetchInterval: 5 * 60 * 1000,
    retry: false,
  });

  // ── Navigate to Flow Explorer with pre-filled search ──────────────────────
  const handleSearchChip = useCallback((query) => {
    navigate('/flows', { state: { searchQuery: query } });
  }, [navigate]);

  // ── Send message ────────────────────────────────────────────────────────────
  const sendMessage = useCallback(async (text) => {
    if (!text.trim() || isStreaming) return;
    if (!sessionId) {
      alert('Please select a capture session first.');
      return;
    }

    const userMsgId = Date.now();
    const asstMsgId = Date.now() + 1;

    // Add user message
    setMessages(prev => [...prev, {
      id: userMsgId,
      role: 'user',
      content: text,
    }]);

    // Add empty assistant message (streaming placeholder)
    setMessages(prev => [...prev, {
      id: asstMsgId,
      role: 'assistant',
      content: '',
      isStreaming: true,
      searchChips: [],
      queryType: null,
    }]);

    setIsStreaming(true);
    setInput('');

    // AbortController for cleanup
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const resp = await fetch('/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          message: text,
          conversation_id: conversationId || undefined,
          is_live: isCapturing,
        }),
        signal: ctrl.signal,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete line

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const event = JSON.parse(line.slice(6));

            if (event.type === 'start') {
              if (event.conversation_id) setConversationId(event.conversation_id);
              if (event.query_type) {
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId ? { ...m, queryType: event.query_type } : m
                ));
              }
            } else if (event.type === 'token') {
              setMessages(prev => prev.map(m =>
                m.id === asstMsgId
                  ? { ...m, content: m.content + event.content }
                  : m
              ));
            } else if (event.type === 'search_chip') {
              setMessages(prev => prev.map(m =>
                m.id === asstMsgId
                  ? { ...m, searchChips: [...(m.searchChips || []), event.query] }
                  : m
              ));
            } else if (event.type === 'done') {
              setMessages(prev => prev.map(m =>
                m.id === asstMsgId ? { ...m, isStreaming: false } : m
              ));
            } else if (event.type === 'error') {
              throw new Error(event.message);
            }
          } catch (parseErr) {
            // skip malformed SSE line
          }
        }
      }
    } catch (err) {
      if (err.name === 'AbortError') return;
      setMessages(prev => prev.map(m =>
        m.id === asstMsgId
          ? {
              ...m,
              content: `Sorry, I encountered an error: ${err.message}. Please try again.`,
              isStreaming: false,
            }
          : m
      ));
    } finally {
      setIsStreaming(false);
      abortRef.current = null;
      inputRef.current?.focus();
    }
  }, [sessionId, conversationId, isStreaming]);

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(input);
  };

  const handleSuggestedQuestion = (q) => sendMessage(q);

  const handleReset = () => {
    if (isStreaming) abortRef.current?.abort();
    setMessages([{
      id: 'welcome',
      role: 'assistant',
      content: "Conversation cleared. Ask me anything about your network.",
      searchChips: [],
    }]);
    setConversationId(null);
    setIsStreaming(false);
  };

  const showSuggestions = messages.length <= 1 && sessionId;

  return (
    <div className="h-full flex flex-col space-y-4">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-indigo-500" />
            AI Copilot
          </h1>
          <p className="text-slate-500 mt-0.5 text-sm">
            Ask questions about your network — grounded in real captured data
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* AI status */}
          <div className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full
            ${aiStatus === 'ok'
              ? 'bg-emerald-50 text-emerald-700'
              : aiStatus === 'degraded'
              ? 'bg-red-50 text-red-600'
              : 'bg-slate-100 text-slate-500'}`}>
            {aiStatus === 'ok'
              ? <><Wifi className="w-3 h-3" /> Groq Connected</>
              : aiStatus === 'degraded'
              ? <><WifiOff className="w-3 h-3" /> AI Unavailable</>
              : <><Wifi className="w-3 h-3" /> Checking...</>}
          </div>

          {/* Reset */}
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700
                       px-2.5 py-1 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" /> New chat
          </button>
        </div>
      </div>

      {/* ── Auto-analysis banner ─────────────────────────────────────────────── */}
      {autoAnalysis?.summary && (
        <div className="shrink-0 flex items-start gap-2.5 bg-indigo-50 border border-indigo-100
                        rounded-xl px-4 py-3 text-sm text-indigo-800">
          <Lightbulb className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" />
          <span><span className="font-medium">AI Insight: </span>{autoAnalysis.summary}</span>
        </div>
      )}

      {/* ── No session guard ─────────────────────────────────────────────────── */}
      {!sessionId && (
        <div className="shrink-0 flex items-center gap-2.5 bg-amber-50 border border-amber-200
                        rounded-xl px-4 py-3 text-sm text-amber-800">
          <AlertCircle className="w-4 h-4 text-amber-500 shrink-0" />
          <span>
            <span className="font-medium">No session selected.</span> Go to{' '}
            <button onClick={() => navigate('/sessions')} className="underline font-medium">
              Sessions
            </button>{' '}
            to start or select a capture.
          </span>
        </div>
      )}

      {/* ── Chat area ────────────────────────────────────────────────────────── */}
      <Card noPadding className="flex-1 flex flex-col min-h-0 bg-white overflow-hidden">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-5 py-5 space-y-5">
          {messages.map(msg => (
            <MessageBubble
              key={msg.id}
              msg={msg}
              onSearchChip={handleSearchChip}
            />
          ))}

          {/* Suggested questions */}
          {showSuggestions && (
            <div className="mt-4">
              <p className="text-xs text-slate-400 mb-3 font-medium uppercase tracking-wide">
                Suggested questions
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {SUGGESTED_QUESTIONS.map(({ icon: Icon, label, query }) => (
                  <button
                    key={label}
                    onClick={() => handleSuggestedQuestion(query)}
                    disabled={isStreaming}
                    className="flex items-center gap-3 px-4 py-3 text-left text-sm text-slate-700
                               bg-slate-50 hover:bg-indigo-50 hover:text-indigo-700 border border-slate-200
                               hover:border-indigo-200 rounded-xl transition-all group disabled:opacity-50"
                  >
                    <Icon className="w-4 h-4 text-slate-400 group-hover:text-indigo-500 shrink-0" />
                    <span>{query}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* ── Input area ──────────────────────────────────────────────────────── */}
        <div className="shrink-0 border-t border-slate-100 bg-slate-50/50 px-4 py-3">
          <form onSubmit={handleSubmit} className="flex items-end gap-2">
            <textarea
              ref={inputRef}
              rows={1}
              placeholder={
                !sessionId
                  ? "Select a session to start analysis..."
                  : "Ask about your network — health, performance, security, flows..."
              }
              disabled={!sessionId || isStreaming}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSubmit(e);
                }
              }}
              className="flex-1 resize-none bg-white border border-slate-200 rounded-xl px-4 py-3
                         text-sm text-slate-900 placeholder-slate-400
                         focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-400
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-shadow shadow-sm max-h-32 overflow-y-auto"
              style={{ fieldSizing: 'content' }}
            />
            <button
              type="submit"
              disabled={!input.trim() || isStreaming || !sessionId}
              className="shrink-0 w-10 h-10 rounded-xl bg-indigo-600 text-white
                         hover:bg-indigo-700 disabled:opacity-40 disabled:cursor-not-allowed
                         flex items-center justify-center transition-colors shadow-sm"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="flex items-center justify-between mt-2 px-1">
            <span className="text-[10px] text-slate-400">
              Shift+Enter for new line • Enter to send
            </span>
            <span className="text-[10px] text-slate-400">
              Powered by Groq · Llama 3.3
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default AiCopilot;
