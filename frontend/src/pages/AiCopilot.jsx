import React, { useState, useRef, useEffect } from 'react';
import { Card } from '../components/ui/Card';
import { Send, Bot, User, Sparkles } from 'lucide-react';

const AiCopilot = () => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      role: 'assistant',
      content: 'Hello! I am PaliCap AI. I can help you analyze your network flows, write BPF filters, or explain security alerts. How can I assist you today?'
    }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const endOfMessagesRef = useRef(null);

  useEffect(() => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSend = (e) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMessage = { id: Date.now(), role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    // Mock API response
    setTimeout(() => {
      const responses = [
        "Based on the recent flow data, it looks like there's a spike in TLS traffic to an unusual IP block.",
        "I can help with that. The equivalent BPF filter would be `tcp port 443 and (src net 10.0.0.0/8)`.",
        "That alert indicates a potential port scan. I recommend isolating the source IP `192.168.1.55` and checking its running processes.",
        "Here's a breakdown of your top talkers over the last 5 minutes. The majority of bandwidth is consumed by video streaming services."
      ];
      
      const assistantMessage = {
        id: Date.now() + 1,
        role: 'assistant',
        content: responses[Math.floor(Math.random() * responses.length)]
      };
      
      setMessages(prev => [...prev, assistantMessage]);
      setIsTyping(false);
    }, 1500);
  };

  return (
    <div className="h-full flex flex-col space-y-4">
      {/* Header */}
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight flex items-center">
            <Sparkles className="w-6 h-6 mr-2 text-indigo-500" />
            AI Copilot
          </h1>
          <p className="text-slate-500 mt-1">Ask questions about your network data</p>
        </div>
      </div>

      {/* Chat Area */}
      <Card noPadding className="flex-1 flex flex-col min-h-0 bg-white">
        <div className="flex-1 overflow-auto p-4 space-y-6">
          {messages.map(msg => (
            <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex space-x-3 max-w-[80%] ${msg.role === 'user' ? 'flex-row-reverse space-x-reverse' : 'flex-row'}`}>
                
                {/* Avatar */}
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                  msg.role === 'user' ? 'bg-blue-100 text-blue-600' : 'bg-indigo-100 text-indigo-600'
                }`}>
                  {msg.role === 'user' ? <User className="w-5 h-5" /> : <Bot className="w-5 h-5" />}
                </div>

                {/* Bubble */}
                <div className={`p-3 rounded-xl text-sm ${
                  msg.role === 'user' 
                    ? 'bg-blue-600 text-white rounded-tr-none shadow-sm' 
                    : 'bg-slate-100 text-slate-800 rounded-tl-none border border-slate-200'
                }`}>
                  {msg.content}
                </div>
              </div>
            </div>
          ))}

          {isTyping && (
            <div className="flex justify-start">
              <div className="flex space-x-3 max-w-[80%]">
                <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center shrink-0">
                  <Bot className="w-5 h-5" />
                </div>
                <div className="p-3 rounded-xl bg-slate-100 text-slate-500 rounded-tl-none border border-slate-200 flex space-x-1 items-center">
                  <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            </div>
          )}
          <div ref={endOfMessagesRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 border-t border-slate-200 bg-slate-50">
          <form onSubmit={handleSend} className="relative flex items-center">
            <input 
              type="text" 
              placeholder="Ask about flows, alerts, or write a query..." 
              className="w-full pl-4 pr-12 py-3 bg-white border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-shadow shadow-sm"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={isTyping}
            />
            <button 
              type="submit" 
              disabled={!input.trim() || isTyping}
              className="absolute right-2 p-1.5 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="text-center mt-2">
            <span className="text-[10px] text-slate-400 font-medium">AI responses may be inaccurate. Verify critical network data.</span>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default AiCopilot;
