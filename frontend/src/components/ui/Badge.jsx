import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

const VARIANTS = {
  success: 'bg-green-50 text-green-700 border-green-200',
  warning: 'bg-amber-50 text-amber-700 border-amber-200',
  critical: 'bg-red-50 text-red-700 border-red-200',
  info: 'bg-blue-50 text-blue-700 border-blue-200',
  neutral: 'bg-slate-50 text-slate-700 border-slate-200',
  
  // Protocol specific colors (based on module8.md rules)
  tcp: 'bg-blue-50 text-blue-700 border-blue-200',
  udp: 'bg-slate-50 text-slate-700 border-slate-200',
  dns: 'bg-amber-50 text-amber-700 border-amber-200',
  tls: 'bg-green-50 text-green-700 border-green-200',
  http: 'bg-purple-50 text-purple-700 border-purple-200',
  icmp: 'bg-red-50 text-red-700 border-red-200',
};

export const Badge = ({ children, variant = 'neutral', className }) => {
  return (
    <span className={twMerge(
      clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        VARIANTS[variant] || VARIANTS.neutral,
        className
      )
    )}>
      {children}
    </span>
  );
};

export const ProtocolBadge = ({ protocol }) => {
  const p = protocol?.toLowerCase() || 'unknown';
  let variant = 'neutral';
  let label = protocol;
  
  if (p.includes('tcp') || p === '6') { variant = 'tcp'; label = 'TCP'; }
  else if (p.includes('udp') || p === '17') { variant = 'udp'; label = 'UDP'; }
  else if (p.includes('dns')) { variant = 'dns'; label = 'DNS'; }
  else if (p.includes('tls') || p.includes('https')) { variant = 'tls'; label = 'TLS'; }
  else if (p.includes('http')) { variant = 'http'; label = 'HTTP'; }
  else if (p.includes('icmp')) { variant = 'icmp'; label = 'ICMP'; }
  
  return <Badge variant={variant}>{label}</Badge>;
};
