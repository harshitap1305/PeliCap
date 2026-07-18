import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export const Card = ({ children, className, noPadding = false }) => {
  return (
    <div className={twMerge(
      clsx(
        "bg-white rounded-lg border border-slate-200 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_1px_2px_rgba(0,0,0,0.04)]",
        !noPadding && "p-6",
        className
      )
    )}>
      {children}
    </div>
  );
};

export const CardHeader = ({ title, subtitle, action }) => (
  <div className="flex justify-between items-start mb-6">
    <div>
      <h3 className="text-base font-semibold text-slate-900 tracking-tight">{title}</h3>
      {subtitle && <p className="text-sm text-slate-500 mt-1">{subtitle}</p>}
    </div>
    {action && <div>{action}</div>}
  </div>
);
