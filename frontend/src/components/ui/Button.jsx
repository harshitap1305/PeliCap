import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

const VARIANTS = {
  primary: 'bg-blue-600 text-white hover:bg-blue-700 active:bg-blue-800 border-transparent',
  secondary: 'bg-white text-slate-700 hover:bg-slate-50 active:bg-slate-100 border-slate-200',
  danger: 'bg-red-600 text-white hover:bg-red-700 active:bg-red-800 border-transparent',
  ghost: 'bg-transparent text-slate-600 hover:bg-slate-100 hover:text-slate-900 border-transparent',
};

const SIZES = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
};

export const Button = React.forwardRef(({ 
  children, 
  variant = 'primary', 
  size = 'md', 
  className,
  disabled,
  icon: Icon,
  ...props 
}, ref) => {
  return (
    <button
      ref={ref}
      disabled={disabled}
      className={twMerge(
        clsx(
          "inline-flex items-center justify-center rounded-md font-medium border transition-colors",
          "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          VARIANTS[variant],
          SIZES[size],
          className
        )
      )}
      {...props}
    >
      {Icon && <Icon className={clsx("w-4 h-4", children ? "mr-2" : "")} />}
      {children}
    </button>
  );
});

Button.displayName = 'Button';
