import React from 'react';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import SessionBanner from './SessionBanner';

const PageLayout = ({ children }) => {
  return (
    <div className="flex h-screen bg-slate-50 overflow-hidden text-slate-900 font-sans">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <SessionBanner />
        <main className="flex-1 overflow-auto p-8">
          <div className="max-w-[1440px] mx-auto w-full h-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

export default PageLayout;

