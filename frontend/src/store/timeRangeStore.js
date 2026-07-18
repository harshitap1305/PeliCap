import { create } from 'zustand';

export const useTimeRangeStore = create((set) => ({
  timeRange: '1h', // '15m', '1h', '6h', '24h', '7d', or custom object
  setTimeRange: (range) => set({ timeRange: range }),
}));
