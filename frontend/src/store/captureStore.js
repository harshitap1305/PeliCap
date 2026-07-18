import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const useCaptureStore = create(
  persist(
    (set) => ({
      isCapturing: false,
      sessionId: null,
      sessionName: null,
      sessionInterface: null,

      // Only updates isCapturing — never clears sessionId
      setCapturing: (status) =>
        set({ isCapturing: status }),

      // Full session start: sets all three fields + marks as capturing
      setSession: (id, name, iface) =>
        set({ sessionId: id, sessionName: name, sessionInterface: iface }),

      // Standalone sessionId setter (for compatibility)
      setSessionId: (id) => set({ sessionId: id }),

      // Clear everything
      clearSession: () =>
        set({ isCapturing: false, sessionId: null, sessionName: null, sessionInterface: null }),
    }),
    {
      name: 'pelicap-session', // localStorage key
    }
  )
);
