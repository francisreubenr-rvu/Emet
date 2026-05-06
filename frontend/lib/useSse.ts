"use client";

import { useEffect, useRef, useState } from "react";

export function useSse(url: string) {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const retries = useRef(0);

  useEffect(() => {
    if (!url) {
      setConnected(false);
      setMessages([]);
      return;
    }

    let source: EventSource | null = null;
    let timer: number | null = null;
    let closed = false;

    const connect = () => {
      source = new EventSource(url, { withCredentials: true });

      source.onopen = () => {
        retries.current = 0;
        setConnected(true);
      };

      source.onmessage = (event) => {
        setMessages((prev) => [...prev.slice(-200), event.data]);
      };

      source.onerror = () => {
        setConnected(false);
        source?.close();
        if (closed) return;
        const delay = Math.min(12000, 500 * 2 ** retries.current);
        retries.current += 1;
        timer = window.setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      closed = true;
      if (timer) window.clearTimeout(timer);
      source?.close();
    };
  }, [url]);

  return { connected, messages };
}
