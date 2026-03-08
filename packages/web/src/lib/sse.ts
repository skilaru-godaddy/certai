export interface PhaseUpdate {
  phase: 'discovery' | 'fetching' | 'thinking' | 'generating' | 'done' | 'error';
  message: string;
  data?: unknown;
}

export function streamJob(
  jobId: string,
  onUpdate: (update: PhaseUpdate) => void,
  onDone: (data: unknown) => void,
  onError: (msg: string) => void
): () => void {
  const es = new EventSource(`/stream/${jobId}`);

  es.onmessage = (event) => {
    const update: PhaseUpdate = JSON.parse(event.data);
    if (update.phase === 'done') {
      onDone(update.data);
      es.close();
    } else if (update.phase === 'error') {
      onError(update.message);
      es.close();
    } else {
      onUpdate(update);
    }
  };

  es.onerror = () => {
    onError('SSE connection lost');
    es.close();
  };

  return () => es.close();
}
