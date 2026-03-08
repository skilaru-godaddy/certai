import { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: { primaryColor: '#4f46e5' },
});

interface Props {
  chart: string;
}

let idCounter = 0;

export function MermaidDiagram({ chart }: Props) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current || !chart) return;
    const id = `mermaid-${++idCounter}`;
    ref.current.innerHTML = '';
    mermaid
      .render(id, chart)
      .then(({ svg }) => {
        if (ref.current) ref.current.innerHTML = svg;
      })
      .catch((err) => {
        if (ref.current) ref.current.textContent = `Diagram error: ${err}`;
      });
  }, [chart]);

  return (
    <div
      ref={ref}
      className="bg-gray-900 rounded-lg p-4 overflow-x-auto
                 flex justify-center min-h-[200px] items-center"
    />
  );
}
