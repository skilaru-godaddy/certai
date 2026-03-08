import { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: {
    primaryColor: '#4f46e5',
    primaryTextColor: '#e5e7eb',
    primaryBorderColor: '#6366f1',
    lineColor: '#6366f1',
    secondaryColor: '#1f2937',
    tertiaryColor: '#111827',
    background: '#030712',
    mainBkg: '#111827',
    nodeBorder: '#374151',
    clusterBkg: '#1f2937',
    titleColor: '#f9fafb',
    edgeLabelBackground: '#1f2937',
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  },
});

interface Props {
  chart: string;
}

let idCounter = 0;

export function MermaidDiagram({ chart }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ref.current || !chart) return;
    setError(null);
    const id = `mermaid-${++idCounter}`;
    ref.current.innerHTML = '';
    mermaid
      .render(id, chart)
      .then(({ svg }) => {
        if (ref.current) {
          ref.current.innerHTML = svg;
          // Make SVG responsive
          const svgEl = ref.current.querySelector('svg');
          if (svgEl) {
            svgEl.removeAttribute('height');
            svgEl.style.maxWidth = '100%';
          }
        }
      })
      .catch((err) => {
        setError(String(err));
      });
  }, [chart]);

  if (error) {
    return (
      <div className="bg-gray-950 border border-gray-800 rounded-xl p-6 text-center">
        <p className="text-gray-500 text-sm mb-2">Diagram render error</p>
        <pre className="text-xs text-gray-600 text-left overflow-auto max-h-32">{chart}</pre>
      </div>
    );
  }

  return (
    <div
      ref={ref}
      className="bg-gray-950 border border-gray-800 rounded-xl p-6
                 flex justify-center min-h-[220px] items-center overflow-x-auto"
    />
  );
}
