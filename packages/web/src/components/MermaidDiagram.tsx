import { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'base',
  themeVariables: {
    primaryColor: '#F5F7F8',
    primaryTextColor: '#111111',
    primaryBorderColor: '#D4DBE0',
    lineColor: '#444444',
    secondaryColor: '#ffffff',
    tertiaryColor: '#F5F7F8',
    background: '#ffffff',
    mainBkg: '#F5F7F8',
    nodeBorder: '#D4DBE0',
    clusterBkg: '#F5F7F8',
    titleColor: '#111111',
    edgeLabelBackground: '#ffffff',
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif',
    fontSize: '13px',
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
      <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-6 text-center">
        <p className="text-[#666] text-[14px] mb-2">Diagram render error</p>
        <pre className="text-[12px] text-[#444] text-left overflow-auto max-h-32 font-mono">{chart}</pre>
      </div>
    );
  }

  return (
    <div
      ref={ref}
      className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-6
                 flex justify-center min-h-[220px] items-center overflow-x-auto"
    />
  );
}
