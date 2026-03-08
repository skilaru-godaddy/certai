import type { ThreatItem } from '../types.js';

const IMPACT_COLOR: Record<string, string> = {
  Critical: 'text-red-400',
  High: 'text-orange-400',
  Medium: 'text-yellow-400',
  Low: 'text-green-400',
};

interface Props {
  threats: ThreatItem[];
}

export function ThreatTable({ threats }: Props) {
  if (!threats.length) return <p className="text-gray-500">No threats identified.</p>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="text-left text-gray-500 border-b border-gray-800">
            <th className="py-2 pr-4">Component</th>
            <th className="py-2 pr-4">Threat</th>
            <th className="py-2 pr-4">Likelihood</th>
            <th className="py-2 pr-4">Impact</th>
            <th className="py-2 pr-4">Mitigation</th>
            <th className="py-2">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((t, i) => (
            <tr key={i} className="border-b border-gray-900 hover:bg-gray-900/50">
              <td className="py-2 pr-4 text-white font-medium">{t.component}</td>
              <td className="py-2 pr-4 text-gray-300">{t.threat}</td>
              <td className={`py-2 pr-4 ${IMPACT_COLOR[t.likelihood] ?? 'text-gray-300'}`}>
                {t.likelihood}
              </td>
              <td className={`py-2 pr-4 font-semibold ${IMPACT_COLOR[t.impact] ?? 'text-gray-300'}`}>
                {t.impact}
              </td>
              <td className="py-2 pr-4 text-gray-400 text-xs max-w-[200px]">{t.mitigation}</td>
              <td className="py-2 text-indigo-400 font-mono text-xs">{t.codeEvidence}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
