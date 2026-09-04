/**
 * 결과 코드 조각 — 줄 번호를 붙이고, Semgrep이 잡은 줄(start_line~end_line)만 강조한다.
 *
 * 문맥(extra.context: 취약 줄 앞뒤 3줄)은 새 실행부터 붙는다. 없으면 code_snippet만
 * 보여주되, 그 경우 모든 줄이 매칭 범위이므로 전부 강조된다.
 */
export default function CodeSnippet({ finding }) {
  const context = finding.extra?.context;
  const firstLine = context ? context.start_line : finding.start_line;
  const lines = context ? context.lines : (finding.code_snippet || '').split('\n');
  const hitEnd = Math.max(finding.end_line || finding.start_line, finding.start_line);

  return (
    <pre className="snippet snippet-lines">
      {lines.map((text, index) => {
        const number = firstLine + index;
        const hit = number >= finding.start_line && number <= hitEnd;
        return (
          <span key={number} className={hit ? 'snippet-line snippet-line-hit' : 'snippet-line'}>
            <span className="snippet-no">{number}</span>
            <span className="snippet-mark" aria-hidden="true">{hit ? '▶' : ''}</span>
            <span className="snippet-text">{text || ' '}</span>
          </span>
        );
      })}
    </pre>
  );
}
