import React from 'react'

// Minimal, dependency-free Markdown → React renderer for displaying LLM output.
// It builds real React elements (never dangerouslySetInnerHTML), so untrusted
// agent/attacker text can't inject HTML or scripts. Handles the common subset
// models emit: fenced code blocks, ATX headings, bold/italic, inline code,
// links, blockquotes, and unordered/ordered lists. Unknown syntax falls through
// as plain text.

const INLINE = /(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\n]+\*|_[^_\n]+_|\[[^\]]+\]\([^)\s]+\))/g

function inline(text) {
  const out = []
  let last = 0, m, key = 0
  while ((m = INLINE.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith('`')) out.push(<code key={key++}>{tok.slice(1, -1)}</code>)
    else if (tok.startsWith('**') || tok.startsWith('__')) out.push(<strong key={key++}>{tok.slice(2, -2)}</strong>)
    else if (tok.startsWith('*') || tok.startsWith('_')) out.push(<em key={key++}>{tok.slice(1, -1)}</em>)
    else {
      const link = /\[([^\]]+)\]\(([^)\s]+)\)/.exec(tok)
      out.push(<a key={key++} href={link[2]} target="_blank" rel="noreferrer">{link[1]}</a>)
    }
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

const para = (text) =>
  text.split('\n').map((ln, idx, arr) => (
    <React.Fragment key={idx}>{inline(ln)}{idx < arr.length - 1 ? <br /> : null}</React.Fragment>
  ))

const isListLine = (l) => /^\s*([-*+]|\d+\.)\s+/.test(l)

export function Markdown({ text }) {
  const lines = String(text ?? '').split('\n')
  const blocks = []
  let i = 0, key = 0
  while (i < lines.length) {
    const line = lines[i]

    const fence = line.match(/^\s*```(\w*)\s*$/)
    if (fence) {
      const code = []
      i++
      while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { code.push(lines[i]); i++ }
      i++ // closing fence
      blocks.push(<pre key={key++} className="md-code"><code>{code.join('\n')}</code></pre>)
      continue
    }

    const h = line.match(/^(#{1,6})\s+(.*)$/)
    if (h) {
      blocks.push(React.createElement(`h${Math.min(6, h[1].length)}`, { key: key++, className: 'md-h' }, inline(h[2])))
      i++
      continue
    }

    if (/^\s*>\s?/.test(line)) {
      const quote = []
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { quote.push(lines[i].replace(/^\s*>\s?/, '')); i++ }
      blocks.push(<blockquote key={key++} className="md-quote">{para(quote.join('\n'))}</blockquote>)
      continue
    }

    if (isListLine(line)) {
      const ordered = /^\s*\d+\.\s+/.test(line)
      const items = []
      while (i < lines.length && isListLine(lines[i])) {
        items.push(<li key={items.length}>{inline(lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, ''))}</li>)
        i++
      }
      blocks.push(ordered
        ? <ol key={key++} className="md-list">{items}</ol>
        : <ul key={key++} className="md-list">{items}</ul>)
      continue
    }

    if (line.trim() === '') { i++; continue }

    const buf = []
    while (i < lines.length && lines[i].trim() !== '' && !/^\s*```/.test(lines[i])
           && !/^#{1,6}\s+/.test(lines[i]) && !isListLine(lines[i]) && !/^\s*>\s?/.test(lines[i])) {
      buf.push(lines[i]); i++
    }
    blocks.push(<p key={key++} className="md-p">{para(buf.join('\n'))}</p>)
  }
  return <div className="md">{blocks}</div>
}
