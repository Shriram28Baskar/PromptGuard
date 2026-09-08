export default function SeverityBadge({ tier }) {
  return (
    <span className={`tier-badge tier-${tier}`}>
      <span className="dot" />
      {tier}
    </span>
  )
}
