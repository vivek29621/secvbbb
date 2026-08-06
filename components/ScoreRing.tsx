const GRADE_COLORS: Record<string, string> = {
  A: "#059669",
  B: "#16a34a",
  C: "#d97706",
  D: "#ea580c",
  F: "#dc2626",
};

export default function ScoreRing({
  score,
  grade,
  size = 96,
  strokeWidth = 8,
}: {
  score: number;
  grade: string;
  size?: number;
  strokeWidth?: number;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = GRADE_COLORS[grade] ?? GRADE_COLORS.F;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 900ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold tracking-tight text-slate-900">{score}</span>
        <span className="-mt-1 text-[10px] font-semibold uppercase tracking-wider" style={{ color }}>
          Grade {grade}
        </span>
      </div>
    </div>
  );
}
