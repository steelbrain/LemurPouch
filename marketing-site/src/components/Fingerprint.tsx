type FingerprintSize = "sm" | "md" | "lg";

type FingerprintProps = {
  words: readonly string[];
  size?: FingerprintSize;
  variant?: "boxed" | "inline";
  className?: string;
};

const sizeClass: Record<FingerprintSize, string> = {
  sm: "text-xs",
  md: "text-sm",
  lg: "text-base sm:text-lg",
};

const boxedPaddingClass: Record<FingerprintSize, string> = {
  sm: "px-2 py-1",
  md: "px-3 py-1.5",
  lg: "px-4 py-2",
};

export function Fingerprint({
  words,
  size = "md",
  variant = "boxed",
  className = "",
}: FingerprintProps) {
  const text = words.join("-");

  if (variant === "inline") {
    return (
      <code
        className={`font-mono text-foreground break-words ${sizeClass[size]} ${className}`}
      >
        {text}
      </code>
    );
  }

  return (
    <code
      className={
        `inline-flex max-w-full items-center rounded-md border border-border bg-background-sunken font-mono text-foreground break-words ` +
        `${boxedPaddingClass[size]} ${sizeClass[size]} ${className}`
      }
    >
      {text}
    </code>
  );
}
