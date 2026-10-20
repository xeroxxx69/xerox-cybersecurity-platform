import React from "react";

export type SystemStatus = "online" | "scanning" | "alert" | "idle" | "degraded" | "offline";

export interface StatusIndicatorProps extends React.HTMLAttributes<HTMLDivElement> {
  status?: SystemStatus;
  label?: string;
  size?: "sm" | "md";
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status = "online",
  label,
  size = "md",
  className = "",
  ...props
}) => {
  const configs: Record<
    SystemStatus,
    { dotColor: string; pingColor: string; defaultLabel: string }
  > = {
    online: {
      dotColor: "bg-emerald-400",
      pingColor: "bg-emerald-400",
      defaultLabel: "ONLINE",
    },
    degraded: {
      dotColor: "bg-amber-400",
      pingColor: "bg-amber-400",
      defaultLabel: "DEGRADED",
    },
    offline: {
      dotColor: "bg-rose-500",
      pingColor: "bg-rose-500",
      defaultLabel: "OFFLINE",
    },
    scanning: {
      dotColor: "bg-blue-400",
      pingColor: "bg-blue-400",
      defaultLabel: "ANALYZING",
    },
    alert: {
      dotColor: "bg-xerox-red",
      pingColor: "bg-xerox-red",
      defaultLabel: "THREAT ALERT",
    },
    idle: {
      dotColor: "bg-slate-400",
      pingColor: "bg-slate-400",
      defaultLabel: "STANDBY",
    },
  };


  const { dotColor, pingColor, defaultLabel } = configs[status];

  const dotSize = size === "sm" ? "w-2 h-2" : "w-2.5 h-2.5";
  const textSize = size === "sm" ? "text-[10px]" : "text-xs";

  return (
    <div className={`inline-flex items-center gap-2 ${className}`} {...props}>
      <span className="relative flex">
        {status !== "idle" && (
          <span
            className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${pingColor}`}
          />
        )}
        <span className={`relative inline-flex rounded-full ${dotSize} ${dotColor}`} />
      </span>
      {(label || defaultLabel) && (
        <span className={`font-mono font-semibold tracking-wider text-slate-300 ${textSize}`}>
          {label || defaultLabel}
        </span>
      )}
    </div>
  );
};
