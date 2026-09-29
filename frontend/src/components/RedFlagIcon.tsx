import React from 'react';

interface RedFlagIconProps {
  className?: string;
  size?: number;
}

export const RedFlagIcon: React.FC<RedFlagIconProps> = ({ className = '', size = 56 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ filter: 'drop-shadow(0px 6px 12px rgba(209, 0, 0, 0.28))' }}
      aria-label="RedFlag Symbol"
    >
      {/* Flagpole */}
      <rect x="12" y="10" width="4.5" height="46" rx="2.25" fill="#D10000" />
      {/* Pole finial cap */}
      <circle cx="14.25" cy="10" r="2.75" fill="#B80000" />
      
      {/* Waving Flag Banner */}
      <path
        d="M16.5 13C23 11 29 17 36 15C43 13 48 11.5 53 14C53.8 14.4 54 15 54 16V34C54 34.8 53.4 35.4 52.6 35.2C48 33 43 34.5 36 36.5C29 38.5 23 32.5 16.5 34.5V13Z"
        fill="#D10000"
      />
      {/* Flag highlight curve for depth */}
      <path
        d="M16.5 13C23 11 29 17 36 15C43 13 48 11.5 53 14V17C48 14.5 43 16 36 18C29 20 23 14 16.5 16V13Z"
        fill="#E02222"
        opacity="0.8"
      />
    </svg>
  );
};
