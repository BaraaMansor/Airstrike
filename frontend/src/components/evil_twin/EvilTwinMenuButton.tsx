import React from "react";

interface EvilTwinMenuButtonProps {
  onClick?: () => void;
}

const EvilTwinMenuButton: React.FC<EvilTwinMenuButtonProps> = ({ onClick }) => {
  return (
    <button onClick={onClick} style={{ width: "100%", padding: 12, margin: "8px 0" }}>
      Evil Twin Attack
    </button>
  );
};

export default EvilTwinMenuButton; 