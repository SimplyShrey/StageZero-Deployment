import React from "react";

interface MessageProps {
  text: string;
  sender: "user" | "bot";
}

// const Message: React.FC<MessageProps> = ({ text, sender }) => {
//   return (
//     <div className={sender === "user" ? "user-message" : "bot-message"}>
//       {text}
//     </div>
//   );
// };
const Message: React.FC<MessageProps> = ({ text, sender }) => {
  return (
    <div className={`message ${sender}`}>
      <div style={{ whiteSpace: "pre-wrap" }}>{text}</div>
    </div>
  );
};

export default Message;