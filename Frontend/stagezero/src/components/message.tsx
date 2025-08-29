import React from "react";

interface MessageProps {
  text: string;
  sender: "user" | "bot";
}

const Message: React.FC<MessageProps> = ({ text, sender }) => {
  return (
    <div className={sender === "user" ? "user-message" : "bot-message"}>
      {text}
    </div>
  );
};

export default Message;