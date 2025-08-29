import React, { useState, useRef, useEffect } from "react";
import Message from "./message";
import "./chatbot.css";

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<{ text: string; sender: "user" | "bot" }[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom when messages update
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Handle file selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      setMessages(prev => [...prev, { text: `Selected file: ${selectedFile.name}`, sender: "user" }]);
    }
  };

  // Run predefined actions
  const runAction = async (action: "analyze-log" | "check-status") => {
    if (action === "analyze-log" && !file) {
      setMessages(prev => [...prev, { text: "Please upload a file first.", sender: "bot" }]);
      return;
    }

    setMessages(prev => [...prev, { text: `User triggered: ${action}`, sender: "user" }]);

    try {
      const formData = new FormData();
      if (action === "analyze-log" && file) {
        formData.append("file", file);
      }
      formData.append("action", action);

      const res = await fetch("http://localhost:8000/run-command", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      setMessages(prev => [...prev, { text: data.output, sender: "bot" }]);
    } catch (err) {
      setMessages(prev => [...prev, { text: `Error: ${err}`, sender: "bot" }]);
    }
  };

  return (
    <div className="chatbot-wrapper">
      <div className="chatbot-container">
        <div className="chatbot-header">StageZero Chatbot</div>

        <div className="chatbot-messages">
          {messages.map((msg, i) => (
            <Message key={i} text={msg.text} sender={msg.sender} />
          ))}
          <div ref={chatEndRef} />
        </div>

        <div className="chatbot-input">
          <input type="file" accept=".zip,.7z" onChange={handleFileChange} />
        </div>

        <div className="chatbot-actions">
          <button onClick={() => runAction("analyze-log")}>Analyze Uploaded Log</button>
          <button onClick={() => runAction("check-status")}>Check Server Status</button>
          <button onClick={() => setMessages([])}>Clear Chat</button>
        </div>
      </div>
    </div>
  );
};

export default Chatbot;
