import React, { useState, useRef, useEffect } from "react";
import "./chatbot.css";
import Message from "./Message";

interface MessageType {
  text: string;
  sender: "user" | "bot";
}

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<MessageType[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      setMessages(prev => [...prev, { text: `Selected file: ${selectedFile.name}`, sender: "user" }]);
    }
  };

  const runAction = async (action: "analyze-log" | "check-status") => {
    if (action === "analyze-log" && !file) {
      setMessages(prev => [...prev, { text: "Please upload a file first.", sender: "bot" }]);
      return;
    }

    setMessages(prev => [...prev, { text: `User triggered: ${action}`, sender: "user" }]);

    try {
      const formData = new FormData();
      if (file && action === "analyze-log") formData.append("file", file);
      formData.append("action", action);
      if (password) formData.append("password", password);
      const res = await fetch("http://localhost:8000/upload-logs", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      setMessages(prev => [...prev, { text: data.output, sender: "bot" }]);
    } 
    // catch (err) {
    //   setMessages(prev => [...prev, { text: `Error: ${err}`, sender: "bot" }]);
    // } 
    catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        setMessages(prev => [...prev, { text: `Error: ${errorMsg}`, sender: "bot" }]);
    }
  };

  return (
    <div className="chatbot-page">
      <div className="chatbot-container">
        <div className="chatbot-header">
          <h1>StageZero AI Assistant</h1>
          <p>Upload logs and get instant insights</p>
        </div>

        <div className="chatbot-messages">
          {messages.map((msg, i) => (
            // <div key={i} className={`message-${msg.sender}`}>
            //   {msg.text}
            // </div>
            <Message key={i} text={msg.text} sender={msg.sender} />
          ))}
          <div ref={chatEndRef}></div>
        </div>
        
        <div className="chatbot-inputs">
          <label className="file-upload-btn">
            Upload Log
            <input type="file" accept=".zip,.7z" onChange={handleFileChange} hidden />
          </label>

          {/* NEW password input */}
          <input
            type="password"
            placeholder="Archive password (if any)"
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ marginLeft: 10 }}
          />

          <div className="chatbot-buttons">
            <button onClick={() => runAction("analyze-log")}>Analyze Uploaded Log</button>
            <button onClick={() => runAction("check-status")}>Check Server Status</button>
            <button onClick={() => setMessages([])}>Clear Chat</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Chatbot;
