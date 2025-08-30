import React, { useState, useRef, useEffect } from "react";
import "./chatbot.css";
import Message from "./message";

interface MessageType {
  text: string;
  sender: "user" | "bot";
}

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<MessageType[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);

  // auto-scroll to last message
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // handle log archive file selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      setMessages((prev) => [
        ...prev,
        { text: `📂 Selected file: ${selectedFile.name}`, sender: "user" },
      ]);
    }
  };

  // run action (upload + analyze logs OR check server status)
  const runAction = async (action: "analyze-log" | "check-status") => {
    if (action === "analyze-log" && !file) {
      setMessages((prev) => [
        ...prev,
        { text: "⚠️ Please upload a file first.", sender: "bot" },
      ]);
      return;
    }

    setMessages((prev) => [
      ...prev,
      { text: `➡️ User triggered: ${action}`, sender: "user" },
    ]);
    

    try {
      const formData = new FormData();
      formData.append("action", action);

      if (file && action === "analyze-log") {
        formData.append("file", file);
      }

      if (password.trim()) {
        formData.append("password", password);
      }

      const res = await fetch("http://localhost:8000/upload-logs", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        throw new Error(`Server error: ${res.status}`);
      }

      const data = await res.json();
      setMessages((prev) => [...prev, { text: data.output, sender: "bot" }]);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setMessages((prev) => [
        ...prev,
        { text: `❌ Error: ${errorMsg}`, sender: "bot" },
      ]);
    }
  };

  return (
    <div className="chatbot-page">
      <div className="chatbot-container">
        {/* HEADER */}
        <div className="chatbot-header">
          <h1>StageZero AI Assistant</h1>
          <p>Upload logs and get instant insights</p>
        </div>

        {/* MESSAGES */}
        <div className="chatbot-messages">
          {messages.map((msg, i) => (
            <Message key={i} text={msg.text} sender={msg.sender} />
          ))}
          <div ref={chatEndRef}></div>
        </div>

        {/* INPUTS + CONTROLS */}
        <div className="chatbot-inputs">
          <label className="file-upload-btn">
            Upload Log
            <input
              type="file"
              accept=".zip,.7z"
              onChange={handleFileChange}
              hidden
            />
          </label>

          <input
            type="password"
            placeholder="Archive password (optional)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="password-input"
          />

          <div className="chatbot-buttons">
            <button onClick={() => runAction("analyze-log")}>
              Analyze Uploaded Log
            </button>

            <button onClick={() => runAction("check-status")}>
              Check Server Status
            </button>

            <button
              onClick={async () => {
                setMessages((prev) => [
                  ...prev,
                  { text: "➡️ User triggered: generate report", sender: "user" },
                ]);

                try {
                  const response = await fetch("http://localhost:8000/api/report/deep");
                  if (!response.ok) throw new Error(`Server error: ${response.status}`);

                  const data = await response.json();

                  const summary = `
          📊 Deep Incident Report
          - Total Logs: ${data.summary?.total_logs}
          - Distinct Techniques: ${data.summary?.distinct_techniques}
          - Tactics Observed: ${data.summary?.tactics_observed}
          - Overall Risk Score: ${data.summary?.overall_risk_score} (${data.summary?.overall_severity})

          📝 Narrative:
          ${data.narrative}
                  `;

                  setMessages((prev) => [...prev, { text: summary, sender: "bot" }]);
                } catch (err) {
                  setMessages((prev) => [
                    ...prev,
                    { text: "❌ Failed to generate deep report.", sender: "bot" },
                  ]);
                }
              }}
            >
              Generate Report
            </button>

            <button onClick={() => setMessages([])}>Clear Chat</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Chatbot;
