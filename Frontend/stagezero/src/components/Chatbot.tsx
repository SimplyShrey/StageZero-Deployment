import React, { useState } from 'react';
import axios from 'axios';

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<string[]>([]);
  const [input, setInput] = useState('');
  const [classifiedLogs, setClassifiedLogs] = useState<any[]>([]); // if you want to send logs too

  const handleSend = async () => {
    if (!input.trim()) return;

    // Add user's message
    setMessages((msgs) => [...msgs, `You: ${input}`]);

    try {
      // Call backend /chat endpoint
      const res = await axios.post('http://127.0.0.1:8000/chat', {
        message: input,
        classified_logs: classifiedLogs, // optional, if you want context
      });

      const botReply = res.data.response;

      // Add bot's response
      setMessages((msgs) => [...msgs, `Bot: ${botReply}`]);
    } catch (err) {
      console.error(err);
      setMessages((msgs) => [...msgs, `Bot: Error contacting server.`]);
    }

    setInput('');
  };

  return (
    <div style={{ border: '1px solid #ccc', padding: 10, marginTop: 20 }}>
      <h3>StageZero Chatbot</h3>
      <div style={{ height: 200, overflowY: 'auto', marginBottom: 10 }}>
        {messages.map((msg, i) => (
          <div key={i}>{msg}</div>
        ))}
      </div>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
        placeholder="Type your message..."
        style={{ width: '80%' }}
      />
      <button onClick={handleSend}>Send</button>
    </div>
  );
};

export default Chatbot;
