import React, { useState } from 'react';

const Chatbot: React.FC = () => {
  const [messages, setMessages] = useState<string[]>([]);
  const [input, setInput] = useState('');

  const handleSend = () => {
    if (input.trim()) {
      setMessages([...messages, `You: ${input}`]);
      setMessages(msgs => [...msgs, `Bot: This is a demo response.`]);
      setInput('');
    }
  };

  return (
    <div style={{ border: '1px solid #ccc', padding: 10, marginTop: 20 }}>
      <h3>StageZero Chatbot</h3>
      <div style={{ height: 100, overflowY: 'auto', marginBottom: 10 }}>
        {messages.map((msg, i) => <div key={i}>{msg}</div>)}
      </div>
      <input
      value={input}
        onChange={e => setInput(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && handleSend()}
        placeholder="Type your message..."
        style={{ width: '80%' }}
      />
      <button onClick={handleSend}>Send</button>
    </div>
  );
};

export default Chatbot;