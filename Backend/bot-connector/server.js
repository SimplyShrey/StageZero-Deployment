const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");

const app = express();
app.use(bodyParser.json());

// Kommunicate webhook endpoint
app.post("/webhook", async (req, res) => {
    const userMessage = req.body.message;

    // Call Watson Assistant / watsonx.ai here
    const response = await fetch("https://api.us-south.assistant.watson.cloud.ibm.com/v2/assistants/7f4a6425-2941-4f5d-848a-76157654c3a1/sessions", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "IkeCx8RlZEmXkPPq38q1EjHur5bHBo9cF-CfeAsHt7rb"
        },
        body: JSON.stringify({ input: { text: userMessage } })
    });

    const data = await response.json();
    const botReply = data.output.generic[0].text;

    // Send bot response back to Kommunicate
    return res.json({
        messages: [
            { type: "text", content: botReply }
        ]
    });
});

app.listen(3000, () => console.log("Server running on port 3000"));