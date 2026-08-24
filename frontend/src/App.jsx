import { useState } from "react";
import "./App.css";

function App() {
  const [selectedFile, setSelectedFile] = useState(null);

  function handleFileChange(event) {
    const file = event.target.files[0] ?? null;
    setSelectedFile(file);
  }

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS</p>
          <h1>PhishTriage</h1>
          <p className="subtitle">
            Automated phishing email analysis and incident triage
          </p>
        </div>

        <span className="status">System Online</span>
      </header>

      <section className="upload-panel">
        <h2>Analyze suspicious email</h2>
        <p>
          Upload an email file to inspect its headers, URLs, attachments,
          language, and authentication results.
        </p>

        <label className="file-input">
          <span>Select an .eml file</span>
          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={handleFileChange}
          />
        </label>

        {selectedFile && (
          <div className="selected-file">
            Selected: <strong>{selectedFile.name}</strong>
          </div>
        )}

        <button type="button" disabled={!selectedFile}>
          Analyze Email
        </button>
      </section>
    </main>
  );
}

export default App;