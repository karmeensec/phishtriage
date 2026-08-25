import { useState } from "react";
import { analyzeEmail } from "./services/api";
import "./App.css";

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  function handleFileChange(event) {
    const file = event.target.files[0] ?? null;

    setSelectedFile(file);
    setResult(null);
    setError("");
  }

  async function handleAnalyze() {
    if (!selectedFile || isAnalyzing) {
      return;
    }

    setIsAnalyzing(true);
    setResult(null);
    setError("");

    try {
      const analysisResult = await analyzeEmail(selectedFile);
      setResult(analysisResult);
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : "An unexpected error occurred.",
      );
    } finally {
      setIsAnalyzing(false);
    }
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

        <button
          type="button"
          disabled={!selectedFile || isAnalyzing}
          onClick={handleAnalyze}
        >
          {isAnalyzing ? "Analyzing…" : "Analyze Email"}
        </button>

        {error && (
          <div className="error-message" role="alert">
            {error}
          </div>
        )}
      </section>

      {result && (
        <section className="result-panel">
          <h2>Analysis result</h2>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </section>
      )}
    </main>
  );
}

export default App;