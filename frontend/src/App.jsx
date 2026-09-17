import { useEffect, useState } from "react";
import AnalysisReport from "./components/AnalysisReport.jsx";
import HistoryPanel from "./components/HistoryPanel.jsx";
import {
  analyzeEmail,
  getAnalysisDetail,
  getAnalysisHistory,
} from "./services/api.js";
import "./App.css";
import SavedAnalysisDetail from "./components/SavedAnalysisDetail.jsx";

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const [historyItems, setHistoryItems] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyError, setHistoryError] = useState("");
  const [isHistoryLoading, setIsHistoryLoading] =
    useState(true);
  const [historyVersion, setHistoryVersion] = useState(0);

    const [selectedHistoryId, setSelectedHistoryId] =
    useState(null);
    const [isHistoryEnabled, setIsHistoryEnabled] =
    useState(true);
  const [savedDetail, setSavedDetail] = useState(null);
  const [savedDetailError, setSavedDetailError] =
    useState("");
  const [isSavedDetailLoading, setIsSavedDetailLoading] =
    useState(false);

  useEffect(() => {
    let isCancelled = false;

    async function loadHistory() {
      setIsHistoryLoading(true);
      setHistoryError("");

      try {
        const history = await getAnalysisHistory({
          limit: 10,
          offset: 0,
        });

        if (!isCancelled) {
          setIsHistoryEnabled(
            history.persistence_enabled !== false,
          );
          setHistoryItems(history.items);
          setHistoryTotal(history.total);
}
      } catch (historyLoadError) {
        if (!isCancelled) {
          setHistoryError(
            historyLoadError instanceof Error
              ? historyLoadError.message
              : "Could not load analysis history.",
          );
        }
      } finally {
        if (!isCancelled) {
          setIsHistoryLoading(false);
        }
      }
    }

    loadHistory();

    return () => {
      isCancelled = true;
    };
  }, [historyVersion]);

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

      if (analysisResult.persisted === false) {
        setIsHistoryEnabled(false);
        setSelectedHistoryId(null);
        setSavedDetail(null);
      } else {
        setHistoryVersion((current) => current + 1);
      }
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

  async function handleHistorySelect(analysisId) {
    if (isSavedDetailLoading) {
      return;
    }

    setSelectedHistoryId(analysisId);
    setSavedDetail(null);
    setSavedDetailError("");
    setIsSavedDetailLoading(true);

    try {
      const detail = await getAnalysisDetail(analysisId);
      setSavedDetail(detail);
    } catch (detailError) {
      setSavedDetailError(
        detailError instanceof Error
          ? detailError.message
          : "Could not load the saved analysis.",
      );
    } finally {
      setIsSavedDetailLoading(false);
    }
  }

  function handleCloseSavedDetail() {
    setSelectedHistoryId(null);
    setSavedDetail(null);
    setSavedDetailError("");
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
          Upload an email file to inspect its headers, URLs,
          attachments, language, and authentication results.
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

      {result && <AnalysisReport result={result} />}

      {isHistoryEnabled ? (
  <>
        <HistoryPanel
          items={historyItems}
          total={historyTotal}
          isLoading={isHistoryLoading}
          error={historyError}
          selectedId={selectedHistoryId}
          isSelectionLoading={isSavedDetailLoading}
          onSelect={handleHistorySelect}
        />

        <SavedAnalysisDetail
          detail={savedDetail}
          isLoading={isSavedDetailLoading}
          error={savedDetailError}
          onClose={handleCloseSavedDetail}
        />
      </>
    ) : (
      <section className="history-panel">
        <p className="eyebrow">PRIVACY MODE</p>
        <h2>Public demo protection</h2>

        <p className="history-message">
          Uploaded emails are analyzed temporarily and are
          not saved. Analysis history is disabled in this
          public demo.
        </p>
      </section>
    )}
    </main>
  );
}

export default App;