const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  (import.meta.env.DEV
    ? "http://127.0.0.1:8000"
    : "");

export async function analyzeEmail(file) {
  if (!(file instanceof File)) {
    throw new Error("Please select an email file.");
  }

  if (!file.name.toLowerCase().endsWith(".eml")) {
    throw new Error("Only .eml files are supported.");
  }

  const formData = new FormData();
  formData.append("file", file);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail ?? "Email analysis failed.");
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The analysis request timed out.", {
        cause: error,
      });
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function getAnalysisHistory({
  limit = 10,
  offset = 0,
} = {}) {
  const query = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15_000);

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/analyses?${query}`,
      {
        method: "GET",
        signal: controller.signal,
      },
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.detail ?? "Could not load analysis history.",
      );
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "The history request timed out.",
        { cause: error },
      );
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function getAnalysisDetail(analysisId) {
  if (!Number.isInteger(analysisId) || analysisId < 1) {
    throw new Error("Invalid analysis identifier.");
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15_000);

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/analyses/${analysisId}`,
      {
        method: "GET",
        signal: controller.signal,
      },
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.detail ?? "Could not load the saved analysis.",
      );
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "The analysis-detail request timed out.",
        { cause: error },
      );
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

