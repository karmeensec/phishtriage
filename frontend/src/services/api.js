const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

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
      throw new Error("The analysis request timed out.");
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}