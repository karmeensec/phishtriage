function createSafeFilename(value) {
  const withoutExtension = String(value || "analysis")
    .replace(/\.eml$/i, "");

  const sanitized = withoutExtension
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);

  return sanitized || "analysis";
}

export function downloadJsonReport(
  analysis,
  filenameSource,
) {
  const report = {
    report_type: "phishtriage-analysis-report",
    exported_at_utc: new Date().toISOString(),
    analysis,
  };

  const jsonContent = JSON.stringify(report, null, 2);

  const blob = new Blob(
    [jsonContent],
    {
      type: "application/json;charset=utf-8",
    },
  );

  const downloadUrl = URL.createObjectURL(blob);
  const downloadLink = document.createElement("a");

  downloadLink.href = downloadUrl;
  downloadLink.download =
    `${createSafeFilename(filenameSource)}-report.json`;

  document.body.append(downloadLink);
  downloadLink.click();
  downloadLink.remove();

  URL.revokeObjectURL(downloadUrl);
}