export async function getReport(logs: string): Promise<string> {
  const response = await fetch('/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs }),
  });
  if (!response.ok) throw new Error('Failed to fetch report');
  const data = await response.json();
  return data.report;
}