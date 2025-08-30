export async function getReport(logs: string): Promise<string> {
  const response = await fetch('http://localhost:8000/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ logs }),
  });
  if (!response.ok) throw new Error('Failed to fetch report');
  const data = await response.json();
  return data.report;
}