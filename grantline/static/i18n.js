// Shared server/browser catalog; identifiers and native commands never pass through it.
{
  const messages = JSON.parse(document.querySelector('#i18n-messages')?.textContent || '{}');
  globalThis.GrantlineI18n = (message, ...values) => (messages[message] || message)
    .replace(/\{(\d+)\}/g, (match, index) => values[index] === undefined ? match : String(values[index]));
}
