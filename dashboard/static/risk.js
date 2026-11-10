/* Risk presentation helpers.
 *
 * ORACLE writes host.risk_score on a 0-100 scale (compliance_mapper filters
 * risk_score > 30), so the UI must not treat it as a 0-10 value. Kept in its
 * own file so the arithmetic is unit-testable without a DOM.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.obsidiosRisk = api;
})(typeof window !== 'undefined' ? window : null, function () {
  function bar(score) {
    const risk = Number(score) || 0;
    return risk > 0 ? Math.max(3, Math.min(100, risk)) : 0;
  }
  function color(score) {
    const risk = Number(score) || 0;
    return risk >= 70 ? 'var(--red)' : risk >= 40 ? 'var(--amber)' : 'var(--green)';
  }
  function band(score) {
    const risk = Number(score) || 0;
    return risk >= 70 ? 'critical' : risk >= 40 ? 'elevated' : 'low';
  }
  return { bar: bar, color: color, band: band };
});
