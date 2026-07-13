// Small AntD Table sorter builders -- avoids re-writing the same
// localeCompare/subtract/Date.parse boilerplate on every column across
// every page's table.
export function textSorter<T>(get: (row: T) => string) {
  return (a: T, b: T) => get(a).localeCompare(get(b));
}
export function numSorter<T>(get: (row: T) => number) {
  return (a: T, b: T) => get(a) - get(b);
}
export function dateSorter<T>(get: (row: T) => string) {
  return (a: T, b: T) => new Date(get(a)).getTime() - new Date(get(b)).getTime();
}
