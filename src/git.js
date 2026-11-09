// The git binary PR packs and corpus validation run. PQC_FORGE_GIT points at one that is not on PATH
// (e.g. GitHub Desktop's bundled git on a dev machine).
export const gitCommand = () => process.env.PQC_FORGE_GIT || 'git';

export const GIT_UNAVAILABLE_MESSAGE = 'PR pack unavailable, contact support';

/** A missing git binary becomes a clear error for the customer instead of "spawn git ENOENT". */
export function gitSpawnError(error) {
  if (error?.code !== 'ENOENT') return error;
  return Object.assign(new Error(GIT_UNAVAILABLE_MESSAGE), { code: 'GIT_UNAVAILABLE' });
}
