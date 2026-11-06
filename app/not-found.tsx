import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 flex items-center justify-center p-6 font-mono text-sm">
      <div className="border border-neutral-800 bg-neutral-900/50 p-6 max-w-md w-full space-y-4">
        <h1 className="text-base font-bold text-white">404 — Not Found</h1>
        <p className="text-xs text-neutral-400">
          The requested resource could not be found.
        </p>
        <Link
          href="/"
          className="inline-block text-xs text-emerald-400 hover:underline"
        >
          Return to Skill Specification
        </Link>
      </div>
    </main>
  );
}
