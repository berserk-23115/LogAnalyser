export default function Navbar() {
  return (
    <nav className="border-b border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-6 max-w-3xl">
        <div className="flex items-center justify-between h-14">
          <span className="font-semibold text-sm text-gray-900 dark:text-white">
            Network Log Analyser
          </span>
          <a
            href="https://github.com/berserk-23115/LogAnalyser"
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white text-xs"
          >
            GitHub →
          </a>
        </div>
      </div>
    </nav>
  );
}
