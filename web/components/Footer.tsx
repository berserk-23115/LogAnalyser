export default function Footer() {
  return (
    <footer className="border-t border-gray-200 dark:border-gray-800 py-8">
      <div className="container mx-auto px-6 max-w-3xl">
        <p className="text-center text-xs text-gray-500 dark:text-gray-500">
          © {new Date().getFullYear()} Network Log Analyser Project
        </p>
      </div>
    </footer>
  );
}
